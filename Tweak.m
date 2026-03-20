// SVPlayerPatcher v22 - Targeted symbol search in libmpv + main binary
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <string.h>

static NSMutableString *_log = nil;
static BOOL _fakeState = NO;

// Known OpenSSL prefixes to SKIP
static BOOL isOpenSSLSymbol(const char *name) {
    const char *prefixes[] = {
        "ASN1_", "BIO_", "BN_", "CMS_", "CRYPTO_", "CT_", "DES_", "DH_", "DSA_",
        "ECDH_", "ECDSA_", "EC_", "ED25519", "ED448", "ENGINE_", "ERR_", "EVP_",
        "HMAC_", "MD5_", "OBJ_", "OCSP_", "OPENSSL_", "PEM_", "PKCS", "RAND_",
        "RSA_", "SHA", "SSL_", "TLS_", "TS_", "UI_", "X509", "X25519", "X448",
        "AES_", "BF_", "CAST_", "Camellia_", "GENERAL_", "NAMING_", "NCONF_",
        "NETSCAPE_", "OSSL_", "ADMISS", "AUTHOR", "BASIC_", "CERTIFICAT",
        "COMP_", "CONF_", "DER_", "DIRECTORYSTRING", "DISPLAYTEXT",
        "DIST_", "ESS_", "EXT_", "GENERAL_", "IDEA_", "IPAddress",
        "ISSUING_", "KRB5", "LHASH_", "NIST_", "NID_", "NOTICEREF",
        "OTHERNAME", "POLICY", "PROFESSION", "RC", "SEED_", "SMIME_",
        "SRP_", "SXNET", "TXT_DB", "USERNOTICE", "WHIRLPOOL", "a2i_", "b2i_",
        "i2a_", "i2b_", "i2d_", "d2i_", "i2o_", "o2i_", "i2s_", "s2i_",
        "i2t_", "i2v_", "v2i_",
        NULL
    };
    for (int i = 0; prefixes[i]; i++) {
        if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0) return YES;
    }
    return NO;
}

static void dumpImageSymbols(const char *targetImage) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *imgName = _dyld_get_image_name(i);
        if (!imgName || !strstr(imgName, targetImage)) continue;
        
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        
        struct symtab_command *symtab = NULL;
        struct segment_command_64 *linkedit = NULL;
        struct load_command *cmd = (struct load_command *)((char *)header + sizeof(struct mach_header_64));
        
        for (uint32_t j = 0; j < header->ncmds; j++) {
            if (cmd->cmd == LC_SYMTAB) symtab = (struct symtab_command *)cmd;
            if (cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
                if (strcmp(seg->segname, SEG_LINKEDIT) == 0) linkedit = seg;
            }
            cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
        }
        if (!symtab || !linkedit) return;
        
        uintptr_t base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
        struct nlist_64 *syms = (struct nlist_64 *)(base + symtab->symoff);
        char *strs = (char *)(base + symtab->stroff);
        
        [_log appendFormat:@"\n=== %s (%d syms) ===\n", targetImage, symtab->nsyms];
        
        // Search 1: SVP-specific keywords (not prefixed by OpenSSL)
        const char *keys[] = {"svp", "hfr", "licen", "premium", "trial",
                              "unlock", "purchas", "subscribe", "iap", "paid", NULL};
        
        int found = 0;
        for (uint32_t s = 0; s < symtab->nsyms; s++) {
            if (syms[s].n_value == 0) continue;
            char *name = strs + syms[s].n_un.n_strx;
            if (name[0] == '_') name++;
            if (isOpenSSLSymbol(name)) continue;
            
            char lower[512];
            size_t len = strlen(name);
            if (len >= 512) len = 511;
            for (size_t c = 0; c < len; c++)
                lower[c] = (name[c] >= 'A' && name[c] <= 'Z') ? name[c]+32 : name[c];
            lower[len] = 0;
            
            for (int k = 0; keys[k]; k++) {
                if (strstr(lower, keys[k])) {
                    void *addr = (void *)(syms[s].n_value + slide);
                    [_log appendFormat:@"  %s @ %p\n", name, addr];
                    found++;
                    break;
                }
            }
        }
        
        // Search 2: ALL non-OpenSSL, non-system exported symbols (first 100)
        if (found == 0) {
            [_log appendString:@"\n--- Non-OpenSSL exports (first 100) ---\n"];
            int cnt = 0;
            for (uint32_t s = 0; s < symtab->nsyms && cnt < 100; s++) {
                if ((syms[s].n_type & N_EXT) == 0) continue;
                if (syms[s].n_value == 0) continue;
                char *name = strs + syms[s].n_un.n_strx;
                if (name[0] == '_') name++;
                if (isOpenSSLSymbol(name)) continue;
                if (strlen(name) < 3) continue;
                // Skip more crypto
                if (strstr(name, "OPENSSL") || strstr(name, "ssl") || strstr(name, "SHA")
                    || strstr(name, "AES") || strstr(name, "DES")) continue;
                
                [_log appendFormat:@"  %s\n", name];
                cnt++;
            }
        }
        
        [_log appendFormat:@"\nFound %d matching\n", found];
        break;
    }
}

// StoreKit hooks (minimal)
static IMP _orig_txState = NULL;
static NSInteger hooked_txState(id self, SEL _cmd) {
    if (_fakeState) return SKPaymentTransactionStateRestored;
    return ((NSInteger(*)(id, SEL))_orig_txState)(self, _cmd);
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v22 ===\n\n"];
    
    // Dump BOTH images
    dumpImageSymbols("SVPlayer.app/SVPlayer");
    dumpImageSymbols("libmpv");
    
    Method m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionState));
    if (m) _orig_txState = method_setImplementation(m, (IMP)hooked_txState);
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [UIPasteboard generalPasteboard].string = _log;
        
        UIWindowScene *sc = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) { sc = s; break; }
        if (!sc) return;
        UIWindow *w = [[UIWindow alloc] initWithWindowScene:sc];
        w.frame = sc.coordinateSpace.bounds;
        w.windowLevel = UIWindowLevelAlert + 100;
        w.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.92];
        w.rootViewController = [[UIViewController alloc] init];
        CGRect b = w.bounds;
        
        UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, b.size.width - 40, 30)];
        t.text = @"v22 - SVP symbols (copy from clipboard)";
        t.textColor = [UIColor cyanColor];
        t.font = [UIFont boldSystemFontOfSize:13];
        [w.rootViewController.view addSubview:t];
        
        UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(10, 85, b.size.width - 20, b.size.height - 95)];
        tv.text = _log;
        tv.font = [UIFont fontWithName:@"Menlo" size:9];
        tv.textColor = [UIColor greenColor];
        tv.backgroundColor = [UIColor clearColor];
        tv.editable = NO;
        [w.rootViewController.view addSubview:tv];
        w.hidden = NO;
        [w makeKeyAndVisible];
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 60*NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            [UIPasteboard generalPasteboard].string = _log;
            w.hidden = YES;
        });
    });
}
