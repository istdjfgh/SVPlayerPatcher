// SVPlayerPatcher v20 - fishhook rebind PKCS7_verify in DATA segment
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

// ========================================
// PART 1: Minimal fishhook implementation
// ========================================

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

static void perform_rebinding(const struct mach_header_64 *header, intptr_t slide,
                               struct rebinding *rebindings, size_t rebindings_count) {
    // Find LC_SYMTAB and LC_DYSYMTAB
    struct symtab_command *symtab = NULL;
    struct dysymtab_command *dysymtab = NULL;
    struct segment_command_64 *linkedit = NULL;
    struct segment_command_64 *data_seg = NULL;
    
    struct load_command *cmd = (struct load_command *)((char *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab = (struct symtab_command *)cmd;
        } else if (cmd->cmd == LC_DYSYMTAB) {
            dysymtab = (struct dysymtab_command *)cmd;
        } else if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) linkedit = seg;
            if (strcmp(seg->segname, SEG_DATA) == 0) data_seg = seg;
            // Also check __DATA_CONST
            if (strcmp(seg->segname, "__DATA_CONST") == 0 && !data_seg) data_seg = seg;
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    if (!symtab || !dysymtab || !linkedit) return;
    
    uintptr_t linkedit_base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    struct nlist_64 *sym_list = (struct nlist_64 *)(linkedit_base + symtab->symoff);
    char *str_tab = (char *)(linkedit_base + symtab->stroff);
    uint32_t *indirect_tab = (uint32_t *)(linkedit_base + dysymtab->indirectsymoff);
    
    // Walk all segments looking for lazy/non-lazy symbol pointers
    cmd = (struct load_command *)((char *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            struct section_64 *sections = (struct section_64 *)((char *)seg + sizeof(struct segment_command_64));
            
            for (uint32_t j = 0; j < seg->nsects; j++) {
                uint32_t type = sections[j].flags & SECTION_TYPE;
                if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) continue;
                
                uint32_t indirect_off = sections[j].reserved1;
                void **ptrs = (void **)(slide + sections[j].addr);
                uint32_t count = (uint32_t)(sections[j].size / sizeof(void *));
                
                for (uint32_t k = 0; k < count; k++) {
                    uint32_t sym_idx = indirect_tab[indirect_off + k];
                    if (sym_idx == 0x80000000 || sym_idx == (0x80000000 | 0x40000000)) continue;
                    if (sym_idx >= symtab->nsyms) continue;
                    
                    uint32_t str_off = sym_list[sym_idx].n_un.n_strx;
                    char *sym_name = str_tab + str_off;
                    
                    // Skip leading underscore
                    if (sym_name[0] == '_') sym_name++;
                    
                    for (size_t r = 0; r < rebindings_count; r++) {
                        if (strcmp(sym_name, rebindings[r].name) == 0) {
                            if (rebindings[r].replaced) {
                                *(rebindings[r].replaced) = ptrs[k];
                            }
                            ptrs[k] = rebindings[r].replacement;
                            [_log appendFormat:@"[REBOUND] %s\n", rebindings[r].name];
                        }
                    }
                }
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
}

static void rebind_symbols(struct rebinding *rebindings, size_t count) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr->magic != MH_MAGIC_64) continue;
        
        const char *name = _dyld_get_image_name(i);
        
        // Only rebind in SVPlayer's own binary and frameworks (not system)
        if (name && (strstr(name, "SVPlayer") || strstr(name, "/Frameworks/"))) {
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            perform_rebinding((const struct mach_header_64 *)hdr, slide, rebindings, count);
        }
    }
}

// ========================================
// PART 2: Replacement functions
// ========================================

typedef int (*orig_PKCS7_verify_t)(void*, void*, void*, void*, void*, int);
static orig_PKCS7_verify_t orig_PKCS7_verify = NULL;

static int fake_PKCS7_verify(void *p7, void *certs, void *store, void *indata, void *out, int flags) {
    [_log appendString:@"[HOOKED] PKCS7_verify -> 1\n"];
    [UIPasteboard generalPasteboard].string = _log;
    return 1; // Signature VALID
}

typedef int (*orig_X509_verify_cert_t)(void*);
static orig_X509_verify_cert_t orig_X509_verify_cert = NULL;

static int fake_X509_verify_cert(void *ctx) {
    [_log appendString:@"[HOOKED] X509_verify_cert -> 1\n"];
    return 1; // Certificate chain VALID
}

// ========================================
// PART 3: StoreKit
// ========================================

static IMP _orig_txState = NULL;
static NSInteger hooked_txState(id self, SEL _cmd) {
    if (_fakeState) return SKPaymentTransactionStateRestored;
    return ((NSInteger(*)(id, SEL))_orig_txState)(self, _cmd);
}
static IMP _orig_txId = NULL;
static NSString* hooked_txId(id self, SEL _cmd) {
    if (_fakeState) return @"2000000845671234";
    return ((NSString*(*)(id, SEL))_orig_txId)(self, _cmd);
}
static IMP _orig_origTx = NULL;
static id hooked_origTx(id self, SEL _cmd) {
    if (_fakeState) return self;
    return ((id(*)(id, SEL))_orig_origTx)(self, _cmd);
}

static IMP _orig_updated = NULL;
static void hooked_updated(id self, SEL _cmd, id queue, NSArray *txs) {
    for (SKPaymentTransaction *tx in txs) {
        NSInteger real = ((NSInteger(*)(id, SEL))_orig_txState)(tx, @selector(transactionState));
        [_log appendFormat:@"[TX] real=%ld prod=%@\n", (long)real, tx.payment.productIdentifier];
    }
    _fakeState = YES;
    ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
    _fakeState = NO;
    [UIPasteboard generalPasteboard].string = _log;
}

static IMP _orig_finish = NULL;
static void hooked_finish(id s, SEL c, id tx) {
    @try { ((void(*)(id,SEL,id))_orig_finish)(s,c,tx); } @catch(NSException *e) {}
}
static IMP _orig_restored = NULL;
static void hooked_restored(id s, SEL c, id q) {
    [_log appendString:@"[RESTORE] Done\n"];
    [UIPasteboard generalPasteboard].string = _log;
    ((void(*)(id,SEL,id))_orig_restored)(s,c,q);
}

static void patchConfig(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:
                   @"Library/Application Support/SVPlayer/settings/main.cfg"];
    NSData *d = [NSData dataWithContentsOfFile:p];
    if (!d) return;
    NSMutableDictionary *c = [NSJSONSerialization JSONObjectWithData:d
                              options:NSJSONReadingMutableContainers error:nil];
    if (!c) return;
    c[@"h/pid"] = @"unlock0";
    c[@"h/last_check"] = @(1893456000);
    NSData *n = [NSJSONSerialization dataWithJSONObject:c options:NSJSONWritingPrettyPrinted error:nil];
    [n writeToFile:p atomically:YES];
    [_log appendString:@"[OK] cfg\n"];
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v20 FISHHOOK ===\n\n"];
    
    // ======= FISHHOOK OpenSSL =======
    struct rebinding rebinds[] = {
        {"PKCS7_verify", (void *)fake_PKCS7_verify, (void **)&orig_PKCS7_verify},
        {"X509_verify_cert", (void *)fake_X509_verify_cert, (void **)&orig_X509_verify_cert},
    };
    rebind_symbols(rebinds, 2);
    [_log appendString:@"[OK] fishhook done\n"];
    
    // ======= StoreKit =======
    Method m;
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionState));
    if (m) _orig_txState = method_setImplementation(m, (IMP)hooked_txState);
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionIdentifier));
    if (m) _orig_txId = method_setImplementation(m, (IMP)hooked_txId);
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(originalTransaction));
    if (m) _orig_origTx = method_setImplementation(m, (IMP)hooked_origTx);
    m = class_getInstanceMethod([SKPaymentQueue class], @selector(finishTransaction:));
    if (m) _orig_finish = method_setImplementation(m, (IMP)hooked_finish);
    [_log appendString:@"[OK] SK\n"];
    
    patchConfig();
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (!cls) return;
        Method mx = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
        if (mx) _orig_updated = method_setImplementation(mx, (IMP)hooked_updated);
        Method my = class_getInstanceMethod(cls, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
        if (my) _orig_restored = method_setImplementation(my, (IMP)hooked_restored);
        [_log appendString:@"[OK] IAP\n"];
        [UIPasteboard generalPasteboard].string = _log;
        
        UIWindowScene *sc = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) { sc = s; break; }
        if (!sc) return;
        UIWindow *w = [[UIWindow alloc] initWithWindowScene:sc];
        w.frame = CGRectMake(20, 40, 380, 30);
        w.windowLevel = UIWindowLevelAlert + 100;
        w.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.8];
        w.layer.cornerRadius = 8; w.clipsToBounds = YES;
        w.rootViewController = [[UIViewController alloc] init];
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(10, 0, 360, 30)];
        l.text = @"✅ v20 FISHHOOK - tap Restore!";
        l.textColor = [UIColor greenColor];
        l.font = [UIFont boldSystemFontOfSize:13];
        [w.rootViewController.view addSubview:l];
        w.hidden = NO;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC), dispatch_get_main_queue(), ^{ w.hidden = YES; });
        
        for (int i = 1; i <= 30; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i*2.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [UIPasteboard generalPasteboard].string = _log;
            });
        }
    });
}
