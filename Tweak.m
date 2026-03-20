// SVPlayerPatcher v21 - Dump libmpv symbols related to licensing
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
// PART 1: Dump libmpv exported symbols
// ========================================

static void dumpLibmpvSymbols(void) {
    [_log appendString:@"=== libmpv Symbol Dump ===\n"];
    
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *imgName = _dyld_get_image_name(i);
        if (!imgName || !strstr(imgName, "libmpv")) continue;
        
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        
        struct symtab_command *symtab = NULL;
        struct load_command *cmd = (struct load_command *)((char *)header + sizeof(struct mach_header_64));
        
        for (uint32_t j = 0; j < header->ncmds; j++) {
            if (cmd->cmd == LC_SYMTAB) {
                symtab = (struct symtab_command *)cmd;
                break;
            }
            cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
        }
        
        if (!symtab) {
            [_log appendString:@"[FAIL] No symtab in libmpv\n"];
            return;
        }
        
        // Find LINKEDIT
        struct segment_command_64 *linkedit = NULL;
        cmd = (struct load_command *)((char *)header + sizeof(struct mach_header_64));
        for (uint32_t j = 0; j < header->ncmds; j++) {
            if (cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
                if (strcmp(seg->segname, SEG_LINKEDIT) == 0) { linkedit = seg; break; }
            }
            cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
        }
        if (!linkedit) return;
        
        uintptr_t linkedit_base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
        struct nlist_64 *sym_list = (struct nlist_64 *)(linkedit_base + symtab->symoff);
        char *str_tab = (char *)(linkedit_base + symtab->stroff);
        
        [_log appendFormat:@"Total symbols: %d\n", symtab->nsyms];
        
        // Keywords to search for
        const char *keywords[] = {
            "licen", "premium", "purchase", "trial", "unlock", "receipt",
            "valid", "verify", "paid", "subscribe", "product", "store",
            "check", "activate", "register", "serial", "key", "auth",
            "iap", "buy", "order", "billing", "svp", "hfr",
            NULL
        };
        
        int found = 0;
        for (uint32_t s = 0; s < symtab->nsyms && found < 200; s++) {
            // Only exported symbols (external, not debug)
            if ((sym_list[s].n_type & N_EXT) == 0) continue;
            if (sym_list[s].n_value == 0) continue;
            
            uint32_t stroff = sym_list[s].n_un.n_strx;
            char *name = str_tab + stroff;
            if (name[0] == '_') name++;
            
            // Check keywords
            char lower[256];
            size_t len = strlen(name);
            if (len >= 256) len = 255;
            for (size_t c = 0; c < len; c++) {
                lower[c] = (name[c] >= 'A' && name[c] <= 'Z') ? name[c] + 32 : name[c];
            }
            lower[len] = 0;
            
            for (int k = 0; keywords[k]; k++) {
                if (strstr(lower, keywords[k])) {
                    void *addr = (void *)(sym_list[s].n_value + slide);
                    [_log appendFormat:@"  %s @ %p\n", name, addr];
                    found++;
                    break;
                }
            }
        }
        
        [_log appendFormat:@"[INFO] Found %d matching symbols\n\n", found];
        break;
    }
}

// ========================================
// PART 2: StoreKit faking
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

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v21 SYMBOL DUMP ===\n\n"];
    
    dumpLibmpvSymbols();
    
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
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (!cls) return;
        Method mx = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
        if (mx) _orig_updated = method_setImplementation(mx, (IMP)hooked_updated);
        Method my = class_getInstanceMethod(cls, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
        if (my) _orig_restored = method_setImplementation(my, (IMP)hooked_restored);
        [_log appendString:@"[OK] IAP\n"];
        
        [UIPasteboard generalPasteboard].string = _log;
        
        // Full log overlay
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
        t.text = @"v21 - libmpv symbols (copy from clipboard)";
        t.textColor = [UIColor cyanColor];
        t.font = [UIFont boldSystemFontOfSize:13];
        [w.rootViewController.view addSubview:t];
        
        UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(10, 85, b.size.width - 20, b.size.height - 95)];
        tv.text = _log;
        tv.font = [UIFont fontWithName:@"Menlo" size:9];
        tv.textColor = [UIColor greenColor];
        tv.backgroundColor = [UIColor clearColor];
        tv.editable = NO;
        tv.tag = 999;
        [w.rootViewController.view addSubview:tv];
        w.hidden = NO;
        [w makeKeyAndVisible];
        
        for (int i = 1; i <= 20; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i*3.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                UITextView *lv = (UITextView*)[w.rootViewController.view viewWithTag:999];
                if (lv) lv.text = _log;
                [UIPasteboard generalPasteboard].string = _log;
            });
        }
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 60*NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            [UIPasteboard generalPasteboard].string = _log;
            w.hidden = YES;
        });
    });
}
