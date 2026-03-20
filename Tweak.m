// SVPlayerPatcher v17 - Bypass receipt crypto validation via interpose
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static NSMutableString *_log = nil;
static BOOL _fakeState = NO;

// ========================================
// PART 1: Interpose Security framework
// ========================================

// Hook SecTrustEvaluateWithError - certificate chain validation
static bool my_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    [_log appendString:@"[CRYPTO] SecTrustEvaluateWithError -> true\n"];
    if (error) *error = NULL;
    return true; // Always trusted
}

// Hook SecTrustEvaluate - older API
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    [_log appendString:@"[CRYPTO] SecTrustEvaluate -> proceed\n"];
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

// Interpose table
struct interpose_s { void *replacement; void *original; };

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_s interpose_funcs[] = {
    { (void *)my_SecTrustEvaluateWithError, (void *)SecTrustEvaluateWithError },
    { (void *)my_SecTrustEvaluate, (void *)SecTrustEvaluate },
};

// ========================================
// PART 2: Hook OpenSSL PKCS7_verify if found
// ========================================

typedef int (*PKCS7_verify_func)(void*, void*, void*, void*, void*, int);
static PKCS7_verify_func orig_PKCS7_verify = NULL;

static int my_PKCS7_verify(void *p7, void *certs, void *store, void *indata, void *out, int flags) {
    [_log appendString:@"[CRYPTO] PKCS7_verify -> 1 (success)\n"];
    return 1; // Success
}

// Try to hook OpenSSL at runtime
static void hookOpenSSL(void) {
    // Look for PKCS7_verify in any loaded library
    void *sym = dlsym(RTLD_DEFAULT, "PKCS7_verify");
    if (sym) {
        orig_PKCS7_verify = (PKCS7_verify_func)sym;
        [_log appendString:@"[OK] Found PKCS7_verify - patching inline\n"];
        
        // Inline patch: replace first instruction with RET (0xD65F03C0 on ARM64)
        // This makes the function immediately return whatever is in X0 register
        // We need to make it return 1
        // ARM64: MOV W0, #1 = 0x52800020; RET = 0xD65F03C0
        uint32_t *func = (uint32_t *)sym;
        
        // Change memory protection
        vm_address_t page = (vm_address_t)func & ~0xFFF;
        kern_return_t kr = vm_protect(mach_task_self(), page, 0x1000, FALSE,
                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        if (kr == KERN_SUCCESS) {
            func[0] = 0x52800020; // MOV W0, #1
            func[1] = 0xD65F03C0; // RET
            [_log appendString:@"[OK] PKCS7_verify patched!\n"];
        } else {
            [_log appendFormat:@"[FAIL] vm_protect: %d\n", kr];
        }
    } else {
        [_log appendString:@"[INFO] No PKCS7_verify found (not using OpenSSL)\n"];
    }
    
    // Also look for other verification functions
    const char *funcs_to_check[] = {
        "PKCS7_verify", "X509_verify_cert", "EVP_VerifyFinal",
        "ECDSA_verify", "RSA_verify", "EVP_DigestVerifyFinal",
        NULL
    };
    for (int i = 0; funcs_to_check[i]; i++) {
        void *s = dlsym(RTLD_DEFAULT, funcs_to_check[i]);
        [_log appendFormat:@"[SCAN] %s = %p\n", funcs_to_check[i], s];
    }
}

// ========================================  
// PART 3: StoreKit transaction faking
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
static IMP _orig_txDate = NULL;
static NSDate* hooked_txDate(id self, SEL _cmd) {
    if (_fakeState) return [NSDate date];
    return ((NSDate*(*)(id, SEL))_orig_txDate)(self, _cmd);
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
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v17 - CRYPTO BYPASS ===\n\n"];
    
    // Hook crypto
    hookOpenSSL();
    
    // Hook StoreKit
    Method m;
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionState));
    if (m) _orig_txState = method_setImplementation(m, (IMP)hooked_txState);
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionIdentifier));
    if (m) _orig_txId = method_setImplementation(m, (IMP)hooked_txId);
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionDate));
    if (m) _orig_txDate = method_setImplementation(m, (IMP)hooked_txDate);
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(originalTransaction));
    if (m) _orig_origTx = method_setImplementation(m, (IMP)hooked_origTx);
    m = class_getInstanceMethod([SKPaymentQueue class], @selector(finishTransaction:));
    if (m) _orig_finish = method_setImplementation(m, (IMP)hooked_finish);
    [_log appendString:@"[OK] SK hooks\n"];
    
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
        l.text = @"✅ v17 CRYPTO BYPASS - tap Buy!";
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
