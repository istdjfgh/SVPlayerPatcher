// SVPlayerPatcher v17b - Crypto bypass
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#include <mach/mach.h>
#include <sys/mman.h>

static NSMutableString *_log = nil;
static BOOL _fakeState = NO;

// ========================================
// PART 1: Interpose SecTrust functions
// ========================================

static bool my_SecTrustEvalWithErr(SecTrustRef trust, CFErrorRef *error) {
    [_log appendString:@"[CRYPTO] SecTrustEvalWithErr -> true\n"];
    if (error) *error = NULL;
    return true;
}

static OSStatus my_SecTrustEval(SecTrustRef trust, SecTrustResultType *result) {
    [_log appendString:@"[CRYPTO] SecTrustEval -> proceed\n"];
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

// Interpose section
typedef struct { const void *replacement; const void *replacee; } interpose_t;

__attribute__((used)) static const interpose_t interps[]
__attribute__((section("__DATA,__interpose"))) = {
    { (const void *)my_SecTrustEvalWithErr, (const void *)SecTrustEvaluateWithError },
    { (const void *)my_SecTrustEval, (const void *)SecTrustEvaluate },
};

// ========================================
// PART 2: Scan and patch OpenSSL
// ========================================

static void hookOpenSSL(void) {
    const char *names[] = {
        "PKCS7_verify", "X509_verify_cert", "EVP_VerifyFinal",
        "ECDSA_verify", "RSA_verify", "EVP_DigestVerifyFinal", NULL
    };
    
    for (int i = 0; names[i]; i++) {
        void *sym = dlsym(RTLD_DEFAULT, names[i]);
        [_log appendFormat:@"[SCAN] %s = %s\n", names[i], sym ? "FOUND" : "no"];
        
        if (sym && (strcmp(names[i], "PKCS7_verify") == 0 ||
                    strcmp(names[i], "EVP_VerifyFinal") == 0 ||
                    strcmp(names[i], "EVP_DigestVerifyFinal") == 0)) {
            // Try to patch: MOV W0, #1; RET
            uint32_t *fn = (uint32_t *)sym;
            vm_address_t page = (vm_address_t)fn & ~(vm_address_t)0x3FFF;
            kern_return_t kr = vm_protect(mach_task_self(), page, 0x4000, FALSE,
                                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
            if (kr == KERN_SUCCESS) {
                fn[0] = 0x52800020; // MOV W0, #1
                fn[1] = 0xD65F03C0; // RET
                [_log appendFormat:@"[PATCH] %s -> return 1\n", names[i]];
            } else {
                [_log appendFormat:@"[FAIL] vm_protect %s: %d\n", names[i], kr];
            }
        }
    }
}

// ========================================
// PART 3: StoreKit faking
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
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v17b CRYPTO ===\n\n"];
    
    hookOpenSSL();
    
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
        l.text = @"✅ v17b CRYPTO - tap Buy then Cancel!";
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
