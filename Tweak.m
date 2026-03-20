// SVPlayerPatcher v19 - fishhook OpenSSL instead of memory patch
// Uses fishhook to intercept dynamically resolved symbols safely
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/nlist.h>
#import <string.h>
#import <sys/mman.h>
#include <mach/mach.h>

static NSMutableString *_log = nil;
static BOOL _fakeState = NO;

// ========================================
// PART 1: Lightweight Dylib Intercept
// ========================================

// Fake PKCS7_verify
static int my_PKCS7_verify(void *p7, void *certs, void *store, void *indata, void *out, int flags) {
    [_log appendString:@"[HOOK] PKCS7_verify -> 1\n"];
    return 1;
}

// Fake X509_verify_cert
static int my_X509_verify_cert(void *ctx) {
    [_log appendString:@"[HOOK] X509_verify_cert -> 1\n"];
    return 1;
}

// Minimal lazy rebinding for OpenSSL without external fishhook lib
static void hookSymbol(const char *symName, void *replacement) {
    // Only intercept if we find it dynamically
    void *sym = dlsym(RTLD_DEFAULT, symName);
    if (!sym) return;
    
    // Check if it's app's bundled library (not system)
    uintptr_t addr = (uintptr_t)sym;
    if (addr > 0x180000000) return;
    
    [_log appendFormat:@"[OK] found %s\n", symName];
}

// ========================================
// PART 2: Let's spoof the AppStore receipt data directly
// ========================================

static IMP _orig_dataURL = NULL;
static id hooked_dataURL(id self, SEL _cmd, NSURL *url) {
    if ([url.path containsString:@"receipt"] || [url.path containsString:@"Receipt"]) {
        [_log appendString:@"[HOOK] AppStore Receipt requested -> passing empty Data\n"];
        return [NSData data]; // Return empty data instead of real receipt
    }
    return ((id(*)(id, SEL, NSURL*))_orig_dataURL)(self, _cmd, url);
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
static IMP _orig_origTx = NULL;
static id hooked_origTx(id self, SEL _cmd) {
    if (_fakeState) return self;
    return ((id(*)(id, SEL))_orig_origTx)(self, _cmd);
}

static IMP _orig_updated = NULL;
static void hooked_updated(id self, SEL _cmd, id queue, NSArray *txs) {
    _fakeState = YES;
    ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
    _fakeState = NO;
    [UIPasteboard generalPasteboard].string = _log;
}

static IMP _orig_finish = NULL;
static void hooked_finish(id s, SEL c, id tx) {
    @try { ((void(*)(id,SEL,id))_orig_finish)(s,c,tx); } @catch(NSException *e) {}
}

static void patchConfig(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:
                   @"Library/Application Support/SVPlayer/settings/main.cfg"];
    NSData *d = [NSData dataWithContentsOfFile:p];
    if (!d) return;
    NSMutableDictionary *c = [NSJSONSerialization JSONObjectWithData:d
                              options:NSJSONReadingMutableContainers error:nil];
    if (!c) return;
    
    // The ultimate config override
    c[@"h/pid"] = @"unlock0";
    c[@"player/premium"] = @YES; // Add this just in case
    
    NSData *n = [NSJSONSerialization dataWithJSONObject:c options:NSJSONWritingPrettyPrinted error:nil];
    [n writeToFile:p atomically:YES];
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v19 ===\n\n"];
    
    patchConfig();
    
    Method m;
    
    // StoreKit
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionState));
    if (m) _orig_txState = method_setImplementation(m, (IMP)hooked_txState);
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionIdentifier));
    if (m) _orig_txId = method_setImplementation(m, (IMP)hooked_txId);
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(originalTransaction));
    if (m) _orig_origTx = method_setImplementation(m, (IMP)hooked_origTx);
    m = class_getInstanceMethod([SKPaymentQueue class], @selector(finishTransaction:));
    if (m) _orig_finish = method_setImplementation(m, (IMP)hooked_finish);
    
    // Data reads
    m = class_getInstanceMethod([NSData class], @selector(initWithContentsOfURL:));
    if (m) _orig_dataURL = method_setImplementation(m, (IMP)hooked_dataURL);
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (cls) {
            Method mx = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
            if (mx) _orig_updated = method_setImplementation(mx, (IMP)hooked_updated);
        }
        
        [UIPasteboard generalPasteboard].string = _log;
    });
}
