// SVPlayerPatcher v11 - FINAL: Fake successful purchase for hfr.m.y
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSMutableString *_log = nil;
static BOOL _fakeState = NO;

// === Fake transactionState: return "Restored" (3) ===
static IMP _orig_txState = NULL;

static NSInteger hooked_txState(id self, SEL _cmd) {
    if (_fakeState) {
        return SKPaymentTransactionStateRestored; // 3 = restored
    }
    return ((NSInteger(*)(id, SEL))_orig_txState)(self, _cmd);
}

// === Fake transactionIdentifier ===
static IMP _orig_txId = NULL;

static NSString* hooked_txId(id self, SEL _cmd) {
    if (_fakeState) {
        return @"2000000845671234";
    }
    return ((NSString*(*)(id, SEL))_orig_txId)(self, _cmd);
}

// === Fake transactionDate ===
static IMP _orig_txDate = NULL;

static NSDate* hooked_txDate(id self, SEL _cmd) {
    if (_fakeState) {
        return [NSDate date];
    }
    return ((NSDate*(*)(id, SEL))_orig_txDate)(self, _cmd);
}

// === Fake originalTransaction (for restores) ===
static IMP _orig_origTx = NULL;

static id hooked_origTx(id self, SEL _cmd) {
    if (_fakeState) {
        return self; // point to self
    }
    return ((id(*)(id, SEL))_orig_origTx)(self, _cmd);
}

// === Hook paymentQueue:updatedTransactions: ===
static IMP _orig_updated = NULL;

static void hooked_updated(id self, SEL _cmd, id queue, NSArray *txs) {
    [_log appendFormat:@"\n[TX] %lu txs:\n", (unsigned long)txs.count];
    
    BOOL hasTarget = NO;
    for (SKPaymentTransaction *tx in txs) {
        NSString *pid = tx.payment.productIdentifier;
        [_log appendFormat:@"  state=%ld prod=%@\n", (long)tx.transactionState, pid];
        
        if ([pid isEqualToString:@"hfr.m.y"]) {
            hasTarget = YES;
        }
    }
    
    if (hasTarget) {
        [_log appendString:@"[PATCH] Faking state -> Restored!\n"];
        
        // Enable fake state
        _fakeState = YES;
        
        // Call original - it will see state=3 (restored) instead of state=2 (failed)
        ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
        
        // Disable fake state
        _fakeState = NO;
        
        [_log appendString:@"[PATCH] Done! Check if premium activated.\n"];
    } else {
        ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
    }
    
    [UIPasteboard generalPasteboard].string = _log;
}

// === Hook finishTransaction to not crash ===
static IMP _orig_finish = NULL;

static void hooked_finish(id self, SEL _cmd, SKPaymentTransaction *tx) {
    [_log appendFormat:@"[FINISH] prod=%@ state=%ld\n", tx.payment.productIdentifier, (long)tx.transactionState];
    @try {
        ((void(*)(id, SEL, SKPaymentTransaction*))_orig_finish)(self, _cmd, tx);
    } @catch (NSException *e) {
        [_log appendFormat:@"[FINISH] caught: %@\n", e.reason];
    }
}

// === Hook restoreFinished ===
static IMP _orig_restored = NULL;
static void hooked_restored(id self, SEL _cmd, id q) {
    [_log appendString:@"[RESTORE] Finished\n"];
    [UIPasteboard generalPasteboard].string = _log;
    ((void(*)(id, SEL, id))_orig_restored)(self, _cmd, q);
}

// === Hook products response ===
static IMP _orig_products = NULL;
static void hooked_products(id self, SEL _cmd, id req, SKProductsResponse *resp) {
    [_log appendString:@"[PRODUCTS]\n"];
    for (SKProduct *p in resp.products) {
        [_log appendFormat:@"  %@ price=%@\n", p.productIdentifier, p.price];
    }
    [UIPasteboard generalPasteboard].string = _log;
    ((void(*)(id, SEL, id, SKProductsResponse*))_orig_products)(self, _cmd, req, resp);
}

static void patchConfig(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:
                   @"Library/Application Support/SVPlayer/settings/main.cfg"];
    NSData *d = [NSData dataWithContentsOfFile:p];
    if (!d) return;
    NSMutableDictionary *c = [NSJSONSerialization JSONObjectWithData:d
                              options:NSJSONReadingMutableContainers error:nil];
    if (!c) return;
    c[@"h/pid"] = @"2000000845671234";
    c[@"h/last_check"] = @(1893456000);
    NSData *n = [NSJSONSerialization dataWithJSONObject:c options:NSJSONWritingPrettyPrinted error:nil];
    [n writeToFile:p atomically:YES];
    [_log appendString:@"[OK] cfg patched\n"];
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v11 FINAL ===\n\n"];
    
    // Hook SKPaymentTransaction getters
    Method m;
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionState));
    if (m) { _orig_txState = method_setImplementation(m, (IMP)hooked_txState); [_log appendString:@"[OK] Hook txState\n"]; }
    
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionIdentifier));
    if (m) { _orig_txId = method_setImplementation(m, (IMP)hooked_txId); [_log appendString:@"[OK] Hook txId\n"]; }
    
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionDate));
    if (m) { _orig_txDate = method_setImplementation(m, (IMP)hooked_txDate); [_log appendString:@"[OK] Hook txDate\n"]; }
    
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(originalTransaction));
    if (m) { _orig_origTx = method_setImplementation(m, (IMP)hooked_origTx); [_log appendString:@"[OK] Hook origTx\n"]; }
    
    // Hook SKPaymentQueue finishTransaction:
    m = class_getInstanceMethod([SKPaymentQueue class], @selector(finishTransaction:));
    if (m) { _orig_finish = method_setImplementation(m, (IMP)hooked_finish); [_log appendString:@"[OK] Hook finish\n"]; }
    
    patchConfig();
    
    // Delayed hooks for InAppPurchaseManager
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (!cls) { [_log appendString:@"[FAIL] No IAP class\n"]; return; }
        
        Method m2 = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
        if (m2) { _orig_updated = method_setImplementation(m2, (IMP)hooked_updated); [_log appendString:@"[OK] Hook tx\n"]; }
        
        Method m3 = class_getInstanceMethod(cls, @selector(productsRequest:didReceiveResponse:));
        if (m3) { _orig_products = method_setImplementation(m3, (IMP)hooked_products); [_log appendString:@"[OK] Hook prod\n"]; }
        
        Method m4 = class_getInstanceMethod(cls, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
        if (m4) { _orig_restored = method_setImplementation(m4, (IMP)hooked_restored); [_log appendString:@"[OK] Hook restore\n"]; }
        
        [UIPasteboard generalPasteboard].string = _log;
        
        // Brief status overlay (3 seconds only!)
        UIWindowScene *scene = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) { scene = s; break; }
        if (!scene) return;
        
        UIWindow *w = [[UIWindow alloc] initWithWindowScene:scene];
        w.frame = CGRectMake(20, 40, 400, 35);
        w.windowLevel = UIWindowLevelAlert + 100;
        w.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.8];
        w.layer.cornerRadius = 10;
        w.clipsToBounds = YES;
        w.rootViewController = [[UIViewController alloc] init];
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(10, 0, 380, 35)];
        l.text = @"✅ v11 ready - tap Restore now!";
        l.textColor = [UIColor greenColor];
        l.font = [UIFont boldSystemFontOfSize:14];
        [w.rootViewController.view addSubview:l];
        w.hidden = NO;
        [w makeKeyAndVisible];
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            w.hidden = YES;
        });
        
        // Keep updating clipboard with log
        for (int i = 1; i <= 30; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [UIPasteboard generalPasteboard].string = _log;
            });
        }
    });
}
