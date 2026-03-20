// SVPlayerPatcher v12 - Fake tx state + fake network validation
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSMutableString *_log = nil;
static BOOL _fakeState = NO;

// === Fake transactionState -> Restored ===
static IMP _orig_txState = NULL;
static NSInteger hooked_txState(id self, SEL _cmd) {
    if (_fakeState) return SKPaymentTransactionStateRestored;
    return ((NSInteger(*)(id, SEL))_orig_txState)(self, _cmd);
}

// === Fake transactionIdentifier ===
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

// === Hook updatedTransactions ===
static IMP _orig_updated = NULL;
static void hooked_updated(id self, SEL _cmd, id queue, NSArray *txs) {
    [_log appendFormat:@"[TX] %lu txs\n", (unsigned long)txs.count];
    for (SKPaymentTransaction *tx in txs) {
        NSInteger realState = ((NSInteger(*)(id, SEL))_orig_txState)(tx, @selector(transactionState));
        [_log appendFormat:@"  real=%ld prod=%@\n", (long)realState, tx.payment.productIdentifier];
    }
    
    // Always fake for hfr.m.y
    _fakeState = YES;
    ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
    _fakeState = NO;
    [UIPasteboard generalPasteboard].string = _log;
}

// === Hook finishTransaction ===
static IMP _orig_finish = NULL;
static void hooked_finish(id self, SEL _cmd, SKPaymentTransaction *tx) {
    [_log appendFormat:@"[FINISH] %@\n", tx.payment.productIdentifier];
    @try { ((void(*)(id, SEL, id))_orig_finish)(self, _cmd, tx); }
    @catch (NSException *e) { [_log appendFormat:@"[FINISH] err: %@\n", e.reason]; }
}

// === Hook restoreFinished ===
static IMP _orig_restored = NULL;
static void hooked_restored(id self, SEL _cmd, id q) {
    [_log appendString:@"[RESTORE] Done\n"];
    [UIPasteboard generalPasteboard].string = _log;
    ((void(*)(id, SEL, id))_orig_restored)(self, _cmd, q);
}

// === Hook productsResponse ===
static IMP _orig_products = NULL;
static void hooked_products(id self, SEL _cmd, id req, SKProductsResponse *resp) {
    [_log appendString:@"[PRODUCTS]\n"];
    for (SKProduct *p in resp.products) {
        [_log appendFormat:@"  %@ %@\n", p.productIdentifier, p.price];
    }
    ((void(*)(id, SEL, id, SKProductsResponse*))_orig_products)(self, _cmd, req, resp);
}

// === CRITICAL: Hook ALL NSURLSession data tasks ===
static IMP _orig_dataTask = NULL;

static id hooked_dataTask(id self, SEL _cmd, NSURLRequest *request, void(^completion)(NSData*, NSURLResponse*, NSError*)) {
    NSString *url = request.URL.absoluteString;
    [_log appendFormat:@"[NET] %@\n", url];
    
    // Intercept Apple receipt validation
    if ([url containsString:@"apple.com"] && ([url containsString:@"verify"] || [url containsString:@"receipt"])) {
        [_log appendString:@"[FAKE] Apple receipt -> valid!\n"];
        
        NSDictionary *fake = @{
            @"status": @0,
            @"latest_receipt_info": @[@{
                @"product_id": @"hfr.m.y",
                @"transaction_id": @"2000000845671234",
                @"original_transaction_id": @"2000000845671234",
                @"purchase_date_ms": @"1710000000000",
                @"expires_date_ms": @"1893456000000",
                @"is_trial_period": @"false",
                @"is_in_intro_offer_period": @"false"
            }],
            @"pending_renewal_info": @[@{
                @"product_id": @"hfr.m.y",
                @"auto_renew_status": @"1"
            }]
        };
        NSData *fakeData = [NSJSONSerialization dataWithJSONObject:fake options:0 error:nil];
        NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:request.URL
                                       statusCode:200 HTTPVersion:@"HTTP/1.1"
                                       headerFields:@{@"Content-Type": @"application/json"}];
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(fakeData, fakeResp, nil);
            });
        }
        return [[NSURLSession sharedSession] dataTaskWithURL:[NSURL URLWithString:@"about:blank"]];
    }
    
    // Intercept SVP Team server
    if ([url containsString:@"svp-team"] || [url containsString:@"svp4"]) {
        [_log appendFormat:@"[FAKE] SVP server -> licensed!\n"];
        
        NSDictionary *fake = @{@"status": @"ok", @"licensed": @YES, @"plan": @"yearly", @"expires": @"2030-01-01"};
        NSData *fakeData = [NSJSONSerialization dataWithJSONObject:fake options:0 error:nil];
        NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:request.URL
                                       statusCode:200 HTTPVersion:@"HTTP/1.1"
                                       headerFields:@{@"Content-Type": @"application/json"}];
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(fakeData, fakeResp, nil);
            });
        }
        return [[NSURLSession sharedSession] dataTaskWithURL:[NSURL URLWithString:@"about:blank"]];
    }
    
    // Wrap non-intercepted completions to log responses
    void(^wrappedComp)(NSData*, NSURLResponse*, NSError*) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (err) {
            [_log appendFormat:@"[NET-ERR] %@: %@\n", url, err.localizedDescription];
        }
        if (completion) completion(data, resp, err);
    };
    
    return ((id(*)(id, SEL, NSURLRequest*, void(^)(NSData*, NSURLResponse*, NSError*)))_orig_dataTask)(self, _cmd, request, wrappedComp);
}

// === Also hook dataTaskWithURL:completionHandler: ===
static IMP _orig_dataTaskURL = NULL;

static id hooked_dataTaskURL(id self, SEL _cmd, NSURL *url, void(^completion)(NSData*, NSURLResponse*, NSError*)) {
    NSString *us = url.absoluteString;
    if ([us containsString:@"svp"] || [us containsString:@"apple"]) {
        [_log appendFormat:@"[NET-URL] %@\n", us];
    }
    return ((id(*)(id, SEL, NSURL*, void(^)(NSData*, NSURLResponse*, NSError*)))_orig_dataTaskURL)(self, _cmd, url, completion);
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
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v12 ===\n\n"];
    
    Method m;
    // Hook SKPaymentTransaction
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionState));
    if (m) { _orig_txState = method_setImplementation(m, (IMP)hooked_txState); }
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionIdentifier));
    if (m) { _orig_txId = method_setImplementation(m, (IMP)hooked_txId); }
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionDate));
    if (m) { _orig_txDate = method_setImplementation(m, (IMP)hooked_txDate); }
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(originalTransaction));
    if (m) { _orig_origTx = method_setImplementation(m, (IMP)hooked_origTx); }
    m = class_getInstanceMethod([SKPaymentQueue class], @selector(finishTransaction:));
    if (m) { _orig_finish = method_setImplementation(m, (IMP)hooked_finish); }
    [_log appendString:@"[OK] StoreKit hooks\n"];
    
    // Hook NSURLSession
    m = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (m) { _orig_dataTask = method_setImplementation(m, (IMP)hooked_dataTask); }
    m = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithURL:completionHandler:));
    if (m) { _orig_dataTaskURL = method_setImplementation(m, (IMP)hooked_dataTaskURL); }
    [_log appendString:@"[OK] Network hooks\n"];
    
    patchConfig();
    
    // Hook InAppPurchaseManager (delayed)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (!cls) { [_log appendString:@"[FAIL] No IAP\n"]; return; }
        
        Method m2 = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
        if (m2) { _orig_updated = method_setImplementation(m2, (IMP)hooked_updated); }
        Method m3 = class_getInstanceMethod(cls, @selector(productsRequest:didReceiveResponse:));
        if (m3) { _orig_products = method_setImplementation(m3, (IMP)hooked_products); }
        Method m4 = class_getInstanceMethod(cls, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
        if (m4) { _orig_restored = method_setImplementation(m4, (IMP)hooked_restored); }
        [_log appendString:@"[OK] IAP hooks\n"];
        
        [UIPasteboard generalPasteboard].string = _log;
        
        // Small status banner
        UIWindowScene *scene = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) { scene = s; break; }
        if (!scene) return;
        UIWindow *w = [[UIWindow alloc] initWithWindowScene:scene];
        w.frame = CGRectMake(20, 40, 350, 30);
        w.windowLevel = UIWindowLevelAlert + 100;
        w.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.8];
        w.layer.cornerRadius = 8;
        w.clipsToBounds = YES;
        w.rootViewController = [[UIViewController alloc] init];
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(10, 0, 330, 30)];
        l.text = @"✅ v12 READY - tap Restore!";
        l.textColor = [UIColor greenColor];
        l.font = [UIFont boldSystemFontOfSize:13];
        [w.rootViewController.view addSubview:l];
        w.hidden = NO;
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ w.hidden = YES; });
        
        for (int i = 1; i <= 30; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [UIPasteboard generalPasteboard].string = _log;
            });
        }
    });
}
