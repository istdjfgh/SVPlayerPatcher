// SVPlayerPatcher v10c - Minimal safe hooks
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static UIWindow *_overlayWindow = nil;
static NSMutableString *_log = nil;
static id _iapManager = nil;

// === Hook 1: Capture observer - NO ivar reading ===
static IMP _orig_addObserver = NULL;

static void hooked_addObserver(id self, SEL _cmd, id observer) {
    NSString *cn = NSStringFromClass([observer class]);
    [_log appendFormat:@"[CAPTURE] %@\n", cn];
    if ([cn isEqualToString:@"InAppPurchaseManager"]) {
        _iapManager = observer;
    }
    ((void(*)(id, SEL, id))_orig_addObserver)(self, _cmd, observer);
}

// === Hook 2: updatedTransactions ===
static IMP _orig_updated = NULL;

static void hooked_updated(id self, SEL _cmd, id queue, NSArray *txs) {
    [_log appendFormat:@"\n[TX] %lu transactions:\n", (unsigned long)txs.count];
    for (SKPaymentTransaction *tx in txs) {
        [_log appendFormat:@"  state=%ld prod=%@ id=%@\n",
         (long)tx.transactionState, tx.payment.productIdentifier, tx.transactionIdentifier];
    }
    [UIPasteboard generalPasteboard].string = _log;
    ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
}

// === Hook 3: products response ===
static IMP _orig_products = NULL;

static void hooked_products(id self, SEL _cmd, id req, SKProductsResponse *resp) {
    [_log appendString:@"\n[PRODUCTS]\n"];
    for (SKProduct *p in resp.products) {
        [_log appendFormat:@"  %@ (%@) %@\n", p.productIdentifier, p.localizedTitle, p.price];
    }
    [UIPasteboard generalPasteboard].string = _log;
    ((void(*)(id, SEL, id, SKProductsResponse*))_orig_products)(self, _cmd, req, resp);
}

// === Hook 4: restore finished ===
static IMP _orig_restored = NULL;
static void hooked_restored(id self, SEL _cmd, id q) {
    [_log appendString:@"\n[RESTORE] Done\n"];
    [UIPasteboard generalPasteboard].string = _log;
    ((void(*)(id, SEL, id))_orig_restored)(self, _cmd, q);
}

// === Hook 5: network ===
static IMP _orig_task = NULL;
static id hooked_task(id self, SEL _cmd, NSURLRequest *req, void(^comp)(NSData*, NSURLResponse*, NSError*)) {
    NSString *u = req.URL.absoluteString;
    if ([u containsString:@"svp"] || [u containsString:@"apple.com"] || [u containsString:@"itunes"]) {
        [_log appendFormat:@"[NET] %@\n", u];
    }
    return ((id(*)(id, SEL, NSURLRequest*, void(^)(NSData*, NSURLResponse*, NSError*)))_orig_task)(self, _cmd, req, comp);
}

// Safely dump InAppPurchaseManager (called with delay)
static void dumpIAPManager(void) {
    if (!_iapManager) {
        [_log appendString:@"[FAIL] No IAP manager captured\n"];
        return;
    }
    
    Class cls = [_iapManager class];
    [_log appendFormat:@"\n=== InAppPurchaseManager dump ===\n"];
    
    // Methods (safe - class metadata)
    unsigned int mc = 0;
    Method *methods = class_copyMethodList(cls, &mc);
    [_log appendFormat:@"Methods (%d):\n", mc];
    for (unsigned int i = 0; i < mc; i++) {
        [_log appendFormat:@"  %@\n", NSStringFromSelector(method_getName(methods[i]))];
    }
    if (methods) free(methods);
    
    // Properties (safe - class metadata)
    unsigned int pc = 0;
    objc_property_t *props = class_copyPropertyList(cls, &pc);
    [_log appendFormat:@"\nProperties (%d):\n", pc];
    for (unsigned int i = 0; i < pc; i++) {
        [_log appendFormat:@"  %s\n", property_getName(props[i])];
    }
    if (props) free(props);
    
    // Try reading properties via KVC (safer than ivar access)
    [_log appendString:@"\nKVC values:\n"];
    for (unsigned int i = 0; i < pc; i++) {
        NSString *pn = [NSString stringWithUTF8String:property_getName(props[i])];
        @try {
            id val = [_iapManager valueForKey:pn];
            [_log appendFormat:@"  %@ = %@\n", pn, val];
        } @catch (NSException *e) {
            [_log appendFormat:@"  %@ = <err: %@>\n", pn, e.reason];
        }
    }
    if (props) free(props);
    
    // Ivar names only (don't read values)
    unsigned int ic = 0;
    Ivar *ivars = class_copyIvarList(cls, &ic);
    [_log appendFormat:@"\nIvars (%d):\n", ic];
    for (unsigned int i = 0; i < ic; i++) {
        const char *n = ivar_getName(ivars[i]);
        const char *t = ivar_getTypeEncoding(ivars[i]);
        [_log appendFormat:@"  %s (%s)\n", n, t ? t : "?"];
    }
    if (ivars) free(ivars);
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v10c ===\n\n"];
    
    // Hook addTransactionObserver
    Method m = class_getInstanceMethod([SKPaymentQueue class], @selector(addTransactionObserver:));
    if (m) { _orig_addObserver = method_setImplementation(m, (IMP)hooked_addObserver); [_log appendString:@"[OK] Hook observer\n"]; }
    
    // Hook NSURLSession
    m = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (m) { _orig_task = method_setImplementation(m, (IMP)hooked_task); [_log appendString:@"[OK] Hook net\n"]; }
    
    // Delayed: hook IAP methods + dump
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (cls) {
            Method m2 = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
            if (m2) { _orig_updated = method_setImplementation(m2, (IMP)hooked_updated); [_log appendString:@"[OK] Hook tx\n"]; }
            
            Method m3 = class_getInstanceMethod(cls, @selector(productsRequest:didReceiveResponse:));
            if (m3) { _orig_products = method_setImplementation(m3, (IMP)hooked_products); [_log appendString:@"[OK] Hook prod\n"]; }
            
            Method m4 = class_getInstanceMethod(cls, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
            if (m4) { _orig_restored = method_setImplementation(m4, (IMP)hooked_restored); [_log appendString:@"[OK] Hook restore\n"]; }
        }
        
        dumpIAPManager();
        
        [UIPasteboard generalPasteboard].string = _log;
        
        // Show overlay
        UIWindowScene *scene = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) { scene = s; break; }
        if (!scene) return;
        
        _overlayWindow = [[UIWindow alloc] initWithWindowScene:scene];
        _overlayWindow.frame = scene.coordinateSpace.bounds;
        _overlayWindow.windowLevel = UIWindowLevelAlert + 100;
        _overlayWindow.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.92];
        _overlayWindow.rootViewController = [[UIViewController alloc] init];
        CGRect b = _overlayWindow.bounds;
        
        UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, b.size.width - 40, 30)];
        t.text = @"v10c OK - close this, tap Restore, paste log";
        t.textColor = [UIColor cyanColor];
        t.font = [UIFont boldSystemFontOfSize:13];
        [_overlayWindow.rootViewController.view addSubview:t];
        
        UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(10, 85, b.size.width - 20, b.size.height - 95)];
        tv.text = _log;
        tv.font = [UIFont fontWithName:@"Menlo" size:10];
        tv.textColor = [UIColor greenColor];
        tv.backgroundColor = [UIColor clearColor];
        tv.editable = NO;
        tv.tag = 999;
        [_overlayWindow.rootViewController.view addSubview:tv];
        
        _overlayWindow.hidden = NO;
        [_overlayWindow makeKeyAndVisible];
        
        // Update log periodically
        for (int i = 1; i <= 20; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                UITextView *lv = (UITextView*)[_overlayWindow.rootViewController.view viewWithTag:999];
                if (lv) lv.text = _log;
                [UIPasteboard generalPasteboard].string = _log;
            });
        }
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(60.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [UIPasteboard generalPasteboard].string = _log;
            _overlayWindow.hidden = YES;
            _overlayWindow = nil;
        });
    });
}
