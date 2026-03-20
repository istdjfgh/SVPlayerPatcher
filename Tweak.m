// SVPlayerPatcher v10 - Direct InAppPurchaseManager hook
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static UIWindow *_overlayWindow = nil;
static NSMutableString *_log = nil;
static id _iapManager = nil;

// === Hook 1: Capture InAppPurchaseManager instance ===
static IMP _orig_addObserver = NULL;

static void hooked_addObserver(id self, SEL _cmd, id observer) {
    NSString *className = NSStringFromClass([observer class]);
    [_log appendFormat:@"[CAPTURE] Observer: %@\n", className];
    
    if ([className isEqualToString:@"InAppPurchaseManager"]) {
        _iapManager = observer;
        [_log appendString:@"[OK] InAppPurchaseManager captured!\n"];
        
        // Dump ALL methods
        unsigned int mc = 0;
        Method *methods = class_copyMethodList([observer class], &mc);
        [_log appendFormat:@"[INFO] %d methods:\n", mc];
        for (unsigned int i = 0; i < mc; i++) {
            SEL sel = method_getName(methods[i]);
            [_log appendFormat:@"  M: %@\n", NSStringFromSelector(sel)];
        }
        if (methods) free(methods);
        
        // Dump ALL properties
        unsigned int pc = 0;
        objc_property_t *props = class_copyPropertyList([observer class], &pc);
        [_log appendFormat:@"[INFO] %d properties:\n", pc];
        for (unsigned int i = 0; i < pc; i++) {
            const char *pn = property_getName(props[i]);
            const char *pa = property_getAttributes(props[i]);
            [_log appendFormat:@"  P: %s (%s)\n", pn, pa];
        }
        if (props) free(props);
        
        // Dump ALL ivars
        unsigned int ic = 0;
        Ivar *ivars = class_copyIvarList([observer class], &ic);
        [_log appendFormat:@"[INFO] %d ivars:\n", ic];
        for (unsigned int i = 0; i < ic; i++) {
            const char *in = ivar_getName(ivars[i]);
            const char *it = ivar_getTypeEncoding(ivars[i]);
            
            // Try to read ivar value
            id value = nil;
            @try {
                value = object_getIvar(observer, ivars[i]);
            } @catch (NSException *e) {
                value = nil;
            }
            [_log appendFormat:@"  IV: %s (%s) = %@\n", in, it ? it : "?", value];
        }
        if (ivars) free(ivars);
    }
    
    ((void(*)(id, SEL, id))_orig_addObserver)(self, _cmd, observer);
}

// === Hook 2: Intercept paymentQueue:updatedTransactions: ===
static IMP _orig_updatedTransactions = NULL;

static void hooked_updatedTransactions(id self, SEL _cmd, id queue, NSArray *transactions) {
    [_log appendFormat:@"[INTERCEPT] updatedTransactions: %lu transactions\n", (unsigned long)transactions.count];
    
    for (SKPaymentTransaction *tx in transactions) {
        [_log appendFormat:@"  TX state=%ld product=%@\n", 
         (long)tx.transactionState, tx.payment.productIdentifier];
    }
    
    // Call original
    ((void(*)(id, SEL, id, NSArray*))_orig_updatedTransactions)(self, _cmd, queue, transactions);
}

// === Hook 3: Intercept productsRequest:didReceiveResponse: ===
static IMP _orig_productsResponse = NULL;

static void hooked_productsResponse(id self, SEL _cmd, SKProductsRequest *request, SKProductsResponse *response) {
    [_log appendString:@"[INTERCEPT] productsRequest:didReceiveResponse:\n"];
    
    for (SKProduct *product in response.products) {
        [_log appendFormat:@"  PRODUCT: %@ (%@) price=%@\n", 
         product.productIdentifier, product.localizedTitle, product.price];
    }
    
    [_log appendFormat:@"  Invalid IDs: %@\n", response.invalidProductIdentifiers];
    
    ((void(*)(id, SEL, SKProductsRequest*, SKProductsResponse*))_orig_productsResponse)(self, _cmd, request, response);
}

// === Hook 4: Intercept restoreFinished ===
static IMP _orig_restoreFinished = NULL;

static void hooked_restoreFinished(id self, SEL _cmd, id queue) {
    [_log appendString:@"[INTERCEPT] paymentQueueRestoreCompletedTransactionsFinished!\n"];
    ((void(*)(id, SEL, id))_orig_restoreFinished)(self, _cmd, queue);
}

// === Hook 5: NSURLSession for server checks ===
static IMP _orig_dataTask = NULL;

static id hooked_dataTask(id self, SEL _cmd, NSURLRequest *request, void(^completion)(NSData*, NSURLResponse*, NSError*)) {
    NSString *url = request.URL.absoluteString;
    
    if ([url containsString:@"svp-team"] || [url containsString:@"apple.com/verifyReceipt"] ||
        [url containsString:@"sandbox.itunes"]) {
        [_log appendFormat:@"[NET] %@ %@\n", request.HTTPMethod, url];
        
        if (request.HTTPBody) {
            NSString *body = [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding];
            if (body) [_log appendFormat:@"[NET] Body: %.200s...\n", body.UTF8String];
        }
    }
    
    return ((id(*)(id, SEL, NSURLRequest*, void(^)(NSData*, NSURLResponse*, NSError*)))_orig_dataTask)(self, _cmd, request, completion);
}

// === Patch main.cfg ===
static void patchConfig(void) {
    NSString *cfgPath = [NSHomeDirectory() stringByAppendingPathComponent:
                         @"Library/Application Support/SVPlayer/settings/main.cfg"];
    NSData *data = [NSData dataWithContentsOfFile:cfgPath];
    if (!data) return;
    NSMutableDictionary *cfg = [NSJSONSerialization JSONObjectWithData:data 
                                options:NSJSONReadingMutableContainers error:nil];
    if (!cfg) return;
    cfg[@"h/pid"] = @"2000000845671234";
    cfg[@"h/last_check"] = @(1893456000);
    NSData *nd = [NSJSONSerialization dataWithJSONObject:cfg options:NSJSONWritingPrettyPrinted error:nil];
    [nd writeToFile:cfgPath atomically:YES];
    [_log appendString:@"[OK] main.cfg patched\n"];
}

static void applyHooks(void) {
    // Hook addTransactionObserver
    Class skpq = [SKPaymentQueue class];
    Method m1 = class_getInstanceMethod(skpq, @selector(addTransactionObserver:));
    if (m1) {
        _orig_addObserver = method_setImplementation(m1, (IMP)hooked_addObserver);
        [_log appendString:@"[OK] Hook addTransactionObserver\n"];
    }
    
    // Hook NSURLSession
    Method m5 = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (m5) {
        _orig_dataTask = method_setImplementation(m5, (IMP)hooked_dataTask);
        [_log appendString:@"[OK] Hook NSURLSession.dataTask\n"];
    }
    
    patchConfig();
    
    // Hook InAppPurchaseManager methods AFTER observer is registered
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class iapClass = NSClassFromString(@"InAppPurchaseManager");
        if (iapClass) {
            [_log appendString:@"[OK] Found InAppPurchaseManager class\n"];
            
            Method m2 = class_getInstanceMethod(iapClass, @selector(paymentQueue:updatedTransactions:));
            if (m2) {
                _orig_updatedTransactions = method_setImplementation(m2, (IMP)hooked_updatedTransactions);
                [_log appendString:@"[OK] Hook paymentQueue:updatedTransactions:\n"];
            }
            
            Method m3 = class_getInstanceMethod(iapClass, @selector(productsRequest:didReceiveResponse:));
            if (m3) {
                _orig_productsResponse = method_setImplementation(m3, (IMP)hooked_productsResponse);
                [_log appendString:@"[OK] Hook productsRequest:didReceiveResponse:\n"];
            }
            
            Method m4 = class_getInstanceMethod(iapClass, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
            if (m4) {
                _orig_restoreFinished = method_setImplementation(m4, (IMP)hooked_restoreFinished);
                [_log appendString:@"[OK] Hook restoreFinished\n"];
            }
        } else {
            [_log appendString:@"[FAIL] InAppPurchaseManager class not found\n"];
        }
    });
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v10 ===\n\n"];
    applyHooks();
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [UIPasteboard generalPasteboard].string = _log;
        
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
        t.text = @"v10 - CLOSE THIS, tap Buy/Restore, then paste log";
        t.textColor = [UIColor cyanColor];
        t.font = [UIFont boldSystemFontOfSize:13];
        t.adjustsFontSizeToFitWidth = YES;
        [_overlayWindow.rootViewController.view addSubview:t];
        
        UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(10, 90, b.size.width - 20, b.size.height - 100)];
        tv.text = _log;
        tv.font = [UIFont fontWithName:@"Menlo" size:10];
        tv.textColor = [UIColor greenColor];
        tv.backgroundColor = [UIColor clearColor];
        tv.editable = NO;
        tv.tag = 999;
        [_overlayWindow.rootViewController.view addSubview:tv];
        
        _overlayWindow.hidden = NO;
        [_overlayWindow makeKeyAndVisible];
        
        // Auto-update log every 5 sec
        for (int i = 1; i <= 12; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                UITextView *lv = (UITextView*)[_overlayWindow.rootViewController.view viewWithTag:999];
                if (lv) lv.text = _log;
                [UIPasteboard generalPasteboard].string = _log;
            });
        }
        
        // Close after 60s
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(60.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [UIPasteboard generalPasteboard].string = _log;
            _overlayWindow.hidden = YES;
            _overlayWindow = nil;
        });
    });
}
