// SVPlayerPatcher v10b - Safe InAppPurchaseManager dump
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static UIWindow *_overlayWindow = nil;
static NSMutableString *_log = nil;
static id _iapManager = nil;

// === Hook 1: Capture InAppPurchaseManager ===
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
        [_log appendFormat:@"\n[METHODS] %d total:\n", mc];
        for (unsigned int i = 0; i < mc; i++) {
            SEL sel = method_getName(methods[i]);
            [_log appendFormat:@"  %@\n", NSStringFromSelector(sel)];
        }
        if (methods) free(methods);
        
        // Dump ALL properties
        unsigned int pc = 0;
        objc_property_t *props = class_copyPropertyList([observer class], &pc);
        [_log appendFormat:@"\n[PROPS] %d total:\n", pc];
        for (unsigned int i = 0; i < pc; i++) {
            const char *pn = property_getName(props[i]);
            const char *pa = property_getAttributes(props[i]);
            [_log appendFormat:@"  %s = %s\n", pn, pa ? pa : "?"];
        }
        if (props) free(props);
        
        // Dump ivars SAFELY - only read ObjC object types
        unsigned int ic = 0;
        Ivar *ivars = class_copyIvarList([observer class], &ic);
        [_log appendFormat:@"\n[IVARS] %d total:\n", ic];
        for (unsigned int i = 0; i < ic; i++) {
            const char *name = ivar_getName(ivars[i]);
            const char *type = ivar_getTypeEncoding(ivars[i]);
            
            if (type && type[0] == '@') {
                // ObjC object - safe to read
                @try {
                    id val = object_getIvar(observer, ivars[i]);
                    if (val) {
                        NSString *desc = [val description];
                        if (desc.length > 150) desc = [[desc substringToIndex:150] stringByAppendingString:@"..."];
                        [_log appendFormat:@"  %s (@) = %@\n", name, desc];
                    } else {
                        [_log appendFormat:@"  %s (@) = nil\n", name];
                    }
                } @catch (NSException *e) {
                    [_log appendFormat:@"  %s (@) = <error>\n", name];
                }
            } else if (type && (type[0] == 'B' || type[0] == 'c')) {
                // BOOL or char
                @try {
                    ptrdiff_t offset = ivar_getOffset(ivars[i]);
                    char *base = (char *)(__bridge void *)observer;
                    BOOL val = *(BOOL *)(base + offset);
                    [_log appendFormat:@"  %s (BOOL) = %@\n", name, val ? @"YES" : @"NO"];
                } @catch (NSException *e) {
                    [_log appendFormat:@"  %s (BOOL) = <error>\n", name];
                }
            } else if (type && (type[0] == 'i' || type[0] == 'q' || type[0] == 'l')) {
                // int/long
                @try {
                    ptrdiff_t offset = ivar_getOffset(ivars[i]);
                    char *base = (char *)(__bridge void *)observer;
                    long val = *(long *)(base + offset);
                    [_log appendFormat:@"  %s (int) = %ld\n", name, val];
                } @catch (NSException *e) {
                    [_log appendFormat:@"  %s (int) = <error>\n", name];
                }
            } else {
                [_log appendFormat:@"  %s (%s)\n", name, type ? type : "?"];
            }
        }
        if (ivars) free(ivars);
    }
    
    ((void(*)(id, SEL, id))_orig_addObserver)(self, _cmd, observer);
}

// === Hook 2: updatedTransactions ===
static IMP _orig_updated = NULL;

static void hooked_updated(id self, SEL _cmd, id queue, NSArray *txs) {
    [_log appendFormat:@"\n[TX] updatedTransactions: %lu\n", (unsigned long)txs.count];
    for (SKPaymentTransaction *tx in txs) {
        [_log appendFormat:@"  state=%ld product=%@ txID=%@\n",
         (long)tx.transactionState, tx.payment.productIdentifier, tx.transactionIdentifier];
    }
    ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
}

// === Hook 3: productsResponse ===
static IMP _orig_products = NULL;

static void hooked_products(id self, SEL _cmd, id req, SKProductsResponse *resp) {
    [_log appendString:@"\n[PRODUCTS] Response:\n"];
    for (SKProduct *p in resp.products) {
        [_log appendFormat:@"  ID: %@ title: %@ price: %@\n",
         p.productIdentifier, p.localizedTitle, p.price];
    }
    [_log appendFormat:@"  Invalid: %@\n", resp.invalidProductIdentifiers];
    ((void(*)(id, SEL, id, SKProductsResponse*))_orig_products)(self, _cmd, req, resp);
}

// === Hook 4: restoreFinished ===
static IMP _orig_restored = NULL;

static void hooked_restored(id self, SEL _cmd, id queue) {
    [_log appendString:@"\n[RESTORE] Finished!\n"];
    ((void(*)(id, SEL, id))_orig_restored)(self, _cmd, queue);
}

// === Hook 5: NSURLSession ===
static IMP _orig_task = NULL;

static id hooked_task(id self, SEL _cmd, NSURLRequest *req, void(^comp)(NSData*, NSURLResponse*, NSError*)) {
    NSString *url = req.URL.absoluteString;
    if ([url containsString:@"svp"] || [url containsString:@"apple.com"] ||
        [url containsString:@"itunes"]) {
        [_log appendFormat:@"\n[NET] %@ %@\n", req.HTTPMethod, url];
    }
    return ((id(*)(id, SEL, NSURLRequest*, void(^)(NSData*, NSURLResponse*, NSError*)))_orig_task)(self, _cmd, req, comp);
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
    [_log appendString:@"[OK] main.cfg patched\n"];
}

static void applyHooks(void) {
    Method m;
    m = class_getInstanceMethod([SKPaymentQueue class], @selector(addTransactionObserver:));
    if (m) { _orig_addObserver = method_setImplementation(m, (IMP)hooked_addObserver); [_log appendString:@"[OK] Hook addObserver\n"]; }
    
    m = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (m) { _orig_task = method_setImplementation(m, (IMP)hooked_task); [_log appendString:@"[OK] Hook NSURLSession\n"]; }
    
    patchConfig();
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (!cls) { [_log appendString:@"[FAIL] No InAppPurchaseManager\n"]; return; }
        [_log appendString:@"[OK] Found InAppPurchaseManager\n"];
        
        Method m2 = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
        if (m2) { _orig_updated = method_setImplementation(m2, (IMP)hooked_updated); [_log appendString:@"[OK] Hook updatedTx\n"]; }
        
        Method m3 = class_getInstanceMethod(cls, @selector(productsRequest:didReceiveResponse:));
        if (m3) { _orig_products = method_setImplementation(m3, (IMP)hooked_products); [_log appendString:@"[OK] Hook products\n"]; }
        
        Method m4 = class_getInstanceMethod(cls, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
        if (m4) { _orig_restored = method_setImplementation(m4, (IMP)hooked_restored); [_log appendString:@"[OK] Hook restore\n"]; }
    });
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v10b ===\n\n"];
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
        t.text = @"v10b - wait 60s, tap Restore, paste log";
        t.textColor = [UIColor cyanColor];
        t.font = [UIFont boldSystemFontOfSize:13];
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
        
        for (int i = 1; i <= 12; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
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
