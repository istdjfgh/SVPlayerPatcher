// SVPlayerPatcher v9 - StoreKit interception
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static UIWindow *_overlayWindow = nil;
static NSMutableString *_globalLog = nil;
static id _capturedObserver = nil;

// === STEP 1: Capture the payment observer ===
static IMP _orig_addTransactionObserver = NULL;

static void hooked_addTransactionObserver(id self, SEL _cmd, id observer) {
    _capturedObserver = observer;
    [_globalLog appendFormat:@"[CAPTURE] Observer: %@\n", NSStringFromClass([observer class])];
    
    // Log all methods the observer responds to
    unsigned int mc = 0;
    Method *methods = class_copyMethodList([observer class], &mc);
    for (unsigned int i = 0; i < mc; i++) {
        SEL sel = method_getName(methods[i]);
        NSString *name = NSStringFromSelector(sel);
        NSString *ln = [name lowercaseString];
        if ([ln containsString:@"payment"] || [ln containsString:@"transact"] ||
            [ln containsString:@"purchase"] || [ln containsString:@"restore"] ||
            [ln containsString:@"product"] || [ln containsString:@"update"] ||
            [ln containsString:@"finish"] || [ln containsString:@"complet"]) {
            [_globalLog appendFormat:@"  OBS_M: %@\n", name];
        }
    }
    if (methods) free(methods);
    
    // Call original
    ((void(*)(id, SEL, id))_orig_addTransactionObserver)(self, _cmd, observer);
}

// === STEP 2: Hook restoreCompletedTransactions ===
static IMP _orig_restore = NULL;

static void hooked_restore(id self, SEL _cmd) {
    [_globalLog appendString:@"[INTERCEPT] restoreCompletedTransactions called!\n"];
    
    // Call original first
    ((void(*)(id, SEL))_orig_restore)(self, _cmd);
    
    // Then try to call the observer's success method after a delay
    if (_capturedObserver) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            // Try calling paymentQueueRestoreCompletedTransactionsFinished:
            SEL finishSel = @selector(paymentQueueRestoreCompletedTransactionsFinished:);
            if ([_capturedObserver respondsToSelector:finishSel]) {
                [_globalLog appendString:@"[OK] Calling restoreFinished on observer\n"];
                ((void(*)(id, SEL, id))objc_msgSend)(_capturedObserver, finishSel, self);
            }
        });
    }
}

// === STEP 3: Hook AppStore receipt check ===
static IMP _orig_receiptURL = NULL;

static NSURL* hooked_receiptURL(id self, SEL _cmd) {
    NSURL *orig = ((NSURL*(*)(id, SEL))_orig_receiptURL)(self, _cmd);
    [_globalLog appendFormat:@"[INTERCEPT] appStoreReceiptURL: %@\n", orig.path];
    return orig; // Don't modify, just log for now
}

// === STEP 4: Hook NSURLSession to intercept Apple receipt validation ===
static IMP _orig_dataTaskWithRequest = NULL;

static id hooked_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request, void(^completion)(NSData*, NSURLResponse*, NSError*)) {
    NSString *url = request.URL.absoluteString;
    
    if ([url containsString:@"apple.com"] || [url containsString:@"svp-team"] || 
        [url containsString:@"sandbox.itunes"] || [url containsString:@"buy.itunes"]) {
        [_globalLog appendFormat:@"[INTERCEPT] Network: %@\n", url];
        
        // If this is a receipt validation request to Apple or SVP servers
        if ([url containsString:@"verifyReceipt"] || [url containsString:@"receipt"]) {
            [_globalLog appendString:@"[FAKE] Returning fake valid receipt response\n"];
            
            // Return fake "valid" response
            NSDictionary *fakeResponse = @{
                @"status": @0,  // 0 = valid receipt
                @"receipt": @{
                    @"bundle_id": @"com.svpteam.svp",
                    @"in_app": @[@{
                        @"product_id": @"com.svpteam.svp.premium",
                        @"transaction_id": @"2000000845671234",
                        @"purchase_date": @"2025-01-01 00:00:00 Etc/GMT",
                        @"expires_date": @"2030-01-01 00:00:00 Etc/GMT"
                    }]
                }
            };
            NSData *fakeData = [NSJSONSerialization dataWithJSONObject:fakeResponse options:0 error:nil];
            NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:request.URL 
                                           statusCode:200 HTTPVersion:@"HTTP/1.1" 
                                           headerFields:@{@"Content-Type": @"application/json"}];
            
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (completion) completion(fakeData, fakeResp, nil);
            });
            
            // Return a dummy task
            return [[NSURLSession sharedSession] dataTaskWithURL:[NSURL URLWithString:@"about:blank"]];
        }
        
        // If SVP server check
        if ([url containsString:@"svp-team"]) {
            [_globalLog appendString:@"[FAKE] Returning fake SVP server response\n"];
            NSDictionary *fakeResponse = @{@"status": @"ok", @"licensed": @YES, @"expires": @"2030-01-01"};
            NSData *fakeData = [NSJSONSerialization dataWithJSONObject:fakeResponse options:0 error:nil];
            NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:request.URL 
                                           statusCode:200 HTTPVersion:@"HTTP/1.1" 
                                           headerFields:@{@"Content-Type": @"application/json"}];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (completion) completion(fakeData, fakeResp, nil);
            });
            return [[NSURLSession sharedSession] dataTaskWithURL:[NSURL URLWithString:@"about:blank"]];
        }
    }
    
    return ((id(*)(id, SEL, NSURLRequest*, void(^)(NSData*, NSURLResponse*, NSError*)))_orig_dataTaskWithRequest)(self, _cmd, request, completion);
}

// === STEP 5: Patch main.cfg ===
static void patchMainCfg(void) {
    NSString *cfgPath = [NSHomeDirectory() stringByAppendingPathComponent:
                         @"Library/Application Support/SVPlayer/settings/main.cfg"];
    NSData *data = [NSData dataWithContentsOfFile:cfgPath];
    if (!data) return;
    
    NSMutableDictionary *cfg = [NSJSONSerialization JSONObjectWithData:data 
                                options:NSJSONReadingMutableContainers error:nil];
    if (!cfg) return;
    
    cfg[@"h/pid"] = @"2000000845671234";
    cfg[@"h/last_check"] = @(1893456000);
    
    NSData *newData = [NSJSONSerialization dataWithJSONObject:cfg 
                       options:NSJSONWritingPrettyPrinted error:nil];
    [newData writeToFile:cfgPath atomically:YES];
    [_globalLog appendString:@"[OK] main.cfg patched\n"];
}

static void applyAllHooks(void) {
    // Hook SKPaymentQueue addTransactionObserver:
    Method m1 = class_getInstanceMethod([SKPaymentQueue class], @selector(addTransactionObserver:));
    if (m1) {
        _orig_addTransactionObserver = method_setImplementation(m1, (IMP)hooked_addTransactionObserver);
        [_globalLog appendString:@"[OK] Hooked addTransactionObserver\n"];
    }
    
    // Hook restoreCompletedTransactions
    Method m2 = class_getInstanceMethod([SKPaymentQueue class], @selector(restoreCompletedTransactions));
    if (m2) {
        _orig_restore = method_setImplementation(m2, (IMP)hooked_restore);
        [_globalLog appendString:@"[OK] Hooked restoreCompletedTransactions\n"];
    }
    
    // Hook appStoreReceiptURL
    Method m3 = class_getInstanceMethod([NSBundle class], @selector(appStoreReceiptURL));
    if (m3) {
        _orig_receiptURL = method_setImplementation(m3, (IMP)hooked_receiptURL);
        [_globalLog appendString:@"[OK] Hooked appStoreReceiptURL\n"];
    }
    
    // Hook NSURLSession dataTaskWithRequest:completionHandler:
    Method m4 = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (m4) {
        _orig_dataTaskWithRequest = method_setImplementation(m4, (IMP)hooked_dataTaskWithRequest);
        [_globalLog appendString:@"[OK] Hooked NSURLSession dataTask\n"];
    }
    
    patchMainCfg();
}

__attribute__((constructor))
static void tweak_init(void) {
    _globalLog = [NSMutableString stringWithString:@"=== SVPlayerPatcher v9 ===\n\n"];
    
    // Apply hooks EARLY (before app loads UI)
    applyAllHooks();
    
    // Show log overlay after delay
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [UIPasteboard generalPasteboard].string = _globalLog;
        
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
        t.text = @"v9 StoreKit Hooks - tap Restore in SVPlayer!";
        t.textColor = [UIColor cyanColor];
        t.font = [UIFont boldSystemFontOfSize:14];
        [_overlayWindow.rootViewController.view addSubview:t];
        
        UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(10, 90, b.size.width - 20, b.size.height - 100)];
        tv.text = _globalLog;
        tv.font = [UIFont fontWithName:@"Menlo" size:11];
        tv.textColor = [UIColor greenColor];
        tv.backgroundColor = [UIColor clearColor];
        tv.editable = NO;
        tv.tag = 999;
        [_overlayWindow.rootViewController.view addSubview:tv];
        
        _overlayWindow.hidden = NO;
        [_overlayWindow makeKeyAndVisible];
        
        // Update log view periodically
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UITextView *logView = [_overlayWindow.rootViewController.view viewWithTag:999];
            if (logView) logView.text = _globalLog;
            [UIPasteboard generalPasteboard].string = _globalLog;
        });
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(60.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [UIPasteboard generalPasteboard].string = _globalLog;
            _overlayWindow.hidden = YES;
            _overlayWindow = nil;
        });
    });
}
