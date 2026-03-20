// SVPlayerPatcher v15 - Memory scan of C++ backend object
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static UIWindow *_overlayWindow = nil;
static NSMutableString *_log = nil;
static void *_backendPtr = NULL;

// === Capture InAppPurchaseManager and its backend pointer ===
static IMP _orig_addObserver = NULL;

static void hooked_addObserver(id self, SEL _cmd, id observer) {
    NSString *cn = NSStringFromClass([observer class]);
    [_log appendFormat:@"[OBS] %@\n", cn];
    
    if ([cn isEqualToString:@"InAppPurchaseManager"]) {
        // Get `backend` ivar (^v = void pointer)
        Ivar backendIvar = class_getInstanceVariable([observer class], "backend");
        if (backendIvar) {
            ptrdiff_t offset = ivar_getOffset(backendIvar);
            char *base = (char *)(__bridge void *)observer;
            _backendPtr = *(void **)(base + offset);
            [_log appendFormat:@"[OK] backend ptr = %p (offset=%ld)\n", _backendPtr, (long)offset];
            
            // Dump memory at backend pointer (256 bytes)
            if (_backendPtr) {
                [_log appendString:@"\n=== Backend Memory Dump (256 bytes) ===\n"];
                unsigned char *mem = (unsigned char *)_backendPtr;
                for (int row = 0; row < 32; row++) {
                    int off = row * 8;
                    [_log appendFormat:@"+%03d: ", off];
                    
                    // Hex
                    for (int col = 0; col < 8; col++) {
                        [_log appendFormat:@"%02X ", mem[off + col]];
                    }
                    
                    // Values as different types
                    // Check for bool-like values (0 or 1)
                    [_log appendString:@" | "];
                    for (int col = 0; col < 8; col++) {
                        unsigned char b = mem[off + col];
                        if (b == 0) [_log appendString:@"0"];
                        else if (b == 1) [_log appendString:@"1"];
                        else [_log appendString:@"."];
                    }
                    
                    [_log appendString:@"\n"];
                }
                
                // Also dump as int64 values
                [_log appendString:@"\n=== As int64 values ===\n"];
                long long *lmem = (long long *)_backendPtr;
                for (int i = 0; i < 32; i++) {
                    if (lmem[i] != 0) {
                        [_log appendFormat:@"+%d: %lld (0x%llx)\n", i*8, lmem[i], lmem[i]];
                    }
                }
            }
        } else {
            [_log appendString:@"[FAIL] No backend ivar\n"];
        }
        
        // Also get pendingTransactions
        Ivar ptIvar = class_getInstanceVariable([observer class], "pendingTransactions");
        if (ptIvar) {
            id pt = object_getIvar(observer, ptIvar);
            [_log appendFormat:@"[INFO] pendingTransactions = %@\n", pt];
        }
    }
    
    ((void(*)(id, SEL, id))_orig_addObserver)(self, _cmd, observer);
}

// === Minimal tx hooks ===
static IMP _orig_txState = NULL;
static IMP _orig_updated = NULL;

static void hooked_updated(id self, SEL _cmd, id queue, NSArray *txs) {
    for (SKPaymentTransaction *tx in txs) {
        [_log appendFormat:@"[TX] state=%ld prod=%@\n", (long)tx.transactionState, tx.payment.productIdentifier];
    }
    ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
    
    // Re-dump backend memory after transaction processing
    if (_backendPtr) {
        [_log appendString:@"\n=== Backend AFTER tx ===\n"];
        unsigned char *mem = (unsigned char *)_backendPtr;
        for (int row = 0; row < 32; row++) {
            int off = row * 8;
            [_log appendFormat:@"+%03d: ", off];
            for (int col = 0; col < 8; col++) {
                [_log appendFormat:@"%02X ", mem[off + col]];
            }
            [_log appendString:@" | "];
            for (int col = 0; col < 8; col++) {
                unsigned char b = mem[off + col];
                if (b == 0) [_log appendString:@"0"];
                else if (b == 1) [_log appendString:@"1"];
                else [_log appendString:@"."];
            }
            [_log appendString:@"\n"];
        }
    }
    [UIPasteboard generalPasteboard].string = _log;
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
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v15 ===\n\n"];
    Method m;
    
    m = class_getInstanceMethod([SKPaymentQueue class], @selector(addTransactionObserver:));
    if (m) _orig_addObserver = method_setImplementation(m, (IMP)hooked_addObserver);
    [_log appendString:@"[OK] Hooks\n"];
    
    patchConfig();
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (!cls) return;
        
        m = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
        if (m) _orig_updated = method_setImplementation(m, (IMP)hooked_updated);
        m = class_getInstanceMethod(cls, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
        if (m) _orig_restored = method_setImplementation(m, (IMP)hooked_restored);
        [_log appendString:@"[OK] IAP\n"];
        
        [UIPasteboard generalPasteboard].string = _log;
        
        // Show full dump overlay
        UIWindowScene *sc = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) { sc = s; break; }
        if (!sc) return;
        
        _overlayWindow = [[UIWindow alloc] initWithWindowScene:sc];
        _overlayWindow.frame = sc.coordinateSpace.bounds;
        _overlayWindow.windowLevel = UIWindowLevelAlert + 100;
        _overlayWindow.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.92];
        _overlayWindow.rootViewController = [[UIViewController alloc] init];
        CGRect b = _overlayWindow.bounds;
        
        UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, b.size.width - 40, 30)];
        t.text = @"v15 MEMORY DUMP - copy log from clipboard";
        t.textColor = [UIColor cyanColor];
        t.font = [UIFont boldSystemFontOfSize:13];
        [_overlayWindow.rootViewController.view addSubview:t];
        
        UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(10, 85, b.size.width - 20, b.size.height - 95)];
        tv.text = _log;
        tv.font = [UIFont fontWithName:@"Menlo" size:9];
        tv.textColor = [UIColor greenColor];
        tv.backgroundColor = [UIColor clearColor];
        tv.editable = NO;
        tv.tag = 999;
        [_overlayWindow.rootViewController.view addSubview:tv];
        
        _overlayWindow.hidden = NO;
        [_overlayWindow makeKeyAndVisible];
        
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
