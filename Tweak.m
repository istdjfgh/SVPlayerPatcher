// SVPlayerPatcher v13 - Full intercept: receipt reading + config write tracking  
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSMutableString *_log = nil;
static BOOL _fakeState = NO;

// === Fake transactionState ===
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

// === Hook updatedTransactions ===
static IMP _orig_updated = NULL;
static void hooked_updated(id self, SEL _cmd, id queue, NSArray *txs) {
    for (SKPaymentTransaction *tx in txs) {
        NSInteger realState = ((NSInteger(*)(id, SEL))_orig_txState)(tx, @selector(transactionState));
        [_log appendFormat:@"[TX] real=%ld prod=%@\n", (long)realState, tx.payment.productIdentifier];
    }
    _fakeState = YES;
    ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
    _fakeState = NO;
    [UIPasteboard generalPasteboard].string = _log;
}

// === Hook NSData initWithContentsOfURL: to catch receipt reads ===
static IMP _orig_dataURL = NULL;
static id hooked_dataURL(id self, SEL _cmd, NSURL *url) {
    NSString *path = url.path;
    if ([path containsString:@"Receipt"] || [path containsString:@"receipt"] ||
        [path containsString:@"StoreKit"] || [path containsString:@"svp"]) {
        [_log appendFormat:@"[READ-URL] %@\n", path];
    }
    return ((id(*)(id, SEL, NSURL*))_orig_dataURL)(self, _cmd, url);
}

// === Hook NSData initWithContentsOfFile: ===
static IMP _orig_dataFile = NULL;
static id hooked_dataFile(id self, SEL _cmd, NSString *path) {
    if ([path containsString:@"Receipt"] || [path containsString:@"receipt"] ||
        [path containsString:@"StoreKit"] || [path containsString:@"svp"] ||
        [path containsString:@"SVPlayer"] || [path containsString:@".lic"] ||
        [path containsString:@".cfg"]) {
        [_log appendFormat:@"[READ-FILE] %@\n", path];
    }
    return ((id(*)(id, SEL, NSString*))_orig_dataFile)(self, _cmd, path);
}

// === Hook NSData dataWithContentsOfFile: (class method) ===
static IMP _orig_classDataFile = NULL;
static id hooked_classDataFile(id self, SEL _cmd, NSString *path) {
    if ([path containsString:@"Receipt"] || [path containsString:@"receipt"] ||
        [path containsString:@"StoreKit"] || [path containsString:@"svp"] ||
        [path containsString:@"SVPlayer"] || [path containsString:@".lic"] ||
        [path containsString:@".cfg"]) {
        [_log appendFormat:@"[DATA-FILE] %@\n", path];
    }
    return ((id(*)(id, SEL, NSString*))_orig_classDataFile)(self, _cmd, path);
}

// === Hook NSUserDefaults setBool:forKey: - track what backend writes ===
static IMP _orig_setBool = NULL;
static void hooked_setBool(id self, SEL _cmd, BOOL value, NSString *key) {
    [_log appendFormat:@"[SET-BOOL] %@ = %@\n", key, value ? @"YES" : @"NO"];
    ((void(*)(id, SEL, BOOL, NSString*))_orig_setBool)(self, _cmd, value, key);
}

// === Hook NSUserDefaults setObject:forKey: ===
static IMP _orig_setObj = NULL;
static void hooked_setObj(id self, SEL _cmd, id value, NSString *key) {
    NSString *desc = [value description];
    if (desc.length > 80) desc = [[desc substringToIndex:80] stringByAppendingString:@"..."];
    [_log appendFormat:@"[SET-OBJ] %@ = %@\n", key, desc];
    ((void(*)(id, SEL, id, NSString*))_orig_setObj)(self, _cmd, value, key);
}

// === Hook NSFileManager fileExistsAtPath: ===
static IMP _orig_exists = NULL;
static BOOL hooked_exists(id self, SEL _cmd, NSString *path) {
    BOOL result = ((BOOL(*)(id, SEL, NSString*))_orig_exists)(self, _cmd, path);
    if ([path containsString:@"svp"] || [path containsString:@"SVPlayer"] || 
        [path containsString:@".lic"] || [path containsString:@"receipt"] ||
        [path containsString:@"Receipt"]) {
        [_log appendFormat:@"[EXISTS] %@ -> %@\n", [path lastPathComponent], result ? @"YES" : @"NO"];
    }
    return result;
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
    c[@"h/pid"] = @"unlock0";  // Real product ID!
    c[@"h/last_check"] = @(1893456000);
    NSData *n = [NSJSONSerialization dataWithJSONObject:c options:NSJSONWritingPrettyPrinted error:nil];
    [n writeToFile:p atomically:YES];
    [_log appendString:@"[OK] cfg: h/pid=unlock0\n"];
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v13 ===\n\n"];
    Method m;
    
    // StoreKit hooks
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
    
    // File reading hooks (to see what backend reads during validation)
    m = class_getInstanceMethod([NSData class], @selector(initWithContentsOfURL:));
    if (m) _orig_dataURL = method_setImplementation(m, (IMP)hooked_dataURL);
    m = class_getInstanceMethod([NSData class], @selector(initWithContentsOfFile:));
    if (m) _orig_dataFile = method_setImplementation(m, (IMP)hooked_dataFile);
    Method cm = class_getClassMethod([NSData class], @selector(dataWithContentsOfFile:));
    if (cm) _orig_classDataFile = method_setImplementation(cm, (IMP)hooked_classDataFile);
    [_log appendString:@"[OK] File hooks\n"];
    
    // NSUserDefaults write hooks
    m = class_getInstanceMethod([NSUserDefaults class], @selector(setBool:forKey:));
    if (m) _orig_setBool = method_setImplementation(m, (IMP)hooked_setBool);
    m = class_getInstanceMethod([NSUserDefaults class], @selector(setObject:forKey:));
    if (m) _orig_setObj = method_setImplementation(m, (IMP)hooked_setObj);
    [_log appendString:@"[OK] Defaults hooks\n"];
    
    // FileManager hooks
    m = class_getInstanceMethod([NSFileManager class], @selector(fileExistsAtPath:));
    if (m) _orig_exists = method_setImplementation(m, (IMP)hooked_exists);
    [_log appendString:@"[OK] FM hooks\n"];
    
    patchConfig();
    
    // Hook IAP (delayed)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (!cls) return;
        Method m2 = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
        if (m2) _orig_updated = method_setImplementation(m2, (IMP)hooked_updated);
        Method m4 = class_getInstanceMethod(cls, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
        if (m4) _orig_restored = method_setImplementation(m4, (IMP)hooked_restored);
        [_log appendString:@"[OK] IAP hooks\n"];
        [UIPasteboard generalPasteboard].string = _log;
        
        // Mini banner
        UIWindowScene *sc = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) { sc = s; break; }
        if (!sc) return;
        UIWindow *w = [[UIWindow alloc] initWithWindowScene:sc];
        w.frame = CGRectMake(20, 40, 300, 30);
        w.windowLevel = UIWindowLevelAlert + 100;
        w.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.8];
        w.layer.cornerRadius = 8; w.clipsToBounds = YES;
        w.rootViewController = [[UIViewController alloc] init];
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(10, 0, 280, 30)];
        l.text = @"✅ v13 - tap Restore!";
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
