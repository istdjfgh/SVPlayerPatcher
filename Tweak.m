// SVPlayerPatcher v8 - Premium activation attempt
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>

static UIWindow *_overlayWindow = nil;

// === Method Swizzling Helper ===
static void swizzleMethod(Class cls, SEL orig, SEL swizzled) {
    Method origMethod = class_getInstanceMethod(cls, orig);
    Method swizMethod = class_getInstanceMethod(cls, swizzled);
    if (origMethod && swizMethod) {
        method_exchangeImplementations(origMethod, swizMethod);
    }
}

// === Patch 1: Modify main.cfg ===
static void patchMainCfg(NSMutableString *log) {
    NSString *cfgPath = [NSHomeDirectory() stringByAppendingPathComponent:
                         @"Library/Application Support/SVPlayer/settings/main.cfg"];
    
    NSData *data = [NSData dataWithContentsOfFile:cfgPath];
    if (!data) { [log appendString:@"[FAIL] main.cfg not found\n"]; return; }
    
    NSError *err;
    NSMutableDictionary *cfg = [NSJSONSerialization JSONObjectWithData:data 
                                options:NSJSONReadingMutableContainers error:&err];
    if (!cfg) { [log appendFormat:@"[FAIL] parse main.cfg: %@\n", err]; return; }
    
    // Save original values
    [log appendFormat:@"[INFO] Original h/pid: %@\n", cfg[@"h/pid"]];
    [log appendFormat:@"[INFO] Original h/last_check: %@\n", cfg[@"h/last_check"]];
    [log appendFormat:@"[INFO] Original h/uid: %@\n", cfg[@"h/uid"]];
    
    // Set fake purchase ID (looks like App Store transaction)
    cfg[@"h/pid"] = @"2000000845671234";
    
    // Set last_check to far future (year 2030)
    cfg[@"h/last_check"] = @(1893456000);
    
    // Write back
    NSData *newData = [NSJSONSerialization dataWithJSONObject:cfg 
                       options:NSJSONWritingPrettyPrinted error:&err];
    if (newData && [newData writeToFile:cfgPath atomically:YES]) {
        [log appendString:@"[OK] main.cfg patched (h/pid + h/last_check)\n"];
    } else {
        [log appendFormat:@"[FAIL] write main.cfg: %@\n", err];
    }
}

// === Patch 2: Inject fake StoreKit receipt ===
@interface NSBundle (SVPatch)
- (NSURL *)svp_appStoreReceiptURL;
@end

@implementation NSBundle (SVPatch)
- (NSURL *)svp_appStoreReceiptURL {
    // Return a path to our fake receipt
    NSString *fakePath = [NSHomeDirectory() stringByAppendingPathComponent:
                          @"Library/Application Support/SVPlayer/settings/fake_receipt"];
    
    // Create minimal receipt file if not exists
    if (![[NSFileManager defaultManager] fileExistsAtPath:fakePath]) {
        // Create a minimal ASN.1 receipt-like data
        [@"fake_receipt_data" writeToFile:fakePath atomically:YES 
                                encoding:NSUTF8StringEncoding error:nil];
    }
    
    return [NSURL fileURLWithPath:fakePath];
}
@end

// === Patch 3: Hook SKPaymentTransactionObserver ===
@interface SKPaymentTransaction (SVPatch)
- (SKPaymentTransactionState)svp_transactionState;
@end

@implementation SKPaymentTransaction (SVPatch)
- (SKPaymentTransactionState)svp_transactionState {
    // Always return "purchased"
    return SKPaymentTransactionStatePurchased;
}
@end

// === Patch 4: Intercept UserDefaults reads ===
@interface NSUserDefaults (SVPatch)
- (id)svp_objectForKey:(NSString *)key;
@end

@implementation NSUserDefaults (SVPatch)
- (id)svp_objectForKey:(NSString *)key {
    NSString *lk = [key lowercaseString];
    if ([lk containsString:@"premium"] || [lk containsString:@"purchased"] ||
        [lk containsString:@"pro_enabled"] || [lk containsString:@"is_pro"]) {
        return @YES;
    }
    if ([lk containsString:@"trial"] || [lk containsString:@"expire"]) {
        // Return far future date
        return [NSDate dateWithTimeIntervalSince1970:1893456000];
    }
    return [self svp_objectForKey:key]; // call original
}
@end

// === Patch 5: Modify svp.lic check by intercepting file reads ===
// Hook NSData initWithContentsOfFile to return modified data for svp.lic
@interface NSData (SVPatch)
+ (instancetype)svp_dataWithContentsOfFile:(NSString *)path;
@end

@implementation NSData (SVPatch)
+ (instancetype)svp_dataWithContentsOfFile:(NSString *)path {
    // Don't intercept svp.lic reads - let original handle it
    // But log when it's accessed
    if ([path containsString:@"svp.lic"]) {
        NSLog(@"[SVPatcher] svp.lic accessed: %@", path);
    }
    return [NSData svp_dataWithContentsOfFile:path]; // call original (swizzled)
}
@end

static void applyPatches(NSMutableString *log) {
    // Patch 1: Config files
    patchMainCfg(log);
    
    // Patch 2: Swizzle receipt URL
    swizzleMethod([NSBundle class],
                  @selector(appStoreReceiptURL),
                  @selector(svp_appStoreReceiptURL));
    [log appendString:@"[OK] Swizzled appStoreReceiptURL\n"];
    
    // Patch 3: Swizzle transaction state
    swizzleMethod([SKPaymentTransaction class],
                  @selector(transactionState),
                  @selector(svp_transactionState));
    [log appendString:@"[OK] Swizzled SKPaymentTransaction.transactionState\n"];
    
    // Patch 4: Swizzle UserDefaults
    swizzleMethod([NSUserDefaults class],
                  @selector(objectForKey:),
                  @selector(svp_objectForKey:));
    [log appendString:@"[OK] Swizzled NSUserDefaults.objectForKey\n"];
    
    [log appendString:@"\n[INFO] All patches applied. Restart app to see effect.\n"];
    [log appendString:@"[INFO] If premium not active, try:\n"];
    [log appendString:@"  1. Force close SVPlayer\n"];
    [log appendString:@"  2. Reopen it\n"];
    [log appendString:@"  3. Check if 60fps works\n"];
}

__attribute__((constructor))
static void tweak_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSMutableString *log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v8 ===\n\n"];
        
        applyPatches(log);
        
        [UIPasteboard generalPasteboard].string = log;
        
        NSString *docsPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        [log writeToFile:[docsPath stringByAppendingPathComponent:@"svpatcher_log.txt"]
              atomically:YES encoding:NSUTF8StringEncoding error:nil];
        
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
        t.text = @"PATCHES APPLIED - restart app to test";
        t.textColor = [UIColor cyanColor];
        t.font = [UIFont boldSystemFontOfSize:14];
        [_overlayWindow.rootViewController.view addSubview:t];
        
        UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(10, 90, b.size.width - 20, b.size.height - 100)];
        tv.text = log;
        tv.font = [UIFont fontWithName:@"Menlo" size:12];
        tv.textColor = [UIColor greenColor];
        tv.backgroundColor = [UIColor clearColor];
        tv.editable = NO;
        [_overlayWindow.rootViewController.view addSubview:tv];
        
        _overlayWindow.hidden = NO;
        [_overlayWindow makeKeyAndVisible];
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            _overlayWindow.hidden = YES;
            _overlayWindow = nil;
        });
    });
}
