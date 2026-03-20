// SVPlayerPatcher v16b - Delayed safe memory patch
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>

static NSMutableString *_log = nil;
static void *_backendPtr = NULL;

// === Capture backend pointer only - NO WRITES ===
static IMP _orig_addObserver = NULL;

static void hooked_addObserver(id self, SEL _cmd, id observer) {
    NSString *cn = NSStringFromClass([observer class]);
    if ([cn isEqualToString:@"InAppPurchaseManager"]) {
        Ivar backendIvar = class_getInstanceVariable([observer class], "backend");
        if (backendIvar) {
            ptrdiff_t offset = ivar_getOffset(backendIvar);
            char *base = (char *)(__bridge void *)observer;
            _backendPtr = *(void **)(base + offset);
            [_log appendFormat:@"[OK] backend = %p\n", _backendPtr];
        }
    }
    ((void(*)(id, SEL, id))_orig_addObserver)(self, _cmd, observer);
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
}

// Dump key offsets
static void dumpKey(unsigned char *mem) {
    [_log appendFormat:@"+016: %02X %02X %02X %02X\n", mem[16],mem[17],mem[18],mem[19]];
    [_log appendFormat:@"+144: %02X %02X %02X %02X %02X %02X %02X %02X\n",
     mem[144],mem[145],mem[146],mem[147],mem[148],mem[149],mem[150],mem[151]];
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v16b ===\n\n"];
    
    Method m = class_getInstanceMethod([SKPaymentQueue class], @selector(addTransactionObserver:));
    if (m) _orig_addObserver = method_setImplementation(m, (IMP)hooked_addObserver);
    
    patchConfig();
    
    // DELAYED patch - wait for app to fully load
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (!_backendPtr) {
            [_log appendString:@"[FAIL] No backend\n"];
            [UIPasteboard generalPasteboard].string = _log;
            return;
        }
        
        unsigned char *mem = (unsigned char *)_backendPtr;
        
        [_log appendString:@"=== BEFORE ===\n"];
        dumpKey(mem);
        
        // TRY 1: Only flip +144 and +148 (trial flags)
        // Change from 01 to 02 (not 0 - maybe 0 causes crash, try "purchased" enum = 2)
        mem[144] = 2;
        mem[148] = 2;
        [_log appendString:@"[PATCH] +144=2 +148=2\n"];
        
        [_log appendString:@"=== AFTER ===\n"];
        dumpKey(mem);
        
        [UIPasteboard generalPasteboard].string = _log;
        
        // Brief banner
        UIWindowScene *sc = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) { sc = s; break; }
        if (!sc) return;
        UIWindow *w = [[UIWindow alloc] initWithWindowScene:sc];
        w.frame = CGRectMake(20, 40, 350, 30);
        w.windowLevel = UIWindowLevelAlert + 100;
        w.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.8];
        w.layer.cornerRadius = 8; w.clipsToBounds = YES;
        w.rootViewController = [[UIViewController alloc] init];
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(10, 0, 330, 30)];
        l.text = @"✅ v16b patched - check premium!";
        l.textColor = [UIColor greenColor];
        l.font = [UIFont boldSystemFontOfSize:13];
        [w.rootViewController.view addSubview:l];
        w.hidden = NO;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC), dispatch_get_main_queue(), ^{ w.hidden = YES; });
        
        // Re-patch every 3s
        for (int i = 1; i <= 10; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i*3.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (_backendPtr) {
                    unsigned char *m2 = (unsigned char *)_backendPtr;
                    m2[144] = 2;
                    m2[148] = 2;
                }
                [UIPasteboard generalPasteboard].string = _log;
            });
        }
    });
}
