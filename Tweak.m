// SVPlayerPatcher v16 - Flip premium flags in C++ backend memory
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>

static NSMutableString *_log = nil;
static void *_backendPtr = NULL;

// === Capture backend pointer ===
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
            
            if (_backendPtr) {
                unsigned char *mem = (unsigned char *)_backendPtr;
                
                // === DUMP BEFORE PATCHING ===
                [_log appendString:@"\n=== BEFORE patch ===\n"];
                [_log appendFormat:@"+016: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                 mem[16],mem[17],mem[18],mem[19],mem[20],mem[21],mem[22],mem[23]];
                [_log appendFormat:@"+144: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                 mem[144],mem[145],mem[146],mem[147],mem[148],mem[149],mem[150],mem[151]];
                [_log appendFormat:@"+200: %02X %02X %02X %02X\n",
                 mem[200],mem[201],mem[202],mem[203]];
                [_log appendFormat:@"+208: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                 mem[208],mem[209],mem[210],mem[211],mem[212],mem[213],mem[214],mem[215]];
                
                // === PATCH 1: Set byte +16 to 1 (isPurchased?) ===
                mem[16] = 1;
                [_log appendString:@"[PATCH] +16 = 1\n"];
                
                // === PATCH 2: Set byte +17 to 1 (another bool?) ===
                mem[17] = 1;
                [_log appendString:@"[PATCH] +17 = 1\n"];
                
                // === PATCH 3: Change +144 from 1 to 0 (disable trial?) ===
                mem[144] = 0;
                [_log appendString:@"[PATCH] +144 = 0\n"];
                
                // === PATCH 4: Change +148 from 1 to 0 ===
                mem[148] = 0;
                [_log appendString:@"[PATCH] +148 = 0\n"];
                
                // === DUMP AFTER PATCHING ===
                [_log appendString:@"\n=== AFTER patch ===\n"];
                [_log appendFormat:@"+016: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                 mem[16],mem[17],mem[18],mem[19],mem[20],mem[21],mem[22],mem[23]];
                [_log appendFormat:@"+144: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                 mem[144],mem[145],mem[146],mem[147],mem[148],mem[149],mem[150],mem[151]];
            }
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
    [_log appendString:@"[OK] cfg\n"];
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v16 - MEMORY FLIP ===\n\n"];
    
    Method m = class_getInstanceMethod([SKPaymentQueue class], @selector(addTransactionObserver:));
    if (m) _orig_addObserver = method_setImplementation(m, (IMP)hooked_addObserver);
    [_log appendString:@"[OK] Hook\n"];
    
    patchConfig();
    
    // Show status + re-patch periodically (in case backend resets values)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [UIPasteboard generalPasteboard].string = _log;
        
        // Keep re-patching every 2 seconds for 30 seconds
        for (int i = 0; i < 15; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (_backendPtr) {
                    unsigned char *mem = (unsigned char *)_backendPtr;
                    mem[16] = 1;   // isPurchased?
                    mem[17] = 1;   // bool?
                    mem[144] = 0;  // trial off?
                    mem[148] = 0;  // trial off?
                }
                [UIPasteboard generalPasteboard].string = _log;
            });
        }
        
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
        l.text = @"✅ v16 MEMORY PATCHED - check premium!";
        l.textColor = [UIColor greenColor];
        l.font = [UIFont boldSystemFontOfSize:13];
        [w.rootViewController.view addSubview:l];
        w.hidden = NO;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC), dispatch_get_main_queue(), ^{ w.hidden = YES; });
    });
}
