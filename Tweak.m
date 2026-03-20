// SVPlayerPatcher v8b - Premium activation (fixed compilation)
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static UIWindow *_overlayWindow = nil;

// === Patch main.cfg ===
static void patchMainCfg(NSMutableString *log) {
    NSString *cfgPath = [NSHomeDirectory() stringByAppendingPathComponent:
                         @"Library/Application Support/SVPlayer/settings/main.cfg"];
    
    NSData *data = [NSData dataWithContentsOfFile:cfgPath];
    if (!data) { [log appendString:@"[FAIL] main.cfg not found\n"]; return; }
    
    NSError *err;
    NSMutableDictionary *cfg = [NSJSONSerialization JSONObjectWithData:data 
                                options:NSJSONReadingMutableContainers error:&err];
    if (!cfg) { [log appendFormat:@"[FAIL] parse: %@\n", err]; return; }
    
    [log appendFormat:@"[OLD] h/pid = %@\n", cfg[@"h/pid"]];
    [log appendFormat:@"[OLD] h/last_check = %@\n", cfg[@"h/last_check"]];
    
    // Patch values
    cfg[@"h/pid"] = @"2000000845671234";
    cfg[@"h/last_check"] = @(1893456000); // year 2030
    
    NSData *newData = [NSJSONSerialization dataWithJSONObject:cfg 
                       options:NSJSONWritingPrettyPrinted error:&err];
    if (newData && [newData writeToFile:cfgPath atomically:YES]) {
        [log appendString:@"[OK] main.cfg patched\n"];
    } else {
        [log appendFormat:@"[FAIL] write: %@\n", err];
    }
}

// === Patch svp.lic - try deleting it to trigger re-validation ===
static void patchLicense(NSMutableString *log) {
    NSString *licPath = [NSHomeDirectory() stringByAppendingPathComponent:
                         @"Library/Application Support/SVPlayer/settings/svp.lic"];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:licPath]) {
        // Read current license
        NSString *lic = [NSString stringWithContentsOfFile:licPath 
                         encoding:NSUTF8StringEncoding error:nil];
        [log appendFormat:@"[INFO] Current svp.lic: %@\n", 
         [lic substringToIndex:MIN(50, lic.length)]];
    }
}

// === Hook NSUserDefaults to intercept premium checks ===
static IMP _orig_objectForKey = NULL;

static id hooked_objectForKey(id self, SEL _cmd, NSString *key) {
    // Call original
    id result = ((id(*)(id, SEL, NSString*))_orig_objectForKey)(self, _cmd, key);
    
    // Intercept premium-related keys
    if (key && [key isKindOfClass:[NSString class]]) {
        NSString *lk = [key lowercaseString];
        if ([lk containsString:@"premium"] || [lk containsString:@"purchased"] ||
            [lk containsString:@"is_pro"] || [lk containsString:@"pro_enabled"]) {
            NSLog(@"[SVPatcher] Intercepted key: %@ (was: %@) -> YES", key, result);
            return @YES;
        }
    }
    return result;
}

// === Hook NSUserDefaults boolForKey ===
static IMP _orig_boolForKey = NULL;

static BOOL hooked_boolForKey(id self, SEL _cmd, NSString *key) {
    BOOL result = ((BOOL(*)(id, SEL, NSString*))_orig_boolForKey)(self, _cmd, key);
    
    if (key && [key isKindOfClass:[NSString class]]) {
        NSString *lk = [key lowercaseString];
        if ([lk containsString:@"premium"] || [lk containsString:@"purchased"] ||
            [lk containsString:@"is_pro"] || [lk containsString:@"pro_enabled"] ||
            [lk containsString:@"unlocked"]) {
            NSLog(@"[SVPatcher] Intercepted boolForKey: %@ -> YES", key);
            return YES;
        }
    }
    return result;
}

static void applyHooks(NSMutableString *log) {
    // Hook objectForKey:
    Method m1 = class_getInstanceMethod([NSUserDefaults class], @selector(objectForKey:));
    if (m1) {
        _orig_objectForKey = method_setImplementation(m1, (IMP)hooked_objectForKey);
        [log appendString:@"[OK] Hooked NSUserDefaults.objectForKey\n"];
    }
    
    // Hook boolForKey:
    Method m2 = class_getInstanceMethod([NSUserDefaults class], @selector(boolForKey:));
    if (m2) {
        _orig_boolForKey = method_setImplementation(m2, (IMP)hooked_boolForKey);
        [log appendString:@"[OK] Hooked NSUserDefaults.boolForKey\n"];
    }
}

// === Read and patch QML config ===
static void checkQMLConfig(NSMutableString *log) {
    // Check if there are any QSettings files
    NSString *settingsDir = [NSHomeDirectory() stringByAppendingPathComponent:
                             @"Library/Application Support/SVPlayer/settings"];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *files = [fm contentsOfDirectoryAtPath:settingsDir error:nil];
    
    [log appendString:@"\n[INFO] Settings files:\n"];
    for (NSString *f in files) {
        NSString *full = [settingsDir stringByAppendingPathComponent:f];
        NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
        [log appendFormat:@"  %@ (%llu bytes)\n", f, [attrs fileSize]];
    }
    
    // After patching main.cfg, also check if we need to modify profiles
    // to enable FRC regardless of license
    NSString *profilesPath = [settingsDir stringByAppendingPathComponent:@"profiles.cfg"];
    NSData *pdata = [NSData dataWithContentsOfFile:profilesPath];
    if (pdata) {
        NSMutableDictionary *profiles = [NSJSONSerialization JSONObjectWithData:pdata
                                         options:NSJSONReadingMutableContainers error:nil];
        if (profiles) {
            // Ensure the default profile has FRC enabled
            for (NSString *key in profiles.allKeys) {
                if ([key hasSuffix:@"/on"]) {
                    profiles[key] = @YES;
                    [log appendFormat:@"[OK] Enabled profile: %@\n", key];
                }
                if ([key hasSuffix:@"/enable"]) {
                    profiles[key] = @YES;
                }
            }
            NSData *newPdata = [NSJSONSerialization dataWithJSONObject:profiles 
                                options:NSJSONWritingPrettyPrinted error:nil];
            [newPdata writeToFile:profilesPath atomically:YES];
            [log appendString:@"[OK] profiles.cfg patched\n"];
        }
    }
}

__attribute__((constructor))
static void tweak_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSMutableString *log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v8 ===\n\n"];
        
        patchMainCfg(log);
        patchLicense(log);
        applyHooks(log);
        checkQMLConfig(log);
        
        [log appendString:@"\n[DONE] Close and reopen SVPlayer to test!\n"];
        
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
        t.text = @"v8 PATCHES APPLIED - close & reopen app";
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
