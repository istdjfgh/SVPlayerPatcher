// SVPlayerPatcher v6 - Smart auto-search
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static UIWindow *_overlayWindow = nil;

static NSString* scanClasses(void) {
    int numClasses = objc_getClassList(NULL, 0);
    Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * numClasses);
    objc_getClassList(classes, numClasses);
    
    // Step 1: Find the app's Swift module name
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    NSString *execName = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    
    NSMutableString *results = [NSMutableString string];
    [results appendFormat:@"=== SVPlayer Smart Scan ===\n"];
    [results appendFormat:@"Bundle: %@\n", bundleID];
    [results appendFormat:@"Executable: %@\n\n", execName];
    
    // Step 2: Collect all unique module names (Swift classes have dots)
    NSMutableDictionary *moduleCount = [NSMutableDictionary dictionary];
    NSMutableArray *appClasses = [NSMutableArray array];
    
    for (int i = 0; i < numClasses; i++) {
        const char *name = class_getName(classes[i]);
        if (!name) continue;
        NSString *cn = [NSString stringWithUTF8String:name];
        
        // Swift classes: ModuleName.ClassName
        NSRange dotRange = [cn rangeOfString:@"."];
        if (dotRange.location != NSNotFound) {
            NSString *module = [cn substringToIndex:dotRange.location];
            NSNumber *count = moduleCount[module] ?: @0;
            moduleCount[module] = @(count.intValue + 1);
        }
    }
    
    // Step 3: Find the app's module (non-Apple module with most classes)
    [results appendString:@"--- Swift Modules ---\n"];
    NSArray *sortedModules = [moduleCount keysSortedByValueUsingComparator:^(id a, id b) {
        return [b compare:a];
    }];
    
    // Known Apple modules to skip
    NSSet *appleModules = [NSSet setWithArray:@[
        @"SwiftUI", @"Swift", @"UIKit", @"Foundation", @"CoreData",
        @"Combine", @"MapKit", @"Photos", @"AVFoundation", @"WebKit",
        @"StoreKit", @"CloudKit", @"CoreLocation", @"Metal",
        @"RealityKit", @"ARKit", @"SpriteKit", @"SceneKit",
        @"NewsCore", @"_TtC", @"CoreMotion", @"HealthKit"
    ]];
    
    NSString *appModule = nil;
    for (NSString *module in sortedModules) {
        int count = [moduleCount[module] intValue];
        BOOL isApple = [appleModules containsObject:module] || 
                       [module hasPrefix:@"_"] || [module hasPrefix:@"__"];
        if (!isApple && count >= 3) {
            [results appendFormat:@"%@ %@: %d classes\n", 
             (appModule == nil ? @">>>" : @"   "), module, count];
            if (appModule == nil) appModule = module;
        }
    }
    
    [results appendFormat:@"\nApp module detected: %@\n\n", appModule ?: @"NONE"];
    
    // Step 4: Dump ALL classes from the app module
    if (appModule) {
        [results appendFormat:@"--- All %@ classes ---\n\n", appModule];
        NSString *prefix = [appModule stringByAppendingString:@"."];
        
        for (int i = 0; i < numClasses; i++) {
            const char *name = class_getName(classes[i]);
            if (!name) continue;
            NSString *cn = [NSString stringWithUTF8String:name];
            
            if (![cn hasPrefix:prefix]) continue;
            
            NSString *shortName = [cn substringFromIndex:prefix.length];
            [results appendFormat:@"\nCLASS: %@\n", shortName];
            
            // Properties
            unsigned int propCount = 0;
            objc_property_t *props = class_copyPropertyList(classes[i], &propCount);
            for (unsigned int j = 0; j < propCount; j++) {
                [results appendFormat:@"  P: %s\n", property_getName(props[j])];
            }
            if (props) free(props);
            
            // Key methods only
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(classes[i], &mc);
            for (unsigned int j = 0; j < mc; j++) {
                SEL sel = method_getName(methods[j]);
                NSString *sn = NSStringFromSelector(sel);
                NSString *ls = [sn lowercaseString];
                if ([ls hasPrefix:@"is"] || [ls hasPrefix:@"has"] || [ls hasPrefix:@"set"] ||
                    [ls containsString:@"init"] || [ls containsString:@"premium"] ||
                    [ls containsString:@"purchase"] || [ls containsString:@"subscri"] ||
                    [ls containsString:@"unlock"] || [ls containsString:@"license"] ||
                    [ls containsString:@"paid"] || [ls containsString:@"pro"] ||
                    [ls containsString:@"enable"] || [ls containsString:@"active"] ||
                    [ls containsString:@"valid"] || [ls containsString:@"expire"] ||
                    [ls containsString:@"interpolat"] || [ls containsString:@"fps"] ||
                    [ls containsString:@"frame"] || [ls containsString:@"smooth"] ||
                    [ls containsString:@"frc"] || [ls containsString:@"motion"]) {
                    [results appendFormat:@"  M: %@\n", sn];
                }
            }
            if (methods) free(methods);
        }
    }

    // Step 5: Also scan for non-Swift (ObjC) classes from app bundle
    [results appendString:@"\n\n--- Non-Swift app classes ---\n"];
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    for (int i = 0; i < numClasses; i++) {
        const char *name = class_getName(classes[i]);
        if (!name) continue;
        NSString *cn = [NSString stringWithUTF8String:name];
        
        // Skip if it has a dot (already covered above) or starts with underscore
        if ([cn containsString:@"."] || [cn hasPrefix:@"_"]) continue;
        if (cn.length < 4) continue;
        
        // Check if the class binary lives in the app bundle
        NSBundle *classBundle = [NSBundle bundleForClass:classes[i]];
        if (classBundle && [[classBundle bundlePath] hasPrefix:bundlePath]) {
            [results appendFormat:@"\nCLASS: %@\n", cn];
            unsigned int propCount = 0;
            objc_property_t *props = class_copyPropertyList(classes[i], &propCount);
            for (unsigned int j = 0; j < propCount; j++) {
                [results appendFormat:@"  P: %s\n", property_getName(props[j])];
            }
            if (props) free(props);
        }
    }
    
    free(classes);
    return results;
}

__attribute__((constructor))
static void tweak_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSString *results = scanClasses();
        [UIPasteboard generalPasteboard].string = results;
        
        NSString *docsPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        [results writeToFile:[docsPath stringByAppendingPathComponent:@"svplayer_classes.txt"]
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
        t.text = @"SMART SCAN DONE - COPIED TO CLIPBOARD - 60s";
        t.textColor = [UIColor cyanColor];
        t.font = [UIFont boldSystemFontOfSize:14];
        [_overlayWindow.rootViewController.view addSubview:t];
        
        UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(10, 90, b.size.width - 20, b.size.height - 100)];
        tv.text = results;
        tv.font = [UIFont fontWithName:@"Menlo" size:10];
        tv.textColor = [UIColor greenColor];
        tv.backgroundColor = [UIColor clearColor];
        tv.editable = NO;
        tv.selectable = YES;
        [_overlayWindow.rootViewController.view addSubview:tv];
        
        _overlayWindow.hidden = NO;
        [_overlayWindow makeKeyAndVisible];
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(60.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            _overlayWindow.hidden = YES;
            _overlayWindow = nil;
        });
    });
}
