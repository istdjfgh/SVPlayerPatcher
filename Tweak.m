// SVPlayerPatcher - Standalone iOS dylib
// NO CydiaSubstrate dependency
// Uses pure Objective-C runtime for class inspection

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// Auto-execute when dylib is loaded
__attribute__((constructor))
static void tweak_init(void) {
    // Delay 3 seconds until app is fully loaded
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        int numClasses = objc_getClassList(NULL, 0);
        Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * numClasses);
        objc_getClassList(classes, numClasses);
        
        NSMutableString *results = [NSMutableString stringWithString:@"=== SVPlayer Class Inspector ===\n\n"];
        
        NSArray *keywords = @[
            @"premium", @"pro", @"subscribe", @"subscription",
            @"purchase", @"vip", @"license", @"paid", @"iap",
            @"store", @"product", @"receipt", @"billing",
            @"unlock", @"feature", @"trial", @"plan"
        ];
        
        int found = 0;
        
        for (int i = 0; i < numClasses; i++) {
            NSString *className = [NSString stringWithUTF8String:class_getName(classes[i])];
            NSString *lowerName = [className lowercaseString];
            
            BOOL match = NO;
            for (NSString *keyword in keywords) {
                if ([lowerName containsString:keyword]) {
                    match = YES;
                    break;
                }
            }
            
            if (match) {
                found++;
                [results appendFormat:@"CLASS: %@\n", className];
                
                // List properties
                unsigned int propCount = 0;
                objc_property_t *props = class_copyPropertyList(classes[i], &propCount);
                for (unsigned int j = 0; j < propCount; j++) {
                    const char *propName = property_getName(props[j]);
                    const char *propAttr = property_getAttributes(props[j]);
                    [results appendFormat:@"  PROP: %s (%s)\n", propName, propAttr];
                }
                if (props) free(props);
                
                // List methods (only relevant ones)
                unsigned int methodCount = 0;
                Method *methods = class_copyMethodList(classes[i], &methodCount);
                for (unsigned int j = 0; j < methodCount; j++) {
                    SEL sel = method_getName(methods[j]);
                    NSString *selName = NSStringFromSelector(sel);
                    NSString *lowerSel = [selName lowercaseString];
                    
                    BOOL relevant = NO;
                    for (NSString *keyword in keywords) {
                        if ([lowerSel containsString:keyword]) { relevant = YES; break; }
                    }
                    if (relevant || [lowerSel hasPrefix:@"is"] || [lowerSel hasPrefix:@"has"] || [lowerSel hasPrefix:@"set"]) {
                        [results appendFormat:@"  METHOD: %@\n", selName];
                    }
                }
                if (methods) free(methods);
                
                [results appendString:@"\n"];
            }
        }
        
        free(classes);
        [results appendFormat:@"\n=== Found %d matching classes ===\n", found];
        
        // Save to Documents folder
        NSString *docsPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *filePath = [docsPath stringByAppendingPathComponent:@"svplayer_classes.txt"];
        [results writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        
        // Show alert with results
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"SVPlayer Inspector"
                                                                      message:results
                                                               preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Copy" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            [UIPasteboard generalPasteboard].string = results;
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
        
        UIWindow *window = nil;
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in scene.windows) {
                    if (w.isKeyWindow) { window = w; break; }
                }
            }
        }
        
        UIViewController *topVC = window.rootViewController;
        while (topVC.presentedViewController) {
            topVC = topVC.presentedViewController;
        }
        
        [topVC presentViewController:alert animated:YES completion:nil];
    });
}
