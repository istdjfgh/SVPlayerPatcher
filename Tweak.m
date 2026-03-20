// SVPlayerPatcher v2 - Standalone iOS dylib
// NO CydiaSubstrate dependency

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static NSString* scanClasses(void) {
    int numClasses = objc_getClassList(NULL, 0);
    Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * numClasses);
    objc_getClassList(classes, numClasses);
    
    NSMutableString *results = [NSMutableString stringWithString:@"=== SVPlayer Inspector ===\n\n"];
    
    NSArray *keywords = @[
        @"premium", @"pro", @"subscribe", @"subscription",
        @"purchase", @"vip", @"license", @"paid", @"iap",
        @"store", @"product", @"receipt", @"billing",
        @"unlock", @"feature", @"trial", @"plan"
    ];
    
    int found = 0;
    
    for (int i = 0; i < numClasses; i++) {
        const char *name = class_getName(classes[i]);
        if (!name) continue;
        NSString *className = [NSString stringWithUTF8String:name];
        NSString *lowerName = [className lowercaseString];
        
        BOOL match = NO;
        for (NSString *keyword in keywords) {
            if ([lowerName containsString:keyword]) { match = YES; break; }
        }
        
        if (match) {
            found++;
            [results appendFormat:@"CLASS: %@\n", className];
            
            unsigned int propCount = 0;
            objc_property_t *props = class_copyPropertyList(classes[i], &propCount);
            for (unsigned int j = 0; j < propCount; j++) {
                const char *pn = property_getName(props[j]);
                const char *pa = property_getAttributes(props[j]);
                [results appendFormat:@"  PROP: %s (%s)\n", pn, pa];
            }
            if (props) free(props);
            
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(classes[i], &methodCount);
            for (unsigned int j = 0; j < methodCount; j++) {
                SEL sel = method_getName(methods[j]);
                NSString *selName = NSStringFromSelector(sel);
                NSString *ls = [selName lowercaseString];
                if ([ls hasPrefix:@"is"] || [ls hasPrefix:@"has"] || [ls hasPrefix:@"set"] ||
                    [ls containsString:@"premium"] || [ls containsString:@"pro"] ||
                    [ls containsString:@"purchase"] || [ls containsString:@"subscri"] ||
                    [ls containsString:@"unlock"] || [ls containsString:@"paid"] ||
                    [ls containsString:@"vip"] || [ls containsString:@"license"] ||
                    [ls containsString:@"trial"] || [ls containsString:@"feature"]) {
                    [results appendFormat:@"  METHOD: %@\n", selName];
                }
            }
            if (methods) free(methods);
            [results appendString:@"\n"];
        }
    }
    
    free(classes);
    [results appendFormat:@"\n=== Found %d classes ===\n", found];
    return results;
}

static void showOverlay(NSString *text) {
    // Create our own window on top of everything
    UIWindowScene *activeScene = nil;
    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            activeScene = scene;
            break;
        }
    }
    if (!activeScene) {
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            activeScene = scene;
            break;
        }
    }
    if (!activeScene) return;
    
    UIWindow *overlayWindow = [[UIWindow alloc] initWithWindowScene:activeScene];
    overlayWindow.frame = activeScene.coordinateSpace.bounds;
    overlayWindow.windowLevel = UIWindowLevelAlert + 100;
    overlayWindow.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.85];
    
    // Scrollable text view
    UITextView *textView = [[UITextView alloc] initWithFrame:CGRectInset(overlayWindow.bounds, 20, 80)];
    textView.text = text;
    textView.font = [UIFont fontWithName:@"Menlo" size:11];
    textView.textColor = [UIColor greenColor];
    textView.backgroundColor = [UIColor clearColor];
    textView.editable = NO;
    textView.selectable = YES;
    [overlayWindow addSubview:textView];
    
    // Copy button
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(20, overlayWindow.bounds.size.height - 70, 150, 50);
    [copyBtn setTitle:@"COPY ALL" forState:UIControlStateNormal];
    [copyBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    copyBtn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    copyBtn.backgroundColor = [UIColor systemBlueColor];
    copyBtn.layer.cornerRadius = 12;
    copyBtn.tag = 1001;
    [overlayWindow addSubview:copyBtn];
    
    // Close button
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(overlayWindow.bounds.size.width - 170, overlayWindow.bounds.size.height - 70, 150, 50);
    [closeBtn setTitle:@"CLOSE" forState:UIControlStateNormal];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    closeBtn.backgroundColor = [UIColor systemRedColor];
    closeBtn.layer.cornerRadius = 12;
    closeBtn.tag = 1002;
    [overlayWindow addSubview:closeBtn];
    
    // Store text and window in associated objects
    objc_setAssociatedObject(copyBtn, "text", text, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(copyBtn, "window", overlayWindow, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(closeBtn, "window", overlayWindow, OBJC_ASSOCIATION_RETAIN);
    
    // Add actions using target-action with a helper class
    [copyBtn addTarget:[NSClassFromString(@"SVPatcherHelper") class] action:@selector(copyTapped:) forControlEvents:UIControlEventTouchUpInside];
    [closeBtn addTarget:[NSClassFromString(@"SVPatcherHelper") class] action:@selector(closeTapped:) forControlEvents:UIControlEventTouchUpInside];
    
    overlayWindow.hidden = NO;
    [overlayWindow makeKeyAndVisible];
}

// Helper class for button actions
@interface SVPatcherHelper : NSObject
+ (void)copyTapped:(UIButton *)sender;
+ (void)closeTapped:(UIButton *)sender;
@end

@implementation SVPatcherHelper
+ (void)copyTapped:(UIButton *)sender {
    NSString *text = objc_getAssociatedObject(sender, "text");
    if (text) {
        [UIPasteboard generalPasteboard].string = text;
        [sender setTitle:@"COPIED!" forState:UIControlStateNormal];
    }
}
+ (void)closeTapped:(UIButton *)sender {
    UIWindow *w = objc_getAssociatedObject(sender, "window");
    w.hidden = YES;
}
@end

__attribute__((constructor))
static void tweak_init(void) {
    // Wait 5 seconds for app to fully load
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSString *results = scanClasses();
        
        // Auto-copy to clipboard
        [UIPasteboard generalPasteboard].string = results;
        
        // Save to file
        NSString *docsPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *filePath = [docsPath stringByAppendingPathComponent:@"svplayer_classes.txt"];
        [results writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        
        // Show custom overlay (not UIAlertController)
        showOverlay(results);
        
        NSLog(@"[SVPlayerPatcher] Results copied to clipboard and saved to %@", filePath);
    });
}
