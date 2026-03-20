// SVPlayerPatcher v3 - Standalone iOS dylib
// NO CydiaSubstrate dependency

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static UIWindow *_overlayWindow = nil;

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
                [results appendFormat:@"  PROP: %s\n", pn];
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
                    [ls containsString:@"unlock"] || [ls containsString:@"paid"]) {
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

__attribute__((constructor))
static void tweak_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSString *results = scanClasses();
        
        // Auto-copy to clipboard
        [UIPasteboard generalPasteboard].string = results;
        
        // Save to Documents
        NSString *docsPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        [results writeToFile:[docsPath stringByAppendingPathComponent:@"svplayer_classes.txt"]
                  atomically:YES encoding:NSUTF8StringEncoding error:nil];
        
        NSLog(@"[SVPlayerPatcher] Done! Results in clipboard. Found classes:\n%@", results);
        
        // Create overlay window
        UIWindowScene *scene = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {
            scene = s;
            break;
        }
        if (!scene) return;
        
        _overlayWindow = [[UIWindow alloc] initWithWindowScene:scene];
        _overlayWindow.frame = scene.coordinateSpace.bounds;
        _overlayWindow.windowLevel = UIWindowLevelAlert + 100;
        _overlayWindow.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.9];
        _overlayWindow.rootViewController = [[UIViewController alloc] init];
        
        CGRect bounds = _overlayWindow.bounds;
        
        // Title
        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 40, bounds.size.width - 40, 30)];
        title.text = @"SVPlayer Inspector - COPIED TO CLIPBOARD";
        title.textColor = [UIColor cyanColor];
        title.font = [UIFont boldSystemFontOfSize:16];
        [_overlayWindow.rootViewController.view addSubview:title];
        
        // Text view with results
        UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(10, 80, bounds.size.width - 20, bounds.size.height - 140)];
        tv.text = results;
        tv.font = [UIFont fontWithName:@"Menlo" size:11];
        tv.textColor = [UIColor greenColor];
        tv.backgroundColor = [UIColor clearColor];
        tv.editable = NO;
        tv.selectable = YES;
        [_overlayWindow.rootViewController.view addSubview:tv];
        
        // Tap anywhere to close
        UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:title action:nil];
        
        _overlayWindow.hidden = NO;
        [_overlayWindow makeKeyAndVisible];
        
        // Auto-close after 30 seconds
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            _overlayWindow.hidden = YES;
            _overlayWindow = nil;
        });
    });
}
