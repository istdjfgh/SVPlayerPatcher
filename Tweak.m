// SVPlayerPatcher v5 - Target search for SVPlayer classes
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static UIWindow *_overlayWindow = nil;

static NSString* scanClasses(void) {
    int numClasses = objc_getClassList(NULL, 0);
    Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * numClasses);
    objc_getClassList(classes, numClasses);
    
    NSMutableString *results = [NSMutableString stringWithString:@"=== SVPlayer Target Scan ===\n\n"];
    
    // SVPlayer-specific prefixes and keywords
    NSArray *targetPrefixes = @[
        @"SV", @"SVP", @"Player", @"Video", @"Smooth",
        @"Motion", @"Frame", @"Interp", @"MEMC", @"Render",
        @"Decode", @"Stream", @"Codec", @"FFmpeg", @"mpv",
        @"MPV", @"Metal", @"OpenGL", @"Vulkan"
    ];
    
    NSArray *targetContains = @[
        @"premium", @"subscribe", @"purchase", @"license",
        @"paid", @"trial", @"unlock", @"iap", @"billing",
        @"pro", @"vip", @"setting", @"config", @"prefer",
        @"interpolat", @"memc", @"framerate", @"fps",
        @"smooth", @"motion", @"compensation"
    ];
    
    int found = 0;
    
    for (int i = 0; i < numClasses; i++) {
        const char *name = class_getName(classes[i]);
        if (!name) continue;
        NSString *className = [NSString stringWithUTF8String:name];
        NSString *lowerName = [className lowercaseString];
        
        // Skip obvious Apple/system classes
        if ([className hasPrefix:@"_"] || [className hasPrefix:@"__"]) continue;
        if (className.length < 3) continue;
        
        BOOL match = NO;
        
        // Check prefixes
        for (NSString *prefix in targetPrefixes) {
            if ([className hasPrefix:prefix]) { match = YES; break; }
        }
        
        // Check contains (case insensitive)
        if (!match) {
            for (NSString *keyword in targetContains) {
                if ([lowerName containsString:keyword]) { match = YES; break; }
            }
        }
        
        if (match) {
            found++;
            [results appendFormat:@"\nCLASS: %@\n", className];
            
            // ALL properties
            unsigned int propCount = 0;
            objc_property_t *props = class_copyPropertyList(classes[i], &propCount);
            for (unsigned int j = 0; j < propCount; j++) {
                [results appendFormat:@"  P: %s\n", property_getName(props[j])];
            }
            if (props) free(props);
            
            // ALL methods (not just filtered)
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(classes[i], &methodCount);
            if (methodCount <= 50) { // Only dump if not too many
                for (unsigned int j = 0; j < methodCount; j++) {
                    SEL sel = method_getName(methods[j]);
                    [results appendFormat:@"  M: %@\n", NSStringFromSelector(sel)];
                }
            } else {
                [results appendFormat:@"  (%d methods - showing key ones)\n", methodCount];
                for (unsigned int j = 0; j < methodCount; j++) {
                    SEL sel = method_getName(methods[j]);
                    NSString *sn = NSStringFromSelector(sel);
                    NSString *ls = [sn lowercaseString];
                    if ([ls hasPrefix:@"is"] || [ls hasPrefix:@"has"] || [ls hasPrefix:@"set"] ||
                        [ls containsString:@"init"] || [ls containsString:@"premium"] ||
                        [ls containsString:@"enable"] || [ls containsString:@"active"] ||
                        [ls containsString:@"purchase"] || [ls containsString:@"subscri"] ||
                        [ls containsString:@"unlock"] || [ls containsString:@"license"] ||
                        [ls containsString:@"paid"] || [ls containsString:@"pro"] ||
                        [ls containsString:@"valid"] || [ls containsString:@"expire"] ||
                        [ls containsString:@"interpolat"] || [ls containsString:@"fps"] ||
                        [ls containsString:@"frame"] || [ls containsString:@"smooth"] ||
                        [ls containsString:@"motion"] || [ls containsString:@"memc"]) {
                        [results appendFormat:@"  M: %@\n", sn];
                    }
                }
            }
        }
    }
    
    free(classes);
    [results appendFormat:@"\n\n=== Found %d target classes ===\n", found];
    return results;
}

__attribute__((constructor))
static void tweak_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
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
        
        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, b.size.width - 40, 30)];
        title.text = @"SVPlayer Classes - COPIED TO CLIPBOARD - closes in 60s";
        title.textColor = [UIColor cyanColor];
        title.font = [UIFont boldSystemFontOfSize:14];
        title.adjustsFontSizeToFitWidth = YES;
        [_overlayWindow.rootViewController.view addSubview:title];
        
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
