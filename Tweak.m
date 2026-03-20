// SVPlayerPatcher v4 - Find SVPlayer's OWN classes
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static UIWindow *_overlayWindow = nil;

// Known Apple framework prefixes to SKIP
static BOOL isAppleClass(NSString *name) {
    NSArray *applePrefixes = @[
        @"NS", @"UI", @"CF", @"CG", @"CA", @"CI", @"CL", @"CM", @"CN",
        @"AV", @"SK", @"SC", @"WK", @"MK", @"PK", @"GC", @"GL", @"MT",
        @"FC", @"NF", @"PR", @"TP", @"AX", @"VO", @"LS", @"BS", @"FBS",
        @"_NS", @"_UI", @"_CF", @"_CG", @"_CA", @"_AV", @"_SK", @"_WK",
        @"__NS", @"__CF", @"OS_", @"_TtC", @"_TtG", @"SCRO", @"RBS",
        @"RCKey", @"Mobile", @"Web", @"Net", @"Sec", @"SSL", @"TLS",
        @"IO", @"HID", @"BK", @"MCPeerID", @"GKP", @"ASIdentifier",
        @"CT", @"AT", @"AD", @"AB", @"EK", @"HK", @"INS", @"MAP",
        @"MPMedia", @"NWC", @"PHAsset", @"QL", @"SF", @"SRP",
        @"TCC", @"UTType", @"XPC", @"CBCentral", @"NWDB",
        @"PLBuild", @"NewsCore", @"NFP", @"CKRecord",
        @"ObjC", @"Swift", @"swift", @"Block", @"Malloc",
        @"dispatch", @"os_", @"objc", @"cxx"
    ];
    for (NSString *prefix in applePrefixes) {
        if ([name hasPrefix:prefix]) return YES;
    }
    // Skip single-letter or very short class names
    if (name.length < 4) return YES;
    // Skip classes containing "Apple" or starting with lowercase
    if ([name containsString:@"Apple"]) return YES;
    if ([[NSCharacterSet lowercaseLetterCharacterSet] characterIsMember:[name characterAtIndex:0]]) return YES;
    return NO;
}

static NSString* scanClasses(void) {
    int numClasses = objc_getClassList(NULL, 0);
    Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * numClasses);
    objc_getClassList(classes, numClasses);
    
    NSMutableString *results = [NSMutableString stringWithString:@"=== SVPlayer OWN Classes ===\n\n"];
    int found = 0;
    
    for (int i = 0; i < numClasses; i++) {
        const char *name = class_getName(classes[i]);
        if (!name) continue;
        NSString *className = [NSString stringWithUTF8String:name];
        
        if (isAppleClass(className)) continue;
        
        found++;
        [results appendFormat:@"CLASS: %@\n", className];
        
        // List ALL properties
        unsigned int propCount = 0;
        objc_property_t *props = class_copyPropertyList(classes[i], &propCount);
        for (unsigned int j = 0; j < propCount; j++) {
            const char *pn = property_getName(props[j]);
            [results appendFormat:@"  P: %s\n", pn];
        }
        if (props) free(props);
        
        // List key methods only
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
                [ls containsString:@"init"] || [ls containsString:@"enable"] ||
                [ls containsString:@"license"] || [ls containsString:@"active"] ||
                [ls containsString:@"valid"] || [ls containsString:@"expire"]) {
                [results appendFormat:@"  M: %@\n", selName];
            }
        }
        if (methods) free(methods);
        [results appendString:@"\n"];
    }
    
    free(classes);
    [results appendFormat:@"\n=== Found %d non-Apple classes ===\n", found];
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
        
        // Show overlay
        UIWindowScene *scene = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {
            scene = s; break;
        }
        if (!scene) return;
        
        _overlayWindow = [[UIWindow alloc] initWithWindowScene:scene];
        _overlayWindow.frame = scene.coordinateSpace.bounds;
        _overlayWindow.windowLevel = UIWindowLevelAlert + 100;
        _overlayWindow.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.92];
        _overlayWindow.rootViewController = [[UIViewController alloc] init];
        
        CGRect b = _overlayWindow.bounds;
        
        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, b.size.width - 40, 30)];
        title.text = [NSString stringWithFormat:@"SVPlayer OWN Classes - AUTO COPIED - tap overlay 30s to close"];
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
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            _overlayWindow.hidden = YES;
            _overlayWindow = nil;
        });
    });
}
