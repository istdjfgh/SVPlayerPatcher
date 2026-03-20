// SVPlayerPatcher v7 - Dump NSUserDefaults + App Container files
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static UIWindow *_overlayWindow = nil;

static NSString* scanEverything(void) {
    NSMutableString *r = [NSMutableString string];
    
    // === PART 1: App info ===
    [r appendFormat:@"=== SVPlayer Deep Scan v7 ===\n"];
    [r appendFormat:@"Bundle: %@\n", [[NSBundle mainBundle] bundleIdentifier]];
    [r appendFormat:@"Container: %@\n\n", NSHomeDirectory()];
    
    // === PART 2: NSUserDefaults - ALL keys ===
    [r appendString:@"=== NSUserDefaults ===\n\n"];
    NSDictionary *defaults = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
    NSArray *sortedKeys = [defaults.allKeys sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *key in sortedKeys) {
        id value = defaults[key];
        NSString *valStr;
        if ([value isKindOfClass:[NSData class]]) {
            valStr = [NSString stringWithFormat:@"<Data %lu bytes>", (unsigned long)[(NSData*)value length]];
        } else if ([value isKindOfClass:[NSArray class]] || [value isKindOfClass:[NSDictionary class]]) {
            NSData *jsonData = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
            valStr = jsonData ? [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding] : [value description];
            if (valStr.length > 200) valStr = [[valStr substringToIndex:200] stringByAppendingString:@"..."];
        } else {
            valStr = [value description];
            if (valStr.length > 200) valStr = [[valStr substringToIndex:200] stringByAppendingString:@"..."];
        }
        [r appendFormat:@"KEY: %@\n  = %@\n\n", key, valStr];
    }
    
    // === PART 3: List ALL files in app container ===
    [r appendString:@"\n=== App Container Files ===\n\n"];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *home = NSHomeDirectory();
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:home];
    NSString *file;
    int fileCount = 0;
    NSMutableArray *interestingFiles = [NSMutableArray array];
    
    while ((file = [enumerator nextObject])) {
        fileCount++;
        NSString *fullPath = [home stringByAppendingPathComponent:file];
        NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
        unsigned long long size = [attrs fileSize];
        
        [r appendFormat:@"%@ (%llu bytes)\n", file, size];
        
        // Mark interesting files
        NSString *ext = [file pathExtension].lowercaseString;
        NSString *lower = file.lowercaseString;
        if ([ext isEqualToString:@"plist"] || [ext isEqualToString:@"json"] ||
            [ext isEqualToString:@"ini"] || [ext isEqualToString:@"conf"] ||
            [ext isEqualToString:@"sqlite"] || [ext isEqualToString:@"db"] ||
            [ext isEqualToString:@"xml"] || [ext isEqualToString:@"dat"] ||
            [lower containsString:@"premium"] || [lower containsString:@"license"] ||
            [lower containsString:@"purchase"] || [lower containsString:@"subscri"] ||
            [lower containsString:@"receipt"] || [lower containsString:@"setting"]) {
            [interestingFiles addObject:fullPath];
        }
    }
    [r appendFormat:@"\nTotal: %d files\n", fileCount];
    
    // === PART 4: Read interesting small files ===
    [r appendString:@"\n=== Interesting File Contents ===\n\n"];
    for (NSString *path in interestingFiles) {
        NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
        unsigned long long size = [attrs fileSize];
        if (size > 50000) {
            [r appendFormat:@"--- %@ (too large: %llu bytes) ---\n\n", [path lastPathComponent], size];
            continue;
        }
        if (size == 0) continue;
        
        [r appendFormat:@"--- %@ (%llu bytes) ---\n", [path lastPathComponent], size];
        
        NSString *ext = [path pathExtension].lowercaseString;
        if ([ext isEqualToString:@"plist"]) {
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:path];
            if (plist) {
                for (NSString *key in plist) {
                    [r appendFormat:@"  %@ = %@\n", key, plist[key]];
                }
            } else {
                NSArray *arr = [NSArray arrayWithContentsOfFile:path];
                if (arr) [r appendFormat:@"  %@\n", arr];
            }
        } else if ([ext isEqualToString:@"json"]) {
            NSData *data = [NSData dataWithContentsOfFile:path];
            NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (str.length > 2000) str = [[str substringToIndex:2000] stringByAppendingString:@"..."];
            [r appendFormat:@"  %@\n", str];
        } else {
            NSData *data = [NSData dataWithContentsOfFile:path];
            NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (str) {
                if (str.length > 2000) str = [[str substringToIndex:2000] stringByAppendingString:@"..."];
                [r appendFormat:@"  %@\n", str];
            } else {
                [r appendFormat:@"  <binary data>\n"];
            }
        }
        [r appendString:@"\n"];
    }
    
    return r;
}

__attribute__((constructor))
static void tweak_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSString *results = scanEverything();
        [UIPasteboard generalPasteboard].string = results;
        
        NSString *docsPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        [results writeToFile:[docsPath stringByAppendingPathComponent:@"svplayer_dump.txt"]
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
        t.text = @"DEEP SCAN DONE - COPIED - closes in 60s";
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
