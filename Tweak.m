// SVPlayerPatcher v23 - Debug + fake receipt writer (USE WITH PATCHED IPA)
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static NSMutableString *_log = nil;
static BOOL _fakeState = NO;

// ====================================================
// PART 1: Verify binary patch + scan crypto
// ====================================================

static void verifyPatch(void) {
    [_log appendString:@"=== Patch Verification ===\n"];
    
    const char *funcs[] = {"PKCS7_verify", "X509_verify_cert", "CMS_verify", "CMS_verify_receipt", NULL};
    
    for (int i = 0; funcs[i]; i++) {
        void *sym = dlsym(RTLD_DEFAULT, funcs[i]);
        if (!sym) {
            [_log appendFormat:@"  %s: NOT FOUND\n", funcs[i]];
            continue;
        }
        
        uint32_t *fn = (uint32_t *)sym;
        // Check if patched: MOV W0, #1 (0x52800020) + RET (0xD65F03C0)
        BOOL patched = (fn[0] == 0x52800020 && fn[1] == 0xD65F03C0);
        [_log appendFormat:@"  %s: %s [%08X %08X]\n",
         funcs[i],
         patched ? "PATCHED ✅" : "NOT PATCHED ❌",
         fn[0], fn[1]];
    }
    [_log appendString:@"\n"];
}

// ====================================================
// PART 2: Build and write fake receipt to DATA container
// ====================================================

// Minimal ASN.1 DER helpers
static NSMutableData *asn1Tag(uint8_t tag, NSData *content) {
    NSMutableData *d = [NSMutableData data];
    [d appendBytes:&tag length:1];
    NSUInteger len = content.length;
    if (len < 0x80) {
        uint8_t b = (uint8_t)len;
        [d appendBytes:&b length:1];
    } else if (len < 0x100) {
        uint8_t b[] = {0x81, (uint8_t)len};
        [d appendBytes:b length:2];
    } else {
        uint8_t b[] = {0x82, (uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
        [d appendBytes:b length:3];
    }
    [d appendData:content];
    return d;
}

static NSData *asn1Seq(NSData *c) { return asn1Tag(0x30, c); }
static NSData *asn1Set(NSData *c) { return asn1Tag(0x31, c); }
static NSData *asn1Octet(NSData *c) { return asn1Tag(0x04, c); }

static NSData *asn1Int(int val) {
    if (val < 0x80) {
        uint8_t b = (uint8_t)val;
        return asn1Tag(0x02, [NSData dataWithBytes:&b length:1]);
    }
    uint8_t b[] = {0x00, (uint8_t)val};
    return asn1Tag(0x02, [NSData dataWithBytes:b length:2]);
}

static NSData *asn1IntBig(int val) {
    // For values > 255 (like 1701, 1702)
    uint8_t b[3];
    if (val < 0x80) {
        b[0] = val; return asn1Tag(0x02, [NSData dataWithBytes:b length:1]);
    } else if (val < 0x100) {
        b[0] = 0; b[1] = val; return asn1Tag(0x02, [NSData dataWithBytes:b length:2]);
    } else {
        b[0] = (val >> 8) & 0xFF; b[1] = val & 0xFF;
        if (b[0] >= 0x80) {
            uint8_t c[] = {0, b[0], b[1]};
            return asn1Tag(0x02, [NSData dataWithBytes:c length:3]);
        }
        return asn1Tag(0x02, [NSData dataWithBytes:b length:2]);
    }
}

static NSData *asn1Utf8(NSString *s) {
    return asn1Tag(0x0C, [s dataUsingEncoding:NSUTF8StringEncoding]);
}
static NSData *asn1IA5(NSString *s) {
    return asn1Tag(0x16, [s dataUsingEncoding:NSASCIIStringEncoding]);
}
static NSData *asn1Ctx(uint8_t num, NSData *c) {
    return asn1Tag(0xA0 | num, c);
}

static NSData *asn1OID(const uint8_t *bytes, int len) {
    return asn1Tag(0x06, [NSData dataWithBytes:bytes length:len]);
}

static NSData *receiptAttr(int type, NSData *val) {
    NSMutableData *d = [NSMutableData data];
    [d appendData:asn1IntBig(type)];
    [d appendData:asn1Int(1)];
    [d appendData:asn1Octet(val)];
    return asn1Seq(d);
}

static NSData *buildFakeReceipt(NSString *bundleId) {
    // IAP receipt for unlock0
    NSMutableData *iap1 = [NSMutableData data];
    [iap1 appendData:receiptAttr(1701, asn1Int(1))];           // quantity
    [iap1 appendData:receiptAttr(1702, asn1Utf8(@"unlock0"))]; // product_id
    [iap1 appendData:receiptAttr(1703, asn1Utf8(@"200000084567"))]; // tx_id
    [iap1 appendData:receiptAttr(1704, asn1IA5(@"2025-01-15T10:00:00Z"))]; // date
    [iap1 appendData:receiptAttr(1705, asn1Utf8(@"200000084567"))]; // orig_tx
    [iap1 appendData:receiptAttr(1706, asn1IA5(@"2025-01-15T10:00:00Z"))]; // orig_date
    
    // IAP receipt for hfr.m.y (subscription - expires far future)
    NSMutableData *iap2 = [NSMutableData data];
    [iap2 appendData:receiptAttr(1701, asn1Int(1))];
    [iap2 appendData:receiptAttr(1702, asn1Utf8(@"hfr.m.y"))];
    [iap2 appendData:receiptAttr(1703, asn1Utf8(@"200000084568"))];
    [iap2 appendData:receiptAttr(1704, asn1IA5(@"2025-01-15T10:00:00Z"))];
    [iap2 appendData:receiptAttr(1705, asn1Utf8(@"200000084568"))];
    [iap2 appendData:receiptAttr(1706, asn1IA5(@"2025-01-15T10:00:00Z"))];
    [iap2 appendData:receiptAttr(1708, asn1IA5(@"2099-12-31T23:59:59Z"))]; // expires
    
    // Main receipt
    NSMutableData *payload = [NSMutableData data];
    [payload appendData:receiptAttr(2, asn1Utf8(bundleId))];     // bundle_id
    [payload appendData:receiptAttr(3, asn1Utf8(@"1.8.0"))];     // version
    [payload appendData:receiptAttr(4, asn1Octet([NSMutableData dataWithLength:16]))]; // opaque
    [payload appendData:receiptAttr(5, asn1Octet([NSMutableData dataWithLength:20]))]; // sha1
    [payload appendData:receiptAttr(12, asn1IA5(@"2025-01-15T10:00:00Z"))]; // creation
    [payload appendData:receiptAttr(17, asn1Set(iap1))];         // IAP unlock0
    [payload appendData:receiptAttr(17, asn1Set(iap2))];         // IAP hfr.m.y
    [payload appendData:receiptAttr(19, asn1Utf8(@"1.0"))];      // orig version
    
    NSData *payloadSet = asn1Set(payload);
    
    // PKCS7 OIDs
    uint8_t oidSD[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}; // 1.2.840.113549.1.7.2
    uint8_t oidData[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}; // 1.2.840.113549.1.7.1
    uint8_t oidSha[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}; // 2.16.840.1.101.3.4.2.1
    
    // ContentInfo
    NSMutableData *ci = [NSMutableData data];
    [ci appendData:asn1OID(oidData, 9)];
    [ci appendData:asn1Ctx(0, asn1Octet(payloadSet))];
    
    // SignedData
    NSMutableData *sd = [NSMutableData data];
    [sd appendData:asn1Int(1)];                        // version
    [sd appendData:asn1Set(asn1Seq(asn1OID(oidSha, 9)))]; // digest algos
    [sd appendData:asn1Seq(ci)];                       // content info
    [sd appendData:asn1Set([NSData data])];             // signer infos (empty)
    
    // PKCS7 wrapper
    NSMutableData *p7 = [NSMutableData data];
    [p7 appendData:asn1OID(oidSD, 9)];
    [p7 appendData:asn1Ctx(0, asn1Seq(sd))];
    
    return asn1Seq(p7);
}

static void writeFakeReceipt(void) {
    [_log appendString:@"=== Receipt Generation ===\n"];
    
    // Get bundle ID
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"hfr.m.svplayer";
    [_log appendFormat:@"  Bundle ID: %@\n", bundleId];
    
    NSData *receipt = buildFakeReceipt(bundleId);
    [_log appendFormat:@"  Receipt size: %lu bytes\n", (unsigned long)receipt.length];
    
    // Write to WRITABLE locations (StoreKit dir is protected by iOS)
    NSString *dataDir = NSHomeDirectory();
    static NSString *_receiptPath = nil;
    NSError *err = nil;
    
    NSArray *tryPaths = @[
        [dataDir stringByAppendingPathComponent:@"Library/Caches/fakereceipt"],
        [dataDir stringByAppendingPathComponent:@"Library/fakereceipt"],
        [dataDir stringByAppendingPathComponent:@"Documents/fakereceipt"],
        [dataDir stringByAppendingPathComponent:@"tmp/fakereceipt"],
    ];
    
    for (NSString *p in tryPaths) {
        NSString *dir = [p stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        BOOL ok = [receipt writeToFile:p options:NSDataWritingAtomic error:&err];
        if (ok) {
            _receiptPath = p;
            [_log appendFormat:@"  Receipt written: %@ ✅\n", [p lastPathComponent]];
            break;
        } else {
            [_log appendFormat:@"  %@: %@ ❌\n", [p lastPathComponent], err.localizedDescription];
        }
    }
    
    if (!_receiptPath) {
        [_log appendString:@"  ALL WRITES FAILED!\n"];
    }
    [_log appendString:@"\n"];
}

// ====================================================
// PART 2b: Test d2i_PKCS7 with our receipt + dump main.cfg
// ====================================================

typedef void* (*d2i_PKCS7_t)(void**, const unsigned char**, long);
typedef void (*PKCS7_free_t)(void*);

static void testReceiptParsing(NSData *receipt) {
    [_log appendString:@"=== d2i_PKCS7 Self-Test ===\n"];
    
    d2i_PKCS7_t d2i = (d2i_PKCS7_t)dlsym(RTLD_DEFAULT, "d2i_PKCS7");
    PKCS7_free_t pfree = (PKCS7_free_t)dlsym(RTLD_DEFAULT, "PKCS7_free");
    
    if (!d2i) {
        [_log appendString:@"  d2i_PKCS7: NOT FOUND\n"];
        return;
    }
    
    const unsigned char *ptr = receipt.bytes;
    void *p7 = d2i(NULL, &ptr, (long)receipt.length);
    
    if (p7) {
        [_log appendString:@"  d2i_PKCS7: PARSED OK ✅\n"];
        
        // Try PKCS7_verify on it
        typedef int (*PKCS7_verify_t)(void*, void*, void*, void*, void*, int);
        PKCS7_verify_t pv = (PKCS7_verify_t)dlsym(RTLD_DEFAULT, "PKCS7_verify");
        if (pv) {
            int r = pv(p7, NULL, NULL, NULL, NULL, 0x8); // PKCS7_NOVERIFY
            [_log appendFormat:@"  PKCS7_verify result: %d %@\n", r, r == 1 ? @"✅" : @"❌"];
        }
        
        if (pfree) pfree(p7);
    } else {
        [_log appendString:@"  d2i_PKCS7: PARSE FAILED ❌ (our ASN.1 is broken!)\n"];
        [_log appendFormat:@"  Receipt hex (first 64): "];
        const uint8_t *b = receipt.bytes;
        for (int i = 0; i < 64 && i < (int)receipt.length; i++) {
            [_log appendFormat:@"%02X", b[i]];
        }
        [_log appendString:@"\n"];
    }
    [_log appendString:@"\n"];
}

static void dumpMainCfg(void) {
    [_log appendString:@"=== File Search (recursive) ===\n"];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // Search these root directories
    NSArray *roots = @[
        NSHomeDirectory(),
        [[NSBundle mainBundle] bundlePath],
    ];
    
    for (NSString *root in roots) {
        NSDirectoryEnumerator *en = [fm enumeratorAtPath:root];
        NSString *item;
        int found = 0;
        while ((item = [en nextObject]) && found < 50) {
            NSString *lower = [item lowercaseString];
            BOOL interesting = [lower hasSuffix:@".cfg"] || [lower hasSuffix:@".lic"] ||
                               [lower hasSuffix:@".ini"] ||
                               [lower containsString:@"svp"] || [lower containsString:@"main.cfg"] ||
                               [lower containsString:@"purchase"] || [lower containsString:@"license"];
            
            if (!interesting) continue;
            
            NSString *full = [root stringByAppendingPathComponent:item];
            NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
            NSNumber *size = attrs[NSFileSize];
            
            [_log appendFormat:@"  %@ (%@ bytes)\n", item, size];
            
            // Read small text files
            if (size.unsignedLongLongValue < 3000 && size.unsignedLongLongValue > 0) {
                NSData *d = [NSData dataWithContentsOfFile:full];
                if (d) {
                    NSString *c = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                    if (c && c.length > 0) {
                        // Show first 500 chars
                        if (c.length > 500) c = [c substringToIndex:500];
                        [_log appendFormat:@"    ---\n%@\n    ---\n", c];
                    } else {
                        // Binary file, show hex
                        [_log appendString:@"    [binary] "];
                        const uint8_t *b = d.bytes;
                        for (int i = 0; i < 40 && i < (int)d.length; i++) {
                            [_log appendFormat:@"%02X", b[i]];
                        }
                        [_log appendString:@"...\n"];
                    }
                }
            }
            found++;
        }
        [_log appendFormat:@"  (%@ total interesting files)\n\n", @(found)];
    }
    
    // Also check NSUserDefaults - ALL keys (not filtered)
    NSDictionary *defaults = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
    [_log appendFormat:@"=== UserDefaults (%lu keys) ===\n", (unsigned long)defaults.count];
    for (NSString *key in [defaults.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
        // Skip Apple internal keys
        if ([key hasPrefix:@"NS"] || [key hasPrefix:@"Apple"] || [key hasPrefix:@"AK"] ||
            [key hasPrefix:@"com.apple"] || [key hasPrefix:@"INNext"] || [key hasPrefix:@"PK"]) continue;
        id val = defaults[key];
        NSString *vs = [NSString stringWithFormat:@"%@", val];
        if (vs.length > 100) vs = [vs substringToIndex:100];
        [_log appendFormat:@"  %@ = %@\n", key, vs];
    }
    [_log appendString:@"\n"];
}

static IMP _orig_txState = NULL;
static NSInteger hooked_txState(id self, SEL _cmd) {
    if (_fakeState) return SKPaymentTransactionStateRestored;
    return ((NSInteger(*)(id, SEL))_orig_txState)(self, _cmd);
}
static IMP _orig_origTx = NULL;
static id hooked_origTx(id self, SEL _cmd) {
    if (_fakeState) return self;
    return ((id(*)(id, SEL))_orig_origTx)(self, _cmd);
}
static IMP _orig_txId = NULL;
static NSString* hooked_txId(id self, SEL _cmd) {
    if (_fakeState) return @"200000084567";
    return ((NSString*(*)(id, SEL))_orig_txId)(self, _cmd);
}

static IMP _orig_updated = NULL;
static void hooked_updated(id self, SEL _cmd, id queue, NSArray *txs) {
    for (SKPaymentTransaction *tx in txs) {
        NSInteger real = ((NSInteger(*)(id, SEL))_orig_txState)(tx, @selector(transactionState));
        [_log appendFormat:@"[TX] state=%ld prod=%@\n", (long)real, tx.payment.productIdentifier];
    }
    _fakeState = YES;
    [_log appendString:@"[FAKE] state -> Restored\n"];
    ((void(*)(id, SEL, id, NSArray*))_orig_updated)(self, _cmd, queue, txs);
    _fakeState = NO;
    [UIPasteboard generalPasteboard].string = _log;
}

static IMP _orig_finish = NULL;
static void hooked_finish(id s, SEL c, id tx) {
    [_log appendString:@"[FINISH] tx\n"];
    @try { ((void(*)(id,SEL,id))_orig_finish)(s,c,tx); } @catch(NSException *e) {}
}
static IMP _orig_restored = NULL;
static void hooked_restored(id s, SEL c, id q) {
    [_log appendString:@"[RESTORE] completed\n"];
    [UIPasteboard generalPasteboard].string = _log;
    ((void(*)(id,SEL,id))_orig_restored)(s,c,q);
}

// ====================================================
// PART 4: Hook receipt URL to return our receipt
// ====================================================

static IMP _orig_receiptURL = NULL;
static NSURL* hooked_receiptURL(id self, SEL _cmd) {
    // Try all our writable receipt locations
    NSArray *paths = @[
        [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/fakereceipt"],
        [NSHomeDirectory() stringByAppendingPathComponent:@"Library/fakereceipt"],
        [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/fakereceipt"],
        [NSHomeDirectory() stringByAppendingPathComponent:@"tmp/fakereceipt"],
    ];
    for (NSString *p in paths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
            [_log appendString:@"[RECEIPT] -> serving fake receipt ✅\n"];
            return [NSURL fileURLWithPath:p];
        }
    }
    [_log appendString:@"[RECEIPT] -> no fake found, using original\n"];
    return ((NSURL*(*)(id, SEL))_orig_receiptURL)(self, _cmd);
}

__attribute__((constructor))
static void tweak_init(void) {
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v25 CONFIG PATCH ===\n\n"];
    
    // 1. Verify binary patches
    verifyPatch();
    
    // 2. Write fake receipt
    writeFakeReceipt();
    
    // 2b. Test receipt parsing
    NSData *testReceipt = buildFakeReceipt([[NSBundle mainBundle] bundleIdentifier] ?: @"com.svpteam.svp");
    testReceiptParsing(testReceipt);
    
    // ==========================================
    // 3. PATCH main.cfg - the key to premium!
    // ==========================================
    NSString *cfgDir = [NSHomeDirectory() stringByAppendingPathComponent:
                        @"Library/Application Support/SVPlayer/settings"];
    NSString *cfgPath = [cfgDir stringByAppendingPathComponent:@"main.cfg"];
    
    // Pre-create the config directory
    [[NSFileManager defaultManager] createDirectoryAtPath:cfgDir
                              withIntermediateDirectories:YES attributes:nil error:nil];
    
    // If main.cfg already exists, patch it
    // If not, pre-create with premium values
    void (^patchConfig)(void) = ^{
        NSFileManager *fm = [NSFileManager defaultManager];
        if ([fm fileExistsAtPath:cfgPath]) {
            NSData *d = [NSData dataWithContentsOfFile:cfgPath];
            NSString *content = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            
            if (content && [content containsString:@"dummydummy"]) {
                // Replace h/pid
                NSString *patched = [content stringByReplacingOccurrencesOfString:@"\"dummydummy\""
                                                                      withString:@"\"unlock0\""];
                [patched writeToFile:cfgPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
                [_log appendString:@"[CFG] Patched h/pid: dummydummy -> unlock0 ✅\n"];
            } else if (content && [content containsString:@"unlock0"]) {
                [_log appendString:@"[CFG] Already patched (unlock0) ✅\n"];
            } else {
                [_log appendFormat:@"[CFG] Exists but no dummydummy found\n"];
            }
        } else {
            // Pre-create with premium values
            NSDictionary *cfg = @{
                @"h/pid": @"unlock0",
                @"h/uid": [[NSUUID UUID] UUIDString],
                @"h/last_check": @((long)[[NSDate date] timeIntervalSince1970]),
                @"dev/fast_render": @YES,
                @"performance/cpu": @7800,
                @"performance/gpu": @1000,
                @"performance/db": @YES,
            };
            NSData *json = [NSJSONSerialization dataWithJSONObject:cfg options:NSJSONWritingPrettyPrinted error:nil];
            [json writeToFile:cfgPath atomically:YES];
            [_log appendString:@"[CFG] Pre-created with unlock0 ✅\n"];
        }
        [UIPasteboard generalPasteboard].string = _log;
    };
    
    patchConfig(); // Patch NOW (before Qt init)
    
    // Make main.cfg READ-ONLY so Qt can't reset h/pid!
    NSDictionary *roAttrs = @{NSFilePosixPermissions: @(0444)};
    [[NSFileManager defaultManager] setAttributes:roAttrs ofItemAtPath:cfgPath error:nil];
    [_log appendString:@"[CFG] Set read-only (0444) 🔒\n"];
    
    // Also keep checking - if Qt somehow writes, re-patch and re-lock
    for (int i = 1; i <= 30; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 500 * NSEC_PER_MSEC)), dispatch_get_global_queue(0, 0), ^{
            NSData *d = [NSData dataWithContentsOfFile:cfgPath];
            if (d) {
                NSString *c = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (c && [c containsString:@"dummydummy"]) {
                    // Make writable first, then patch, then lock again
                    [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @(0644)}
                                                     ofItemAtPath:cfgPath error:nil];
                    NSString *p = [c stringByReplacingOccurrencesOfString:@"\"dummydummy\""
                                                              withString:@"\"unlock0\""];
                    [p writeToFile:cfgPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
                    [[NSFileManager defaultManager] setAttributes:roAttrs ofItemAtPath:cfgPath error:nil];
                    [_log appendFormat:@"[CFG] Re-patched+locked at %dms ✅\n", i*500];
                }
            }
        });
    }
    
    // BLOCK svp-team.com API validation by hooking NSURLSession
    {
        Method dm = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
        if (dm) {
            static IMP _orig_task = NULL;
            _orig_task = method_setImplementation(dm, imp_implementationWithBlock(
                ^NSURLSessionDataTask*(id self, NSURLRequest *request, void (^completion)(NSData*, NSURLResponse*, NSError*)) {
                    NSString *url = request.URL.absoluteString;
                    if ([url containsString:@"svp-team.com"] || [url containsString:@"svpteam.com"]) {
                        [_log appendFormat:@"[API] BLOCKED: %@\n", url];
                        [UIPasteboard generalPasteboard].string = _log;
                        
                        // Return fake "valid" response
                        NSDictionary *resp = @{@"status": @"ok", @"valid": @YES, @"licensed": @YES};
                        NSData *body = [NSJSONSerialization dataWithJSONObject:resp options:0 error:nil];
                        NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc]
                            initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1"
                            headerFields:@{@"Content-Type": @"application/json"}];
                        
                        if (completion) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                                completion(body, fakeResp, nil);
                            });
                        }
                        // Return a dummy task
                        NSURLRequest *dummy = [NSURLRequest requestWithURL:[NSURL URLWithString:@"about:blank"]];
                        return ((NSURLSessionDataTask*(*)(id, SEL, NSURLRequest*, id))_orig_task)(
                            self, @selector(dataTaskWithRequest:completionHandler:), dummy, nil);
                    }
                    return ((NSURLSessionDataTask*(*)(id, SEL, NSURLRequest*, id))_orig_task)(
                        self, @selector(dataTaskWithRequest:completionHandler:), request, completion);
                }
            ));
            [_log appendString:@"[OK] API block hook\n"];
        }
    }
    
    [_log appendString:@"\n"];
    
    // 4. Hook receiptURL
    Method m = class_getInstanceMethod([NSBundle class], @selector(appStoreReceiptURL));
    if (m) {
        _orig_receiptURL = method_setImplementation(m, (IMP)hooked_receiptURL);
        [_log appendString:@"[OK] receiptURL hook\n"];
    }
    
    // 3b. Hook NSData reads to inject our receipt data
    static NSData *_fakeReceiptData = nil;
    _fakeReceiptData = buildFakeReceipt([[NSBundle mainBundle] bundleIdentifier] ?: @"com.svpteam.svp");
    
    // Store receipt data globally
    static __strong NSData *_globalReceipt = nil;
    _globalReceipt = _fakeReceiptData;
    
    // Hook NSData initWithContentsOfURL:
    {
        Method dm = class_getInstanceMethod([NSData class], @selector(initWithContentsOfURL:));
        if (dm) {
            static IMP _orig_dataURL = NULL;
            _orig_dataURL = method_setImplementation(dm, imp_implementationWithBlock(^NSData*(id self, NSURL *url) {
                if ([url.path containsString:@"receipt"] || [url.path containsString:@"Receipt"]) {
                    [_log appendFormat:@"[DATA-URL] %@ -> FAKE ✅\n", [url.path lastPathComponent]];
                    [UIPasteboard generalPasteboard].string = _log;
                    return _globalReceipt;
                }
                return ((NSData*(*)(id, SEL, NSURL*))_orig_dataURL)(self, @selector(initWithContentsOfURL:), url);
            }));
            [_log appendString:@"[OK] NSData URL hook\n"];
        }
    }
    
    // Hook NSData initWithContentsOfFile:
    {
        Method dm = class_getInstanceMethod([NSData class], @selector(initWithContentsOfFile:));
        if (dm) {
            static IMP _orig_dataFile = NULL;
            _orig_dataFile = method_setImplementation(dm, imp_implementationWithBlock(^NSData*(id self, NSString *path) {
                if ([path containsString:@"receipt"] || [path containsString:@"Receipt"]) {
                    [_log appendFormat:@"[DATA-FILE] %@ -> FAKE ✅\n", [path lastPathComponent]];
                    [UIPasteboard generalPasteboard].string = _log;
                    return _globalReceipt;
                }
                return ((NSData*(*)(id, SEL, NSString*))_orig_dataFile)(self, @selector(initWithContentsOfFile:), path);
            }));
            [_log appendString:@"[OK] NSData File hook\n"];
        }
    }
    
    // 4. StoreKit hooks
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionState));
    if (m) _orig_txState = method_setImplementation(m, (IMP)hooked_txState);
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(transactionIdentifier));
    if (m) _orig_txId = method_setImplementation(m, (IMP)hooked_txId);
    m = class_getInstanceMethod([SKPaymentTransaction class], @selector(originalTransaction));
    if (m) _orig_origTx = method_setImplementation(m, (IMP)hooked_origTx);
    m = class_getInstanceMethod([SKPaymentQueue class], @selector(finishTransaction:));
    if (m) _orig_finish = method_setImplementation(m, (IMP)hooked_finish);
    [_log appendString:@"[OK] SK hooks\n"];
    
    // 5. IAP hooks + DELAYED file scan
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"InAppPurchaseManager");
        if (cls) {
            Method mx = class_getInstanceMethod(cls, @selector(paymentQueue:updatedTransactions:));
            if (mx) _orig_updated = method_setImplementation(mx, (IMP)hooked_updated);
            Method my = class_getInstanceMethod(cls, @selector(paymentQueueRestoreCompletedTransactionsFinished:));
            if (my) _orig_restored = method_setImplementation(my, (IMP)hooked_restored);
            [_log appendString:@"[OK] IAP hooks\n"];
        }
        [UIPasteboard generalPasteboard].string = _log;
    });
    
    // 6. DELAYED full file scan (10s - after Qt/app init creates configs)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [_log appendString:@"\n=== DELAYED FILE SCAN (10s) ===\n"];
        
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *home = NSHomeDirectory();
        NSDirectoryEnumerator *en = [fm enumeratorAtPath:home];
        NSString *item;
        int total = 0;
        while ((item = [en nextObject]) && total < 80) {
            // Skip known uninteresting dirs
            if ([item hasPrefix:@"Library/SplashBoard"] || [item hasPrefix:@"Library/Caches/com.apple"] ||
                [item hasPrefix:@"Library/WebKit"] || [item hasPrefix:@"Library/Saved"] ||
                [item containsString:@".ktx"]) continue;
            
            NSString *full = [home stringByAppendingPathComponent:item];
            BOOL isDir = NO;
            [fm fileExistsAtPath:full isDirectory:&isDir];
            if (isDir) continue;
            
            NSDictionary *a = [fm attributesOfItemAtPath:full error:nil];
            unsigned long long sz = [a[NSFileSize] unsignedLongLongValue];
            [_log appendFormat:@"  %@ (%llu)\n", item, sz];
            
            // Read cfg/lic/ini/plist files
            NSString *lower = [item lowercaseString];
            if (([lower hasSuffix:@".cfg"] || [lower hasSuffix:@".lic"] || [lower hasSuffix:@".ini"] ||
                 [lower hasSuffix:@".plist"]) && sz < 3000 && sz > 0) {
                NSData *d = [NSData dataWithContentsOfFile:full];
                NSString *c = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (c) {
                    if (c.length > 300) c = [c substringToIndex:300];
                    [_log appendFormat:@"    ---\n%@\n    ---\n", c];
                }
            }
            total++;
        }
        [_log appendFormat:@"  (listed %d files)\n", total];
        
        [UIPasteboard generalPasteboard].string = _log;
        
        // Banner
        UIWindowScene *sc = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) { sc = s; break; }
        if (!sc) return;
        UIWindow *w = [[UIWindow alloc] initWithWindowScene:sc];
        w.frame = CGRectMake(10, 40, 400, 40);
        w.windowLevel = UIWindowLevelAlert + 100;
        w.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.9];
        w.layer.cornerRadius = 8; w.clipsToBounds = YES;
        w.rootViewController = [[UIViewController alloc] init];
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(10, 0, 380, 40)];
        l.text = @"v24b | Restore → check clipboard 📋";
        l.font = [UIFont fontWithName:@"Menlo" size:11];
        l.textColor = [UIColor cyanColor];
        [w.rootViewController.view addSubview:l];
        w.hidden = NO;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 6*NSEC_PER_SEC), dispatch_get_main_queue(), ^{ w.hidden = YES; });
        
        // Keep updating clipboard
        for (int i = 1; i <= 30; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i*2.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [UIPasteboard generalPasteboard].string = _log;
            });
        }
    });
}
