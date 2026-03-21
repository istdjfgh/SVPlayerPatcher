// SVPlayerPatcher v38 - RSA_public_decrypt interpose
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static NSMutableString *_log = nil;
static BOOL _fakeState = NO;
static NSData *_globalReceipt = nil;
static int _rsaCallCount = 0;

// ====================================================
// RSA_public_decrypt INTERPOSE
// RSA_public_decrypt is used for LICENSE VERIFICATION (decrypt with public key)
// TLS uses RSA_private_decrypt (different function!) so this is safe to hook globally
// ====================================================

static int hooked_RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding) {
    _rsaCallCount++;
    
    if (_log) {
        [_log appendFormat:@"[RSA] public_decrypt #%d: flen=%d padding=%d\n", _rsaCallCount, flen, padding];
        
        // Log first 16 bytes of input
        NSMutableString *hex = [NSMutableString string];
        int n = flen < 16 ? flen : 16;
        for (int i = 0; i < n; i++) {
            [hex appendFormat:@"%02X ", from[i]];
        }
        [_log appendFormat:@"  input[0..%d]: %@\n", n, hex];
    }
    
    // For RSA-2048 (flen=256) - this is the license decryption
    if (flen == 256) {
        // Try multiple formats. SVP might expect email|product_id|timestamp
        // or a simple string, or JSON
        const char *fake = "hfr.m.y|user@svp.com|9999999999|1";
        int len = (int)strlen(fake);
        memcpy(to, fake, len + 1);
        
        if (_log) {
            [_log appendFormat:@"[RSA] → wrote license '%s' (%d bytes) ✅\n", fake, len];
            [UIPasteboard generalPasteboard].string = _log;
        }
        return len;
    }
    
    // For other calls (flen=584 etc.) - write dummy valid ASN.1 or just return success
    // Return 1 byte of data
    to[0] = 0x01;
    if (_log) {
        [_log appendFormat:@"[RSA] → flen=%d, wrote 0x01 (passthrough)\n", flen];
        [UIPasteboard generalPasteboard].string = _log;
    }
    return 1;
}

// DYLD_INTERPOSE macro
#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
   __attribute__((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

// Declare the original symbol as weak (libmpv exports it at runtime, but we don't link libcrypto)
extern int RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding) __attribute__((weak_import));

// Install the interpose
DYLD_INTERPOSE(hooked_RSA_public_decrypt, RSA_public_decrypt)

// ====================================================
// PART 1: Verify binary patch + scan crypto
// ====================================================

static void verifyPatch(void) {
    [_log appendString:@"=== Patch Verification ===\n"];
    
    const char *funcs[] = {
        "PKCS7_verify", "X509_verify_cert", "CMS_verify", "CMS_verify_receipt",
        "RSA_verify", "EVP_VerifyFinal", "EVP_DigestVerifyFinal",
        "ECDSA_verify", "DSA_verify", NULL
    };
    
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
    
    // Store globally for FakeTransaction
    _globalReceipt = receipt;
    
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
    _log = [NSMutableString stringWithString:@"=== SVPlayerPatcher v39 RSA-FMT ===\n\n"];
    
    // 0. Hook Security framework verify functions
    {
        // SecKeyRawVerify -> always errSecSuccess (0)
        void *secSym = dlsym(RTLD_DEFAULT, "SecKeyRawVerify");
        if (secSym) {
            // Can't easily hook C functions without fishhook, but we can try method swizzle
            [_log appendString:@"[SEC] SecKeyRawVerify found\n"];
        }
        
        // Write FAKE svp.lic - PKCS7_verify is patched so any blob passes
        NSString *licPath = [NSHomeDirectory() stringByAppendingPathComponent:
                             @"Library/Application Support/SVPlayer/settings/svp.lic"];
        NSFileManager *fm = [NSFileManager defaultManager];
        
        // Remove directory trap if it exists from previous version
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:licPath isDirectory:&isDir] && isDir) {
            [fm removeItemAtPath:licPath error:nil];
        }
        
        // Create settings dir if needed
        [fm createDirectoryAtPath:[licPath stringByDeletingLastPathComponent]
      withIntermediateDirectories:YES attributes:nil error:nil];
        
        // Build fake license: base64(PKCS7(license_payload))
        // The app reads this, calls PKCS7_verify (patched → returns 1),
        // then extracts the signed data payload
        NSData *fakeLicReceipt = buildFakeReceipt(@"com.svpteam.svp");
        NSString *base64Lic = [fakeLicReceipt base64EncodedStringWithOptions:0];
        [base64Lic writeToFile:licPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [_log appendFormat:@"[LIC] Wrote fake svp.lic (%lu bytes) ✅\n", (unsigned long)base64Lic.length];
    }
    
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
                                                                      withString:@"\"hfr.m.y\""];
                [patched writeToFile:cfgPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
                [_log appendString:@"[CFG] Patched h/pid: dummydummy -> hfr.m.y ✅\n"];
            } else if (content && [content containsString:@"hfr.m.y"]) {
                [_log appendString:@"[CFG] Already patched (hfr.m.y) ✅\n"];
            } else {
                [_log appendFormat:@"[CFG] Exists but no dummydummy found\n"];
            }
        } else {
            // Pre-create with premium values
            NSDictionary *cfg = @{
                @"h/pid": @"hfr.m.y",
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
    
    // DON'T make read-only! Qt needs to READ the file.
    // Keep re-patching if Qt overwrites with dummydummy + keep deleting svp.lic
    NSString *licPath2 = [NSHomeDirectory() stringByAppendingPathComponent:
                          @"Library/Application Support/SVPlayer/settings/svp.lic"];
    for (int i = 1; i <= 60; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 500 * NSEC_PER_MSEC)), dispatch_get_global_queue(0, 0), ^{
            // Re-write fake svp.lic if Qt overwrote it
            NSData *licData = [NSData dataWithContentsOfFile:licPath2];
            if (!licData || licData.length != _globalReceipt.length) {
                // File missing or changed — re-write fake
                NSString *b64 = [_globalReceipt base64EncodedStringWithOptions:0];
                [b64 writeToFile:licPath2 atomically:YES encoding:NSUTF8StringEncoding error:nil];
                [_log appendFormat:@"[LIC] Re-wrote at %dms ✅\n", i*500];
            }
            
            // Re-patch main.cfg if dummydummy appeared
            NSData *d = [NSData dataWithContentsOfFile:cfgPath];
            if (d) {
                NSString *c = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (c && [c containsString:@"dummydummy"]) {
                    NSString *p = [c stringByReplacingOccurrencesOfString:@"\"dummydummy\""
                                                              withString:@"\"hfr.m.y\""];
                    [p writeToFile:cfgPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
                    [_log appendFormat:@"[CFG] Re-patched at %dms ✅\n", i*500];
                }
            }
        });
    }
    
    // INTERCEPT (don't block) svp-team.com API - LOG request + response
    {
        Method dm = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
        if (dm) {
            static IMP _orig_task = NULL;
            _orig_task = method_setImplementation(dm, imp_implementationWithBlock(
                ^NSURLSessionDataTask*(id self, NSURLRequest *request, void (^completion)(NSData*, NSURLResponse*, NSError*)) {
                    NSString *url = request.URL.absoluteString;
                    if ([url containsString:@"svp-team"] || [url containsString:@"svpteam"]) {
                        [_log appendFormat:@"[API] %@ %@\n", request.HTTPMethod, url];
                        
                        // Log request body
                        NSData *body = request.HTTPBody;
                        if (body) {
                            NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
                            if (bodyStr.length > 300) bodyStr = [bodyStr substringToIndex:300];
                            [_log appendFormat:@"[API-BODY] %@\n", bodyStr];
                        }
                        
                        // Log headers
                        NSDictionary *headers = request.allHTTPHeaderFields;
                        for (NSString *key in headers) {
                            [_log appendFormat:@"[API-HDR] %@: %@\n", key, headers[key]];
                        }
                        
                        [UIPasteboard generalPasteboard].string = _log;
                        
                        // Wrap completion to log response
                        void (^wrappedCompletion)(NSData*, NSURLResponse*, NSError*) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
                            if (err) {
                                [_log appendFormat:@"[API-ERR] %@\n", err.localizedDescription];
                            }
                            if (data) {
                                NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                                if (!respStr) respStr = [NSString stringWithFormat:@"<binary %lu bytes>", (unsigned long)data.length];
                                if (respStr.length > 500) respStr = [respStr substringToIndex:500];
                                [_log appendFormat:@"[API-RESP] %@\n", respStr];
                            }
                            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse*)resp;
                            if ([httpResp isKindOfClass:[NSHTTPURLResponse class]]) {
                                [_log appendFormat:@"[API-STATUS] %ld\n", (long)httpResp.statusCode];
                            }
                            [UIPasteboard generalPasteboard].string = _log;
                            
                            if (completion) completion(data, resp, err);
                        };
                        
                        // Let request go through with wrapped completion
                        return ((NSURLSessionDataTask*(*)(id, SEL, NSURLRequest*, id))_orig_task)(
                            self, @selector(dataTaskWithRequest:completionHandler:), request, wrappedCompletion);
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
                // Block svp.lic reads - force app to use receipt/config instead
                if ([path containsString:@"svp.lic"]) {
                    [_log appendFormat:@"[LIC-READ] BLOCKED svp.lic read ❌\n"];
                    [UIPasteboard generalPasteboard].string = _log;
                    return nil; // File not found
                }
                // Log SVPlayer file reads
                if ([path containsString:@"SVPlayer"] || [path containsString:@"svpteam"]) {
                    [_log appendFormat:@"[FILE-READ] %@\n", [path lastPathComponent]];
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
    
    // 5. IAP hooks + INJECT fake purchase
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
    
    // 5a. INJECT fake purchase after 6s (after IAP hooks are set)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        // Find the InAppPurchaseManager instance via SKPaymentQueue observers
        SKPaymentQueue *queue = [SKPaymentQueue defaultQueue];
        NSArray *observers = [queue performSelector:@selector(transactionObservers)
                                                     withObject:nil];
        id iapManager = nil;
        if (!observers || [observers count] == 0) {
            // Try via delegate
            @try {
                observers = [queue valueForKey:@"_observers"];
            } @catch(NSException *e) {}
        }
        
        for (id obs in observers) {
            if ([obs isKindOfClass:NSClassFromString(@"InAppPurchaseManager")]) {
                iapManager = obs;
                break;
            }
        }
        
        if (iapManager) {
            [_log appendFormat:@"[INJECT] Found IAP manager instance ✅\n"];
            
            _fakeState = YES;
            
            // Create a dynamic class that acts as SKPaymentTransaction
            static Class FakeTxClass = Nil;
            if (!FakeTxClass) {
                FakeTxClass = objc_allocateClassPair([NSObject class], "FakeTransaction", 0);
                
                // transactionState -> SKPaymentTransactionStateRestored (3)
                class_addMethod(FakeTxClass, @selector(transactionState), imp_implementationWithBlock(^NSInteger(id self) {
                    return 3; // SKPaymentTransactionStateRestored
                }), "q@:");
                
                // payment -> SKPayment with productIdentifier "hfr.m.y"
                class_addMethod(FakeTxClass, @selector(payment), imp_implementationWithBlock(^id(id self) {
                    SKMutablePayment *p = [[SKMutablePayment alloc] init];
                    [p setProductIdentifier:@"hfr.m.y"];
                    return p;
                }), "@@:");
                
                // transactionIdentifier
                class_addMethod(FakeTxClass, @selector(transactionIdentifier), imp_implementationWithBlock(^NSString*(id self) {
                    return @"FAKE_TX_200000099999";
                }), "@@:");
                
                // transactionDate
                class_addMethod(FakeTxClass, @selector(transactionDate), imp_implementationWithBlock(^NSDate*(id self) {
                    return [NSDate date];
                }), "@@:");
                
                // originalTransaction
                class_addMethod(FakeTxClass, @selector(originalTransaction), imp_implementationWithBlock(^id(id self) {
                    return nil;
                }), "@@:");
                
                // transactionReceipt (deprecated but some apps use it)
                class_addMethod(FakeTxClass, @selector(transactionReceipt), imp_implementationWithBlock(^NSData*(id self) {
                    return _globalReceipt;
                }), "@@:");
                
                // error
                class_addMethod(FakeTxClass, @selector(error), imp_implementationWithBlock(^id(id self) {
                    return nil;
                }), "@@:");
                
                objc_registerClassPair(FakeTxClass);
            }
            
            id fakeTx = [[FakeTxClass alloc] init];
            NSArray *txArray = @[fakeTx];
            
            @try {
                // Call the ORIGINAL (unhooked) updatedTransactions with our fake tx
                // This goes to InAppPurchaseManager's real handler -> C++ backend
                if (_orig_updated) {
                    ((void(*)(id, SEL, id, NSArray*))_orig_updated)(iapManager, 
                        @selector(paymentQueue:updatedTransactions:), queue, txArray);
                    [_log appendString:@"[INJECT] Called updatedTransactions with fake TX ✅\n"];
                } else {
                    // Hooks not set yet, call directly
                    [iapManager paymentQueue:queue updatedTransactions:txArray];
                    [_log appendString:@"[INJECT] Called updatedTransactions (direct) ✅\n"];
                }
            } @catch(NSException *e) {
                [_log appendFormat:@"[INJECT] update error: %@\n", e];
            }
            
            @try {
                if (_orig_restored) {
                    ((void(*)(id,SEL,id))_orig_restored)(iapManager,
                        @selector(paymentQueueRestoreCompletedTransactionsFinished:), queue);
                } else {
                    [iapManager paymentQueueRestoreCompletedTransactionsFinished:queue];
                }
                [_log appendString:@"[INJECT] Called restoreCompleted ✅\n"];
            } @catch(NSException *e) {
                [_log appendFormat:@"[INJECT] restore error: %@\n", e];
            }
            
            _fakeState = NO;
        } else {
            [_log appendFormat:@"[INJECT] IAP manager NOT found. Queue observers: %lu\n",
             (unsigned long)[observers count]];
            for (id obs in observers) {
                [_log appendFormat:@"  observer: %@\n", NSStringFromClass([obs class])];
            }
        }
        [UIPasteboard generalPasteboard].string = _log;
    });
    
    // 5c. Try SVP internal webui HTTP API (8s)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [_log appendString:@"\n=== SVP HTTP API PROBE ===\n"];
        
        // Read /tmp/svp-http for port info
        NSString *tmpHttp = @"/tmp/svp-http";
        NSData *httpData = [NSData dataWithContentsOfFile:tmpHttp];
        if (httpData) {
            NSString *httpStr = [[NSString alloc] initWithData:httpData encoding:NSUTF8StringEncoding];
            [_log appendFormat:@"[HTTP] /tmp/svp-http: %@\n", httpStr];
        }
        
        // Also check app container tmp
        NSString *appTmp = [NSHomeDirectory() stringByAppendingPathComponent:@"tmp/svp-http"];
        NSData *appHttpData = [NSData dataWithContentsOfFile:appTmp];
        if (appHttpData) {
            NSString *s = [[NSString alloc] initWithData:appHttpData encoding:NSUTF8StringEncoding];
            [_log appendFormat:@"[HTTP] app/tmp/svp-http: %@\n", s];
        }
        
        // Scan tmp for any svp files 
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *tmpFiles = [fm contentsOfDirectoryAtPath:@"/tmp" error:nil];
        for (NSString *f in tmpFiles) {
            if ([f containsString:@"svp"]) {
                NSString *content = [[NSString alloc] initWithContentsOfFile:[@"/tmp" stringByAppendingPathComponent:f]
                                                                   encoding:NSUTF8StringEncoding error:nil];
                [_log appendFormat:@"[TMP] %@ = %@\n", f, content ?: @"<binary>"];
            }
        }
        
        // Try common webui ports
        for (int port = 9000; port <= 9010; port++) {
            NSString *url = [NSString stringWithFormat:@"http://127.0.0.1:%d/r/reg", port];
            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]
                                                              cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                          timeoutInterval:1.0];
            req.HTTPMethod = @"POST";
            NSHTTPURLResponse *resp = nil;
            NSError *err = nil;
            NSData *data = [NSURLConnection sendSynchronousRequest:req returningResponse:&resp error:&err];
            if (data && resp.statusCode == 200) {
                NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                [_log appendFormat:@"[API] Port %d: %@\n", port, body];
                
                // Try to set h/pid via r/set-opt
                NSString *setUrl = [NSString stringWithFormat:@"http://127.0.0.1:%d/r/set-opt", port];
                NSMutableURLRequest *setReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:setUrl]];
                setReq.HTTPMethod = @"POST";
                NSString *postBody = @"n=h/pid&v=hfr.m.y";
                setReq.HTTPBody = [postBody dataUsingEncoding:NSUTF8StringEncoding];
                [setReq setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
                NSData *setData = [NSURLConnection sendSynchronousRequest:setReq returningResponse:&resp error:&err];
                if (setData) {
                    NSString *setBody = [[NSString alloc] initWithData:setData encoding:NSUTF8StringEncoding];
                    [_log appendFormat:@"[SET-OPT] Port %d: %@\n", port, setBody];
                }
                break;
            }
        }
        
        [UIPasteboard generalPasteboard].string = _log;
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSData *cfgData = [NSData dataWithContentsOfFile:cfgPath];
        if (cfgData) {
            NSString *cfgContent = [[NSString alloc] initWithData:cfgData encoding:NSUTF8StringEncoding];
            [_log appendFormat:@"\n=== main.cfg AFTER Qt (5s) ===\n%@\n", cfgContent ?: @"<binary>"];
        } else {
            [_log appendString:@"\n=== main.cfg AFTER Qt: NOT FOUND ===\n"];
        }
        [UIPasteboard generalPasteboard].string = _log;
    });
    
    // 6. DELAYED: dump UserDefaults + plist + full file scan (10s)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        // Dump NSUserDefaults
        [_log appendString:@"\n=== NSUserDefaults (10s) ===\n"];
        NSDictionary *defaults = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        for (NSString *key in [defaults.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            id val = defaults[key];
            NSString *valStr = [NSString stringWithFormat:@"%@", val];
            if (valStr.length > 80) valStr = [valStr substringToIndex:80];
            [_log appendFormat:@"  %@ = %@\n", key, valStr];
        }
        
        // Dump plist file directly 
        NSString *plistPath = [NSHomeDirectory() stringByAppendingPathComponent:
                               @"Library/Preferences/com.svpteam.svp.plist"];
        NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (plist) {
            [_log appendFormat:@"\n=== com.svpteam.svp.plist ===\n"];
            for (NSString *key in plist) {
                [_log appendFormat:@"  %@ = %@\n", key, plist[key]];
            }
        }
        
        // Dump FULL main.cfg
        NSString *cfgP = [NSHomeDirectory() stringByAppendingPathComponent:
                          @"Library/Application Support/SVPlayer/settings/main.cfg"];
        NSData *cfgD = [NSData dataWithContentsOfFile:cfgP];
        if (cfgD) {
            NSString *cfgStr = [[NSString alloc] initWithData:cfgD encoding:NSUTF8StringEncoding];
            [_log appendFormat:@"\n=== FULL main.cfg ===\n%@\n", cfgStr];
        }
        
        [UIPasteboard generalPasteboard].string = _log;
        
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
            
            // Read cfg/lic/ini/plist/LOG files
            NSString *lower = [item lowercaseString];
            if (([lower hasSuffix:@".cfg"] || [lower hasSuffix:@".lic"] || [lower hasSuffix:@".ini"] ||
                 [lower hasSuffix:@".plist"] || [lower hasSuffix:@".log"]) && sz < 5000 && sz > 0) {
                NSData *d = [NSData dataWithContentsOfFile:full];
                NSString *c = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (c) {
                    if (c.length > 500) c = [c substringToIndex:500];
                    [_log appendFormat:@"    ---\n%@\n    ---\n", c];
                }
            }
            total++;
        }
        [_log appendFormat:@"  (listed %d files)\n", total];
        
        // === RUNTIME LICENSE SCAN ===
        [_log appendString:@"\n=== ObjC Runtime Scan ===\n"];
        
        // Scan InAppPurchaseManager
        Class iapCls = NSClassFromString(@"InAppPurchaseManager");
        if (iapCls) {
            [_log appendString:@"InAppPurchaseManager:\n"];
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(iapCls, &mc);
            for (unsigned int i = 0; i < mc && i < 30; i++) {
                [_log appendFormat:@"  M: %s\n", sel_getName(method_getName(methods[i]))];
            }
            free(methods);
            
            unsigned int ic = 0;
            Ivar *ivars = class_copyIvarList(iapCls, &ic);
            for (unsigned int i = 0; i < ic; i++) {
                [_log appendFormat:@"  I: %s (%s)\n", ivar_getName(ivars[i]), ivar_getTypeEncoding(ivars[i])];
            }
            free(ivars);
            
            unsigned int pc = 0;
            objc_property_t *props = class_copyPropertyList(iapCls, &pc);
            for (unsigned int i = 0; i < pc; i++) {
                [_log appendFormat:@"  P: %s = %s\n", property_getName(props[i]),
                 property_getAttributes(props[i])];
            }
            free(props);
        }
        
        // === Qt Purchase Backend Scan ===
        [_log appendString:@"\n=== Qt Backend Scan ===\n"];
        unsigned int classCount = 0;
        Class *classes = objc_copyClassList(&classCount);
        for (unsigned int i = 0; i < classCount; i++) {
            const char *name = class_getName(classes[i]);
            NSString *cn = [NSString stringWithUTF8String:name];
            // Only Qt/SVP/IAP classes
            if (![cn containsString:@"AppStore"] && ![cn containsString:@"InApp"] &&
                ![cn hasPrefix:@"SVP"] && ![cn containsString:@"Product"] &&
                ![cn containsString:@"Backend"]) continue;
            // Skip Apple/system classes
            if ([cn hasPrefix:@"ASD"] || [cn hasPrefix:@"FC"] || [cn hasPrefix:@"Fig"] ||
                [cn hasPrefix:@"LA"] || [cn hasPrefix:@"LS"] || [cn hasPrefix:@"BY"] ||
                [cn hasPrefix:@"Cloud"] || [cn hasPrefix:@"Network"] ||
                [cn hasPrefix:@"Sensitive"] || [cn hasPrefix:@"Managed"] ||
                [cn hasPrefix:@"_Tt"] || [cn hasPrefix:@"StoreKit"]) continue;
            
            [_log appendFormat:@"\n  CLASS: %@\n", cn];
            unsigned int pc = 0;
            objc_property_t *props = class_copyPropertyList(classes[i], &pc);
            for (unsigned int j = 0; j < pc; j++) {
                [_log appendFormat:@"    P: %s = %s\n", property_getName(props[j]),
                 property_getAttributes(props[j])];
            }
            free(props);
            
            unsigned int mc2 = 0;
            Method *methods2 = class_copyMethodList(classes[i], &mc2);
            for (unsigned int j = 0; j < mc2; j++) {
                [_log appendFormat:@"    M: %s\n", sel_getName(method_getName(methods2[j]))];
            }
            free(methods2);
            
            unsigned int ic2 = 0;
            Ivar *ivars2 = class_copyIvarList(classes[i], &ic2);
            for (unsigned int j = 0; j < ic2; j++) {
                [_log appendFormat:@"    I: %s (%s)\n", ivar_getName(ivars2[j]),
                 ivar_getTypeEncoding(ivars2[j])];
            }
            free(ivars2);
        }
        free(classes);
        
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
