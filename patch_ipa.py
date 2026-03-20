#!/usr/bin/env python3
"""
SVPlayer IPA Patcher v2
1. Patches PKCS7_verify + X509_verify_cert + CMS_verify in libmpv -> return 1
2. Generates fake Apple receipt containing product 'unlock0'
3. Injects receipt into IPA
Usage: python patch_ipa.py SVPlayer.ipa
"""

import sys, os, struct, shutil, zipfile, tempfile

MOV_W0_1 = bytes([0x20, 0x00, 0x80, 0x52])
RET      = bytes([0xC0, 0x03, 0x5F, 0xD6])

# =======================================
# ASN.1 DER builder for fake receipt
# =======================================

def asn1_len(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, length >> 8, length & 0xFF])
    else:
        return bytes([0x83, length >> 16, (length >> 8) & 0xFF, length & 0xFF])

def asn1_tag(tag, content):
    return bytes([tag]) + asn1_len(len(content)) + content

def asn1_seq(content):
    return asn1_tag(0x30, content)

def asn1_set(content):
    return asn1_tag(0x31, content)

def asn1_int(val):
    if val < 0x80:
        return asn1_tag(0x02, bytes([val]))
    elif val < 0x100:
        return asn1_tag(0x02, bytes([0x00, val]))
    else:
        b = val.to_bytes((val.bit_length() + 8) // 8, 'big')
        return asn1_tag(0x02, b)

def asn1_octet(content):
    return asn1_tag(0x04, content)

def asn1_utf8(s):
    return asn1_tag(0x0C, s.encode('utf-8'))

def asn1_ia5(s):
    return asn1_tag(0x16, s.encode('ascii'))

def asn1_oid(vals):
    """Encode OID - first two values combined: 40*v1+v2, rest base-128"""
    result = bytes([40 * vals[0] + vals[1]])
    for v in vals[2:]:
        if v < 0x80:
            result += bytes([v])
        elif v < 0x4000:
            result += bytes([0x80 | (v >> 7), v & 0x7F])
        else:
            parts = []
            while v > 0:
                parts.append(v & 0x7F)
                v >>= 7
            parts.reverse()
            for i in range(len(parts) - 1):
                parts[i] |= 0x80
            result += bytes(parts)
    return asn1_tag(0x06, result)

def asn1_context(tag_num, content, constructed=True):
    tag = 0xA0 | tag_num if constructed else 0x80 | tag_num
    return asn1_tag(tag, content)

def receipt_attr(attr_type, value_bytes):
    """Apple receipt attribute: SEQUENCE { INTEGER type, INTEGER 1, OCTET_STRING value }"""
    return asn1_seq(
        asn1_int(attr_type) +
        asn1_int(1) +
        asn1_octet(value_bytes)
    )

def iap_attr(attr_type, value_bytes):
    """IAP receipt attribute"""
    return asn1_seq(
        asn1_int(attr_type) +
        asn1_int(1) +
        asn1_octet(value_bytes)
    )

def build_fake_receipt(bundle_id="hfr.m.svplayer", product_id="unlock0"):
    """Build a minimal PKCS7 SignedData containing a fake Apple receipt"""
    
    # In-App Purchase receipt (attribute type 17)
    iap_set = asn1_set(
        iap_attr(1701, asn1_int(1)) +                           # quantity = 1
        iap_attr(1702, asn1_utf8(product_id)) +                 # product_id
        iap_attr(1703, asn1_utf8("2000000845671234")) +          # transaction_id
        iap_attr(1704, asn1_ia5("2025-01-15T10:00:00Z")) +      # purchase_date
        iap_attr(1705, asn1_utf8("2000000845671234")) +          # orig_transaction_id
        iap_attr(1706, asn1_ia5("2025-01-15T10:00:00Z"))        # orig_purchase_date
    )
    
    # Also add subscription product
    iap_set2 = asn1_set(
        iap_attr(1701, asn1_int(1)) +
        iap_attr(1702, asn1_utf8("hfr.m.y")) +
        iap_attr(1703, asn1_utf8("2000000845671235")) +
        iap_attr(1704, asn1_ia5("2025-01-15T10:00:00Z")) +
        iap_attr(1705, asn1_utf8("2000000845671235")) +
        iap_attr(1706, asn1_ia5("2025-01-15T10:00:00Z")) +
        iap_attr(1708, asn1_ia5("2099-12-31T23:59:59Z"))  # expires_date (far future)
    )
    
    # Main receipt payload
    receipt_payload = asn1_set(
        receipt_attr(2, asn1_utf8(bundle_id)) +           # bundle_id
        receipt_attr(3, asn1_utf8("1.8.0")) +             # app_version
        receipt_attr(4, asn1_octet(b'\x00' * 16)) +       # opaque_value
        receipt_attr(5, asn1_octet(b'\x00' * 20)) +       # sha1_hash
        receipt_attr(12, asn1_ia5("2025-01-15T10:00:00Z")) + # receipt_creation_date
        receipt_attr(17, iap_set) +                        # in_app_purchase (unlock0)
        receipt_attr(17, iap_set2) +                       # in_app_purchase (hfr.m.y)
        receipt_attr(19, asn1_utf8("1.0"))                 # original_app_version
    )
    
    # OIDs
    oid_signed_data = asn1_oid([1, 2, 840, 113549, 1, 7, 2])
    oid_data = asn1_oid([1, 2, 840, 113549, 1, 7, 1])
    oid_sha256 = asn1_oid([2, 16, 840, 1, 101, 3, 4, 2, 1])
    
    # SignedData content
    signed_data = asn1_seq(
        asn1_int(1) +                              # version
        asn1_set(asn1_seq(oid_sha256)) +           # digestAlgorithms
        asn1_seq(                                   # contentInfo
            oid_data +
            asn1_context(0, asn1_octet(receipt_payload))
        ) +
        asn1_set(b'')                              # signerInfos (empty - patched verify)
    )
    
    # PKCS7 wrapper
    pkcs7 = asn1_seq(
        oid_signed_data +
        asn1_context(0, signed_data)
    )
    
    return pkcs7

# =======================================
# Mach-O symbol finder
# =======================================

def find_symbol_in_macho(data, base_offset, symbol_name):
    magic = struct.unpack_from('<I', data, base_offset)[0]
    if magic != 0xFEEDFACF:
        return None
    
    ncmds = struct.unpack_from('<I', data, base_offset + 16)[0]
    symtab_cmd = None
    segments = []
    
    cmd_offset = base_offset + 32
    for _ in range(ncmds):
        cmd = struct.unpack_from('<I', data, cmd_offset)[0]
        cmdsize = struct.unpack_from('<I', data, cmd_offset + 4)[0]
        
        if cmd == 2:
            symtab_cmd = {
                'symoff': base_offset + struct.unpack_from('<I', data, cmd_offset + 8)[0],
                'nsyms': struct.unpack_from('<I', data, cmd_offset + 12)[0],
                'stroff': base_offset + struct.unpack_from('<I', data, cmd_offset + 16)[0],
            }
        elif cmd == 25:
            segname = data[cmd_offset+8:cmd_offset+24].split(b'\x00')[0].decode()
            vmaddr = struct.unpack_from('<Q', data, cmd_offset + 24)[0]
            vmsize = struct.unpack_from('<Q', data, cmd_offset + 32)[0]
            fileoff = struct.unpack_from('<Q', data, cmd_offset + 40)[0]
            segments.append({'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                           'fileoff': base_offset + fileoff})
        cmd_offset += cmdsize
    
    if not symtab_cmd:
        return None
    
    for i in range(symtab_cmd['nsyms']):
        so = symtab_cmd['symoff'] + i * 16
        n_strx = struct.unpack_from('<I', data, so)[0]
        n_value = struct.unpack_from('<Q', data, so + 8)[0]
        if n_value == 0: continue
        
        str_off = symtab_cmd['stroff'] + n_strx
        try:
            end = data.index(b'\x00', str_off)
            name = data[str_off:end]
        except ValueError:
            continue
        
        if name == b'_' + symbol_name.encode():
            for seg in segments:
                if seg['vmaddr'] <= n_value < seg['vmaddr'] + seg['vmsize']:
                    return seg['fileoff'] + (n_value - seg['vmaddr'])
            return None
    return None

def find_symbol_offset(data, symbol_name):
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic == 0xFEEDFACF:
        return find_symbol_in_macho(data, 0, symbol_name)
    elif magic == 0xBEBAFECA:
        nfat = struct.unpack_from('>I', data, 4)[0]
        for i in range(nfat):
            off = 8 + i * 20
            cpu_type = struct.unpack_from('>I', data, off)[0]
            f_offset = struct.unpack_from('>I', data, off + 8)[0]
            if cpu_type == 0x0100000C:
                r = find_symbol_in_macho(data, f_offset, symbol_name)
                if r is not None: return r
    return None

# =======================================
# Main patcher
# =======================================

def patch_ipa(ipa_path):
    print("=== SVPlayer IPA Patcher v2 ===")
    base = os.path.splitext(ipa_path)[0]
    out_path = base + "_patched.ipa"
    tmpdir = tempfile.mkdtemp(prefix="svp_")
    
    try:
        print("Extracting...")
        with zipfile.ZipFile(ipa_path, 'r') as z:
            z.extractall(tmpdir)
        
        # Find app dir and libmpv
        app_dir = None
        libmpv_path = None
        for root, dirs, files in os.walk(tmpdir):
            for d in dirs:
                if d.endswith('.app'):
                    app_dir = os.path.join(root, d)
            for f in files:
                full = os.path.join(root, f)
                if ('libmpv' in f) and 'Frameworks' in full:
                    libmpv_path = full
        
        if not libmpv_path:
            print("ERROR: libmpv not found!")
            return False
        
        print(f"App: {app_dir}")
        print(f"libmpv: {libmpv_path}")
        
        # ===== PATCH 1: Binary patch libmpv =====
        with open(libmpv_path, 'rb') as f:
            data = bytearray(f.read())
        
        symbols = [
            'PKCS7_verify', 'X509_verify_cert', 'CMS_verify', 'CMS_verify_receipt',
            'RSA_verify', 'EVP_VerifyFinal', 'EVP_DigestVerifyFinal',
            'ECDSA_verify', 'DSA_verify', 'CMS_SignerInfo_verify',
            'ASN1_item_verify', 'ASN1_verify',
        ]
        patched = 0
        for sym in symbols:
            offset = find_symbol_offset(data, sym)
            if offset is not None:
                print(f"  PATCH {sym} @ 0x{offset:X}")
                data[offset:offset+4] = MOV_W0_1
                data[offset+4:offset+8] = RET
                patched += 1
            else:
                print(f"  skip {sym} (not found)")
        
        with open(libmpv_path, 'wb') as f:
            f.write(data)
        print(f"Patched {patched} crypto functions")
        
        # ===== PATCH 1b: String patch "dummydummy" in libmpv =====
        dummy_bytes = b'dummydummy'
        replace_bytes = b'unlock0\x00\x00\x00'  # same length (10 bytes)
        count = data.count(dummy_bytes)
        if count > 0:
            data2 = bytes(data).replace(dummy_bytes, replace_bytes)
            with open(libmpv_path, 'wb') as f:
                f.write(data2)
            print(f"  String-patched 'dummydummy' x{count} in libmpv")
        
        # ===== PATCH 1c: String patch "dummydummy" in main binary =====
        if app_dir:
            main_bin = None
            for item in os.listdir(app_dir):
                full = os.path.join(app_dir, item)
                if os.path.isfile(full) and not item.endswith('.dylib') and not item.endswith('.plist'):
                    with open(full, 'rb') as f:
                        magic = f.read(4)
                    if magic in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xcf\xfa\xed\xfe'):
                        main_bin = full
                        break
            
            if main_bin:
                with open(main_bin, 'rb') as f:
                    main_data = bytearray(f.read())
                count2 = main_data.count(dummy_bytes)
                if count2 > 0:
                    main_data2 = bytes(main_data).replace(dummy_bytes, replace_bytes)
                    with open(main_bin, 'wb') as f:
                        f.write(main_data2)
                    print(f"  String-patched 'dummydummy' x{count2} in {os.path.basename(main_bin)}")
        
        # ===== PATCH 2: Remove _CodeSignature from libmpv framework =====
        # So signing tool will re-sign the modified binary
        libmpv_framework = os.path.dirname(libmpv_path)
        codesig_dir = os.path.join(libmpv_framework, "_CodeSignature")
        if os.path.exists(codesig_dir):
            shutil.rmtree(codesig_dir)
            print("Removed libmpv _CodeSignature (will be re-signed)")
        
        # Also remove any other framework _CodeSignature that might reference libmpv
        if app_dir:
            frameworks_dir = os.path.join(app_dir, "Frameworks")
            if os.path.exists(frameworks_dir):
                for item in os.listdir(frameworks_dir):
                    cs = os.path.join(frameworks_dir, item, "_CodeSignature")
                    if os.path.exists(cs):
                        shutil.rmtree(cs)
                        print(f"Removed {item}/_CodeSignature")
            
            # Remove app-level _CodeSignature too
            app_cs = os.path.join(app_dir, "_CodeSignature")
            if os.path.exists(app_cs):
                shutil.rmtree(app_cs)
                print("Removed app _CodeSignature")
        
        # ===== REPACK =====
        print(f"Repacking...")
        if os.path.exists(out_path):
            os.remove(out_path)
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as z:
            for root, dirs, files in os.walk(tmpdir):
                for f in files:
                    full = os.path.join(root, f)
                    arcname = os.path.relpath(full, tmpdir)
                    z.write(full, arcname)
        
        print(f"\n=== DONE ===")
        print(f"Output: {out_path}")
        print(f"Sign with ESign/GBox - it will re-sign all binaries!")
        return True
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} SVPlayer.ipa")
        sys.exit(1)
    if not os.path.exists(sys.argv[1]):
        print(f"File not found: {sys.argv[1]}")
        sys.exit(1)
    patch_ipa(sys.argv[1])
