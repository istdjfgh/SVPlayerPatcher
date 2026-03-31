"""
Cheat Engine v5 - Numpy-accelerated memory scanner.
memdump.sh v2: single .bin + .idx file.
Loading: 0.05s (numpy), comparison: 0.005s.
Total scan cycle: ~5s (freeze 2s + pull 1s + load 0.05s).

Usage: just run scan.bat, then type commands.
"""
import subprocess
import struct
import sys
import os
import time
import base64
import numpy as np

ADB = r'C:\adb\platform-tools\adb.exe'
LIBG_BASE = 0x53c0000
LIBG_SIZE = 0x1200000
LOCAL_DIR = r'D:\brawl\BrawlStrars_Mod\ce_snapshots'
DEVICE_SCRIPT = '/data/local/tmp/memdump.sh'
DEVICE_BINARY = '/data/local/tmp/memdump'  # native binary (preferred)
DEVICE_SNAP_DIR = '/data/local/tmp'
SCRIPT_SRC = os.path.join(os.path.dirname(__file__), 'memdump.sh')
BINARY_SRC = os.path.join(os.path.dirname(__file__), 'memdump')  # compiled binary

use_native = False  # set True when native binary is available


class Snapshot:
    """Memory snapshot backed by numpy arrays."""
    __slots__ = ('addrs', 'vals', 'raw', 'regions')

    def __init__(self, addrs, vals, raw, regions):
        self.addrs = addrs      # int64 array of addresses
        self.vals = vals        # int32 array of values
        self.raw = raw          # raw bytes (for context reads)
        self.regions = regions  # [(base_addr, size, file_off), ...]


class CandidateSet:
    """Surviving candidates backed by numpy arrays."""
    __slots__ = ('addrs', 'vals')

    def __init__(self, addrs, vals):
        self.addrs = addrs  # int64
        self.vals = vals    # int32

    def __len__(self):
        return len(self.addrs)


def adb(*args):
    r = subprocess.run([ADB] + list(args), capture_output=True, timeout=300)
    return r.stdout.decode('utf-8', errors='replace').strip()


def adb_raw(*args):
    return subprocess.run([ADB] + list(args), capture_output=True, timeout=300)


def get_pid():
    out = adb('shell', "su -c 'pidof com.supercell.brawlstars'")
    try:
        return int(out.strip())
    except ValueError:
        return 0


def push_dumper():
    """Push memdump binary or shell script to device."""
    global use_native
    
    # Try native binary first
    if os.path.exists(BINARY_SRC):
        with open(BINARY_SRC, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode()
        # Split into chunks if too large for single echo
        chunk_size = 65000
        if len(b64) <= chunk_size:
            adb('shell', f"su -c 'echo {b64} | base64 -d > {DEVICE_BINARY} && chmod 755 {DEVICE_BINARY}'")
        else:
            adb('shell', f"su -c 'rm -f {DEVICE_BINARY}'")
            for i in range(0, len(b64), chunk_size):
                chunk = b64[i:i+chunk_size]
                adb('shell', f"su -c 'echo {chunk} | base64 -d >> {DEVICE_BINARY}'")
            adb('shell', f"su -c 'chmod 755 {DEVICE_BINARY}'")
        # Verify
        out = adb('shell', f"su -c 'file {DEVICE_BINARY} 2>/dev/null || echo unknown'")
        if 'ELF' in out or 'executable' in out:
            use_native = True
            print(f"  Pushed native memdump ({len(data)} bytes)")
            return
        else:
            print(f"  Native binary push failed ({out}), falling back to shell")
    
    # Fallback to shell script
    with open(SCRIPT_SRC, 'rb') as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()
    adb('shell', f"su -c 'echo {b64} | base64 -d > {DEVICE_SCRIPT} && chmod 755 {DEVICE_SCRIPT}'")
    use_native = False
    print(f"  Pushed memdump.sh (shell fallback)")


def take_and_pull(pid, slot):
    """Take snapshot on device, pull to local. Returns (local_bin, local_idx)."""
    dev_bin = f'{DEVICE_SNAP_DIR}/snap_{slot}.bin'
    dev_idx = f'{dev_bin}.idx'
    local_bin = os.path.join(LOCAL_DIR, f'{slot}.bin')
    local_idx = os.path.join(LOCAL_DIR, f'{slot}.idx')

    t0 = time.time()
    if use_native:
        out = adb('shell', f"su -c '{DEVICE_BINARY} {pid} {dev_bin}'")
    else:
        out = adb('shell', f"su -c 'sh {DEVICE_SCRIPT} {pid} {dev_bin}'")
    t_dump = time.time() - t0

    t1 = time.time()
    adb_raw('pull', dev_bin, local_bin)
    adb_raw('pull', dev_idx, local_idx)
    t_pull = time.time() - t1

    sz = os.path.getsize(local_bin) if os.path.exists(local_bin) else 0
    print(f"  {out}")
    print(f"  dump={t_dump:.1f}s pull={t_pull:.1f}s ({sz/1048576:.0f}MB)")
    return local_bin, local_idx


def load_snapshot(local_bin, local_idx):
    """Load snapshot into numpy arrays. ~0.05s for 63MB."""
    if not os.path.exists(local_bin) or not os.path.exists(local_idx):
        print("  ERROR: files missing")
        return None

    with open(local_bin, 'rb') as f:
        raw = f.read()

    regions = []
    with open(local_idx) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            regions.append((int(parts[0], 16), int(parts[1]), int(parts[2])))

    all_vals = np.frombuffer(raw, dtype=np.int32)

    # Build address array
    total = sum(s // 4 for _, s, _ in regions)
    all_addrs = np.empty(total, dtype=np.int64)
    pos = 0
    for base_addr, size, file_off in regions:
        n = size // 4
        all_addrs[pos:pos + n] = np.arange(base_addr, base_addr + n * 4, 4, dtype=np.int64)
        pos += n

    return Snapshot(all_addrs[:pos], all_vals[:pos], raw, regions)


def snap_exact(snap, value):
    """Find all addresses with exact int32 value."""
    mask = snap.vals == np.int32(value)
    return CandidateSet(snap.addrs[mask].copy(), snap.vals[mask].copy())


def snap_float_range(snap, fmin, fmax):
    """Find addresses with float values in range."""
    fvals = snap.vals.view(np.float32)
    mask = (fvals >= fmin) & (fvals <= fmax) & np.isfinite(fvals)
    return CandidateSet(snap.addrs[mask].copy(), snap.vals[mask].copy())


def filter_candidates(cands, snap, mode):
    """Filter candidates against new snapshot using vectorized comparison."""
    # Find candidate addresses in new snapshot via sorted merge
    # Both arrays should be sorted (addrs from sequential memory regions = sorted)
    # Use np.searchsorted for O(n log n) matching

    idx_in_snap = np.searchsorted(snap.addrs, cands.addrs)
    # Clip to valid range
    idx_in_snap = np.clip(idx_in_snap, 0, len(snap.addrs) - 1)
    # Verify actual match
    valid = snap.addrs[idx_in_snap] == cands.addrs

    old_vals = cands.vals[valid]
    new_vals = snap.vals[idx_in_snap[valid]]
    matched_addrs = cands.addrs[valid]

    if mode == 'c':
        mask = new_vals != old_vals
    elif mode == 'u':
        mask = new_vals == old_vals
    elif mode == '+':
        mask = new_vals > old_vals
    elif mode == '-':
        mask = new_vals < old_vals
    else:
        return CandidateSet(matched_addrs, new_vals)

    return CandidateSet(matched_addrs[mask].copy(), new_vals[mask].copy())


def filter_exact(cands, snap, value):
    """Filter candidates for exact value from new snapshot."""
    idx_in_snap = np.searchsorted(snap.addrs, cands.addrs)
    idx_in_snap = np.clip(idx_in_snap, 0, len(snap.addrs) - 1)
    valid = snap.addrs[idx_in_snap] == cands.addrs
    new_vals = snap.vals[idx_in_snap[valid]]
    matched_addrs = cands.addrs[valid]
    mask = new_vals == np.int32(value)
    return CandidateSet(matched_addrs[mask].copy(), new_vals[mask].copy())


def refresh_candidates(cands, snap):
    """Update candidate values from new snapshot."""
    idx_in_snap = np.searchsorted(snap.addrs, cands.addrs)
    idx_in_snap = np.clip(idx_in_snap, 0, len(snap.addrs) - 1)
    valid = snap.addrs[idx_in_snap] == cands.addrs
    new_vals = np.zeros_like(cands.vals)
    new_vals[valid] = snap.vals[idx_in_snap[valid]]
    return CandidateSet(cands.addrs[valid].copy(), snap.vals[idx_in_snap[valid]].copy())


def show_results(cands, max_show=30):
    n = min(len(cands), max_show)
    for i in range(n):
        addr = int(cands.addrs[i])
        val = int(cands.vals[i])
        f32 = struct.unpack('<f', struct.pack('<i', val))[0]
        tag = ""
        if LIBG_BASE <= addr < LIBG_BASE + LIBG_SIZE:
            tag = f" [libg+0x{addr - LIBG_BASE:x}]"
        fstr = ""
        if 0.001 < abs(f32) < 1e6 and f32 == f32:
            fstr = f" f={f32:.3f}"
        print(f"  0x{addr:08x} = {val:12d}{fstr}{tag}")
    if len(cands) > max_show:
        print(f"  ... and {len(cands) - max_show} more")


def show_context(snap, cands, count=10, window=96):
    """Show memory context around candidate addresses."""
    # Build quick lookup: addr -> index in snap
    # For few addresses, binary search is fine
    n = min(len(cands), count)
    for i in range(n):
        addr = int(cands.addrs[i])
        print(f"\n  --- 0x{addr:08x} ---")

        for off in range(-window, window + 4, 4):
            check = addr + off
            idx = np.searchsorted(snap.addrs, check)
            if idx >= len(snap.addrs) or int(snap.addrs[idx]) != check:
                continue
            val = int(snap.vals[idx])
            f32 = struct.unpack('<f', struct.pack('<i', val))[0]
            marker = "  <<<" if off == 0 else ""
            fstr = ""
            if 0.001 < abs(f32) < 1e6 and f32 == f32:
                fstr = f"  (f={f32:.3f})"
            ptr_tag = ""
            if LIBG_BASE <= val < LIBG_BASE + LIBG_SIZE:
                ptr_tag = f"  [->libg+0x{val - LIBG_BASE:x}]"
            elif 0x05000000 <= val <= 0x7F000000:
                ptr_tag = f"  [->0x{val:x}]"
            print(f"    {off:+5d}: 0x{val & 0xFFFFFFFF:08x} {val:12d}{fstr}{ptr_tag}{marker}")


def write_memory(pid, addr, value):
    """Write int32 to game memory."""
    data_bytes = struct.pack('<i', value)
    hex_str = ''.join(f'\\x{b:02x}' for b in data_bytes)
    adb('shell', f"su -c 'printf \"{hex_str}\" | dd of=/proc/{pid}/mem bs=1 seek={addr} conv=notrunc 2>/dev/null'")
    print(f"  Wrote {value} to 0x{addr:08x}")


def main():
    os.makedirs(LOCAL_DIR, exist_ok=True)

    pid = get_pid()
    if not pid:
        print("Brawl Stars not running!")
        return
    print(f"Brawl Stars PID: {pid}")

    push_dumper()

    print()
    print("=== MEMORY SCANNER v5 (numpy, ~5s/scan) ===")
    print()
    print("Commands:")
    print("  <int>        exact int32 scan/filter")
    print("  f<min>:<max> float range (e.g. f100:500)")
    print("  c/u/+/-      changed/unchanged/increased/decreased")
    print("  ctx          context around results (up to 50)")
    print("  w            watch (refresh values)")
    print("  wr <addr> <val>  write int32")
    print("  r            reset")
    print("  q            quit")
    print()

    candidates = None      # CandidateSet or None
    last_snap = None        # Snapshot
    snap_slot = 'a'
    scan_num = 0

    while True:
        if candidates is not None:
            prompt = f"[{len(candidates)} addr] > "
        else:
            prompt = "> "

        try:
            inp = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not inp:
            continue
        if inp == 'q':
            break
        if inp == 'r':
            candidates = None
            last_snap = None
            scan_num = 0
            print("  Reset.")
            continue

        if inp == 'ctx':
            if candidates and last_snap and len(candidates) <= 50:
                show_context(last_snap, candidates)
            elif candidates:
                print(f"  Too many ({len(candidates)}), narrow first")
            else:
                print("  No scan yet")
            continue

        if inp.startswith('wr '):
            parts = inp.split()
            if len(parts) == 3:
                try:
                    w_addr = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1])
                    w_val = int(parts[2])
                    write_memory(pid, w_addr, w_val)
                except ValueError:
                    print("  Usage: wr 0xADDR value")
            else:
                print("  Usage: wr 0xADDR value")
            continue

        # Check PID
        new_pid = get_pid()
        if new_pid != pid:
            if new_pid:
                print(f"  PID changed {pid}->{new_pid}, reset")
                pid = new_pid
                candidates = None
                last_snap = None
                scan_num = 0
            else:
                print("  Game not running!")
            continue

        # Take snapshot
        scan_num += 1
        snap_slot = 'a' if snap_slot == 'b' else 'b'

        print(f"  [Scan #{scan_num}]")
        t0 = time.time()

        local_bin, local_idx = take_and_pull(pid, snap_slot)

        t_load = time.time()
        new_snap = load_snapshot(local_bin, local_idx)
        if new_snap is None:
            print("  Failed to load snapshot")
            continue
        t_loaded = time.time()
        print(f"  load={t_loaded - t_load:.3f}s ({len(new_snap.vals)} vals)")

        # Watch
        if inp == 'w':
            if candidates:
                candidates = refresh_candidates(candidates, new_snap)
                show_results(candidates)
            last_snap = new_snap
            dt = time.time() - t0
            print(f"  total={dt:.1f}s")
            continue

        # Float range
        if inp.startswith('f') and ':' in inp:
            try:
                fparts = inp[1:].split(':')
                fmin, fmax = float(fparts[0]), float(fparts[1])
            except ValueError:
                print(f"  Bad float range: {inp}")
                continue

            if candidates is None:
                candidates = snap_float_range(new_snap, fmin, fmax)
                print(f"  Float [{fmin}, {fmax}]: {len(candidates)}")
            else:
                # Filter existing candidates
                candidates = refresh_candidates(candidates, new_snap)
                fvals = candidates.vals.view(np.float32)
                mask = (fvals >= fmin) & (fvals <= fmax) & np.isfinite(fvals)
                candidates = CandidateSet(candidates.addrs[mask].copy(), candidates.vals[mask].copy())
                print(f"  Float filter: {len(candidates)}")

            last_snap = new_snap
            if len(candidates) <= 30:
                show_results(candidates)
            dt = time.time() - t0
            print(f"  total={dt:.1f}s")
            continue

        # Compare modes
        if inp in ('c', 'u', '+', '-'):
            if last_snap is None:
                last_snap = new_snap
                candidates = CandidateSet(new_snap.addrs.copy(), new_snap.vals.copy())
                print(f"  Initial snapshot ({len(candidates)} values)")
                print(f"  Now change something in game, then: c/u/+/-")
                dt = time.time() - t0
                print(f"  total={dt:.1f}s")
                continue

            prev_count = len(candidates) if candidates else len(last_snap.vals)

            if candidates is None:
                # First filter from full snap
                old_snap_as_cands = CandidateSet(last_snap.addrs.copy(), last_snap.vals.copy())
                candidates = filter_candidates(old_snap_as_cands, new_snap, inp)
            else:
                candidates = filter_candidates(candidates, new_snap, inp)

            last_snap = new_snap
            mode_name = {'c': 'changed', 'u': 'unchanged', '+': 'increased', '-': 'decreased'}[inp]
            print(f"  {mode_name}: {prev_count} -> {len(candidates)}")

        else:
            # Exact value
            try:
                value = int(inp)
            except ValueError:
                print(f"  Unknown: {inp}")
                continue

            if candidates is None:
                candidates = snap_exact(new_snap, value)
                print(f"  Found {len(candidates)} with value {value}")
            else:
                prev = len(candidates)
                candidates = filter_exact(candidates, new_snap, value)
                print(f"  {prev} -> {len(candidates)}")

            last_snap = new_snap

        # Auto-show
        if candidates and len(candidates) <= 30:
            show_results(candidates)
        if candidates and len(candidates) <= 5:
            print("  -> 'ctx' for context, 'w' to watch, 'wr' to write")

        dt = time.time() - t0
        print(f"  total={dt:.1f}s")


if __name__ == '__main__':
    main()
