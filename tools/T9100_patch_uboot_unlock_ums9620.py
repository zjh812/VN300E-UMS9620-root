#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T9100_patch_uboot_unlock_ums9620.py
===================================

OFFLINE ONLY.  Generates a signature-preserving (magic64) unlocked-boot U-Boot
image for the UNISOC UMS9620 / T9100 (product Mario_12_2_5G, model VN300E)
from the *stock* uboot_b backup.

This tool NEVER:
  * modifies the input file            (opened "rb" only)
  * modifies the official UnisocBypass repository (bytecode writing disabled)
  * re-signs / regenerates any signature
  * connects to, flashes, or writes to any device
  * touches splloader / miscdata / vbmeta

What it does
------------
1.  Requires the input to be a DHTB image.
2.  Requires the input SHA256 to equal the pinned T9100 stock hash.
3.  Strictly verifies all 4 patch points (exact 32-bit word, at the exact
    file offset = 0x200 + code offset).  Any mismatch aborts.
4.  Delegates the actual packing to the official repository implementation
    `tools/magic_pack_ums9620.py` -> pack(), which keeps the signed DHTB
    payload byte-for-byte and appends the magic64 relocation+patch shellcode
    plus a patch table.
5.  Writes a NEW output file; the input is never touched.

Derived LOAD_BASE for THIS build
--------------------------------
    0xB5000000

Derived (not copied from the upstream default) from this device's own
`uboot_log` partition:

    sprd_get_vboot_key(): load_buf is 0x0xb4fffe00.        <- image base
    sprd_get_vboot_key(): sechdr_addr is 0x0xb5171630.     <- 0xb4fffe00+0x171830
    sprd_get_vboot_key(): cert_addr: 0xb5171690.           <- sechdr + 0x60
    sysdump-uboot: addr is 0xb5000000, size is 0x1000000   <- U-Boot region base

0xb4fffe00 + 0x200 (DHTB header) = 0xb5000000.  Corroborated by 1115 aligned
absolute 64-bit pointers inside the stock payload that all land in
0xb5000000..0xb5171630 (see T9100_check_magic64.py --load-base-report).

Usage
-----
    python T9100_patch_uboot_unlock_ums9620.py
    python T9100_patch_uboot_unlock_ums9620.py --input  <stock.img>
    python T9100_patch_uboot_unlock_ums9620.py --output <out.img>
    python T9100_patch_uboot_unlock_ums9620.py --dry-run

Exit codes
----------
    0  success
    1  a patch point did not match (image is not the expected stock build)
    2  structural error / bad SHA256 / bad input
"""

import argparse
import hashlib
import os
import struct
import sys

# --- never write .pyc into the official repository -------------------------
sys.dont_write_bytecode = True

REPO_TOOLS = r"C:\Users\admin\Desktop\B\T9100\UnisocBypass-main\tools"
if REPO_TOOLS not in sys.path:
    sys.path.insert(0, REPO_TOOLS)
try:
    import magic_pack_ums9620 as MP
except ImportError as e:  # pragma: no cover
    sys.exit(f"cannot import magic_pack_ums9620 from {REPO_TOOLS}: {e}")

# ---------------------------------------------------------------- constants
DEFAULT_INPUT = r"C:\Users\admin\Desktop\B\T9100\backup\T9100_back\uboot_b.bin"
DEFAULT_OUTPUT = "T9100_uboot_b_unlock_magic64.img"

STOCK_SHA256 = "5935075bed5b12d35b961d0e39a4e95154b8cfb94ac177f96919700a24b8e321"
PARTITION_SIZE = 0x300000
DHTB_HDR = 0x200

NOP = 0xD503201F

# LOAD_BASE derived from this device's uboot_log (see module docstring).
LOAD_BASE = 0xB5000000
LOAD_BASE_SOURCE = "derived from this device's uboot_log partition"

# (code_off, expected_stock_word, description)
PATCH_POINTS = [
    (0x62830, 0x350002A0, "get_lock_status(): cbnz w0 -> nop (force UNLOCK)"),
    (0x0B504, 0x54000180, "unlock warning branch: b.eq -> nop"),
    (0x0B7B8, 0x94009DA3, "SKIP_VERIFY UART print: bl -> nop"),
    (0x0B7C0, 0x9401F0BD, "SKIP_VERIFY screen print: bl -> nop"),
]


def die(msg, code=2):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def main():
    ap = argparse.ArgumentParser(
        description="Offline magic64 unlock patcher for T9100 / VN300E (UMS9620).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=DEFAULT_INPUT,
                    help="stock uboot_b image (read-only)")
    ap.add_argument("--output", default=DEFAULT_OUTPUT,
                    help="output image (a NEW file; input is never touched)")
    ap.add_argument("--load-base", type=lambda x: int(x, 0), default=LOAD_BASE,
                    help="uboot payload runtime base (default: derived 0xb5000000)")
    ap.add_argument("--dry-run", action="store_true",
                    help="verify everything, write nothing")
    args = ap.parse_args()

    print("=" * 74)
    print("  T9100 / VN300E (UMS9620) offline magic64 unlock patcher")
    print("  OFFLINE ONLY - no device access, no flashing, no re-signing")
    print("=" * 74)

    # ---------------------------------------------------------------- input
    if not os.path.isfile(args.input):
        die(f"input not found: {args.input}")
    in_abs = os.path.abspath(args.input)
    out_abs = os.path.abspath(args.output)
    if in_abs.lower() == out_abs.lower():
        die("output path equals input path - refusing to overwrite the stock image")

    with open(args.input, "rb") as f:          # read-only
        data = bytearray(f.read())

    print(f"input      : {in_abs}")
    print(f"size       : {len(data)} (0x{len(data):x})")

    # ------------------------------------------------------------ 1. DHTB
    if data[0:4] != b"DHTB":
        die(f"not a DHTB image (magic = {bytes(data[0:4])!r})")

    # ------------------------------------------------------------ 2. SHA256
    sha = hashlib.sha256(data).hexdigest()
    print(f"sha256     : {sha}")
    if sha != STOCK_SHA256:
        die(f"sha256 mismatch\n  expected {STOCK_SHA256}\n  got      {sha}")
    print("sha256     : MATCH (pinned T9100 stock image)")

    if len(data) != PARTITION_SIZE:
        die(f"unexpected size 0x{len(data):x}, expected 0x{PARTITION_SIZE:x}")

    # ------------------------------------------------------- 3. structure
    size = struct.unpack_from("<I", data, 0x30)[0]
    foot_off = DHTB_HDR + size
    if data[foot_off:foot_off + 7] != b"SIMGHDR":
        die(f"SIMGHDR footer not found at file 0x{foot_off:x}")
    payload_offset = struct.unpack_from("<Q", data, foot_off + 0x18)[0]
    if payload_offset != 0x200:
        die(f"footer payload_offset = 0x{payload_offset:x} (expected 0x200); "
            f"image is already magic-patched or is a different format")
    print(f"payload    : file 0x{DHTB_HDR:x} .. 0x{foot_off:x}  (size 0x{size:x})")
    print(f"sechdr     : file 0x{foot_off:x}  (payload_offset field = 0x{payload_offset:x})")

    # ------------------------------------------------- 4. strict patch check
    print()
    print("--- patch point verification (exact 32-bit word match) ---")
    print(f"  {'#':>2}  {'code_off':>9}  {'file_off':>9}  {'found':>10}  "
          f"{'expected':>10}  {'result':>6}  semantics")
    ok = True
    for i, (code_off, want, desc) in enumerate(PATCH_POINTS, 1):
        file_off = DHTB_HDR + code_off
        if file_off + 4 > DHTB_HDR + size:
            die(f"patch point 0x{code_off:x} is past the end of the payload")
        got = struct.unpack_from("<I", data, file_off)[0]
        match = (got == want)
        ok &= match
        print(f"  {i:>2}  0x{code_off:07x}  0x{file_off:07x}  "
              f"0x{got:08x}  0x{want:08x}  {'OK' if match else 'MISMATCH':>6}  {desc}")
    if not ok:
        die("at least one patch point did not match the expected stock "
            "instruction - aborting, nothing written", 1)

    # ------------------------------------------------------------ 5. pack
    patches = [(code_off, NOP) for code_off, _, _ in PATCH_POINTS]
    print()
    print("--- magic64 packing (official implementation) ---")
    print(f"  packer        : {MP.__file__}")
    print(f"  LOAD_BASE     : 0x{args.load_base:08x}  ({LOAD_BASE_SOURCE})")
    for code_off, _ in patches:
        print(f"  patch table   : runtime 0x{args.load_base + code_off:08x} "
              f"(= LOAD_BASE + 0x{code_off:x})  <- 0x{NOP:08x}")

    try:
        out = MP.pack(data, patches, args.load_base)
    except ValueError as e:
        die(f"packing failed: {e}")

    # ------------------------------------------------------ 6. self-checks
    if len(out) != PARTITION_SIZE:
        die(f"packed size 0x{len(out):x} != partition size 0x{PARTITION_SIZE:x}")
    if out[0x210:0x210 + size] != data[DHTB_HDR:DHTB_HDR + size]:
        die("packed payload is not byte-identical to the stock payload")
    if bytes(out[DHTB_HDR:DHTB_HDR + 0x10]) == bytes(data[DHTB_HDR:DHTB_HDR + 0x10]):
        die("entry jump was not installed at 0x200")
    print(f"  packed size   : {len(out)} (0x{len(out):x}) == partition size  OK")
    print(f"  stock payload : byte-identical inside the packed image      OK")
    print(f"  signature     : untouched (no re-signing performed)         OK")

    if args.dry_run:
        print()
        print("DRY RUN - nothing written.")
        return 0

    # ------------------------------------------------------------ 7. write
    if os.path.exists(out_abs):
        print(f"\nnote: overwriting existing output {out_abs}")
    with open(out_abs, "wb") as f:
        f.write(out)

    print()
    print("=" * 74)
    print(f"wrote: {out_abs}")
    print(f"size : {len(out)} (0x{len(out):x})")
    print(f"sha256: {hashlib.sha256(out).hexdigest()}")
    print()
    print("NEXT STEP (manual, not performed by this tool):")
    print("  verify with:  python T9100_check_magic64.py")
    print("  Then flash uboot_b from the download tool. Do NOT flash splloader.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
