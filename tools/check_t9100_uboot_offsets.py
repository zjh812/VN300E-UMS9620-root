#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_t9100_uboot_offsets.py
============================

READ-ONLY offset checker for the UMS9620 / T9100 (Mario_12_2_5G, VN300E) U-Boot.

It re-derives and verifies the 4 candidate patch points that are semantically
equivalent to the official UMS9620 (T820) unlock patch, for THIS specific build.

Guarantees
----------
* Opens the U-Boot image with mode "rb" only.
* Never writes, truncates, renames or creates any image file.
* Never emits a patched U-Boot.  Nothing is written to disk at all.
* No device access, no flashing, no fastboot.

Usage
-----
    python check_t9100_uboot_offsets.py
    python check_t9100_uboot_offsets.py --image D:\\path\\to\\uboot_b.bin
    python check_t9100_uboot_offsets.py --json          # machine readable

Requires: capstone  (pip install capstone)
"""

import argparse
import hashlib
import json
import os
import struct
import sys

try:
    from capstone import (Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN,
                          CS_OP_REG, CS_OP_IMM, CS_OP_MEM)
except ImportError:  # pragma: no cover
    sys.exit("capstone is required:  python -m pip install capstone")

DEFAULT_IMAGE = r"C:\Users\admin\Desktop\B\T9100\backup\T9100_back\uboot_b.bin"
EXPECTED_SHA256 = "5935075bed5b12d35b961d0e39a4e95154b8cfb94ac177f96919700a24b8e321"
EXPECTED_SIZE = 0x300000
PAYLOAD_OFF = 0x200          # DHTB header size == payload start
NOP = 0xD503201F

# --------------------------------------------------------------------------
# Candidate patch points (code offsets = file offset - 0x200)
# mask 0xFF00001F : match opcode byte + Rt/cond, ignore imm19  (cbnz / b.cond)
# mask 0xFC000000 : match bl opcode only, ignore branch target
# --------------------------------------------------------------------------
PATCH_CANDIDATES = [
    dict(
        key="get_lock_status_force_unlock",
        code_off=0x62830,
        stock=0x350002A0,          # cbnz w0, #0x62884
        target=NOP,
        mask=0xFF00001F,
        func=0x627A4,
        ref_off=0x604C0,           # official T820 patch point
        ref_stock=0x35000160,
        semantics="get_lock_status() always reports UNLOCK "
                  "(g_DeviceStatus = 1, returns 1)",
    ),
    dict(
        key="unlock_warning_branch",
        code_off=0xB504,
        stock=0x54000180,          # b.eq #0xb534
        target=NOP,
        mask=0xFF00001F,
        func=0xB4E0,
        ref_off=0x0AFE8,
        ref_stock=0x54000180,      # byte-identical to the official stock word
        semantics="skip the 'INFO: LOCK FLAG IS : UNLOCK!!!' warning arm",
    ),
    dict(
        key="skip_verify_uart",
        code_off=0xB7B8,
        stock=0x94009DA3,          # bl 0x32e44
        target=NOP,
        mask=0xFC000000,
        func=0xB74C,
        ref_off=0x0B2A4,
        ref_stock=0x9400A21C,
        semantics="drop the UART print of "
                  "'WARNNING: LOCK FLAG IS : UNLOCK, SKIP VERIFY!!!'",
    ),
    dict(
        key="skip_verify_screen",
        code_off=0xB7C0,
        stock=0x9401F0BD,          # bl 0x87ab4
        target=NOP,
        mask=0xFC000000,
        func=0xB74C,
        ref_off=0x0B2AC,
        ref_stock=0x9401E7A2,
        semantics="drop the screen print of "
                  "'WARNNING: LOCK FLAG IS : UNLOCK, SKIP VERIFY!!!'",
    ),
]

# --------------------------------------------------------------------------
# Informational landmarks (no patch, just context / call-chain evidence)
# --------------------------------------------------------------------------
LANDMARKS = [
    (0x17B8C8, "global", "g_DeviceStatus (adrp 0x17b000 + 0x8c8) - THE lock state"),
    (0x627A4,  "func",   "get_lock_status()"),
    (0x622A0,  "func",   "read_lock_flag()  (0x200-byte stack frame; prints 'enter %s')"),
    (0x625BC,  "func",   "write_lock_flag() - writes 'VerifiedBoot-LOCK/UNLOCK'"),
    (0x62890,  "func",   "set_lock_status(lock, arg)"),
    (0x66048,  "func",   "read_is_device_unlocked() - AvbOps slot [ops+0x48]"),
    (0x66A00,  "data",   "AvbOps vtable A: [+0x48] = 0x66048"),
    (0x66A98,  "data",   "AvbOps vtable B: [+0x48] = 0x66048"),
    (0x69478,  "func",   "avb_append_options()"),
    (0x6956C,  "insn",   "blr  ops->read_is_device_unlocked   (in avb_append_options)"),
    (0x67400,  "insn",   "blr  ops->read_is_device_unlocked   (in avb_slot_verify path)"),
    (0x612C8,  "func",   "per-partition secure verify (prints 'Device Status is unlock, skip ...')"),
    (0x61620,  "block",  "'Device Status is unlock, skip %s image verify!.' print block"),
    (0xB4E0,   "func",   "boot-time lock-warning display fn"),
    (0xB74C,   "func",   "SKIP_VERIFY status-print fn (jump table on verify result)"),
    (0xB33C,   "func",   "power-button wait / timeout fn (w0 = iteration count)"),
    (0xB7A8,   "insn",   "br x2  - jump table dispatch inside 0xb74c"),
    (0x1F640,  "insn",   "bl 0xb4e0  - boot flow: lock warning"),
    (0x1F664,  "insn",   "bl 0xb74c  - boot flow: SKIP_VERIFY dispatch"),
    (0x37714,  "func",   "writes 'androidboot.flash.locked=0/1' (variant A)"),
    (0x3F83C,  "func",   "writes 'androidboot.flash.locked=0/1' (variant B, live)"),
]

# --------------------------------------------------------------------------
# Strings that must be present (code offsets)
# --------------------------------------------------------------------------
STRINGS = [
    (0xD49C8, "VerifiedBoot-UNLOCK"),
    (0xD49E0, "VerifiedBoot-LOCK"),
    (0xD4A90, "set device status unlock"),
    (0xD4AB0, "set device status lock"),
    (0xD21D8, "get_lock_status"),
    (0xBD6F8, "set_lock_status"),
    (0xD6038, "read_is_device_unlocked() get DeviceStatus 0x%x, *out_is_unlocked is %d."),
    (0xBAD18, "WARNNING: LOCK FLAG IS : UNLOCK, SKIP VERIFY!!!"),
    (0xBAAC0, "INFO: LOCK FLAG IS : UNLOCK!!!"),
    (0xBAAA0, "INFO: LOCK FLAG IS : LOCK!!!"),
    (0xBA9E8, "UNLOCK: check the status of the power button..."),
    (0xBAA20, "INFO: Press power button to continue."),
    (0xD4370, "Device Status is unlock, skip %s image verify!."),
    (0xD6D60, "Error getting device lock state."),
    (0xC8D28, "androidboot.flash.locked=0"),
    (0xC8D48, "androidboot.flash.locked=1"),
    (0xD20E8, "secure_avb_verify_image"),
    (0xD23D8, "sprd_fb_secure_vboot_verify"),
]


def iter_insns(md, payload, lo=0, hi=None):
    """Linear sweep that survives undecodable words (restart after each failure)."""
    hi = len(payload) if hi is None else hi
    off = lo
    while off < hi:
        progressed = False
        for i in md.disasm(payload[off:hi], off):
            yield i
            off = i.address + i.size
            progressed = True
        if not progressed:
            off += 4


def build_md():
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def disasm_one(md, payload, code_off):
    got = list(md.disasm(payload[code_off:code_off + 4], code_off))
    if not got:
        return "??"
    i = got[0]
    return f"{i.mnemonic} {i.op_str}".strip()


def context(md, payload, code_off, before=3, after=3):
    """Return list of (code_off, raw, text) around code_off."""
    lo = max(0, code_off - before * 4)
    hi = min(len(payload), code_off + 4 + after * 4)
    out = []
    for i in iter_insns(md, payload, lo, hi):
        raw = struct.unpack_from("<I", payload, i.address)[0]
        out.append((i.address, raw, f"{i.mnemonic} {i.op_str}".strip()))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Read-only verification of re-derived UMS9620/T9100 "
                    "U-Boot patch offsets.")
    ap.add_argument("--image", default=DEFAULT_IMAGE,
                    help="U-Boot image to inspect (opened read-only)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--context", type=int, default=3,
                    help="instructions of context around each point (default 3)")
    args = ap.parse_args()

    if not os.path.isfile(args.image):
        sys.exit(f"image not found: {args.image}")

    with open(args.image, "rb") as f:          # read-only, never "r+b"/"wb"
        data = f.read()

    report = {"image": args.image, "size": len(data)}

    sha = hashlib.sha256(data).hexdigest()
    report["sha256"] = sha
    report["sha256_expected"] = EXPECTED_SHA256
    report["sha256_ok"] = (sha == EXPECTED_SHA256)
    report["size_ok"] = (len(data) == EXPECTED_SIZE)

    # ---- structure ----
    is_dhtb = data[0:4] == b"DHTB"
    payload_size = struct.unpack_from("<Q", data, 0x30)[0] if is_dhtb else 0
    stored_hash = data[8:0x28] if is_dhtb else b""
    payload = data[PAYLOAD_OFF:PAYLOAD_OFF + payload_size]
    calc_hash = hashlib.sha256(payload).digest()
    sim_off = PAYLOAD_OFF + payload_size
    has_sim = data[sim_off:sim_off + 8] == b"SIMGHDR\x00"

    report["structure"] = dict(
        magic=data[0:4].decode("latin1"),
        dhtb_data_size=payload_size,
        dhtb_hash_match=(stored_hash == calc_hash),
        payload_start=PAYLOAD_OFF,
        payload_end=PAYLOAD_OFF + payload_size,
        simghdr_offset=(sim_off if has_sim else None),
        simghdr_header_size=(struct.unpack_from("<Q", data, sim_off + 0x18)[0]
                             if has_sim else None),
        simghdr_sig_size=(struct.unpack_from("<Q", data, sim_off + 0x20)[0]
                          if has_sim else None),
        tail_zero_pad=len(data) - (sim_off + 0x2B4) if has_sim else None,
    )

    md = build_md()

    # ---- strings ----
    str_results = []
    for off, expect in STRINGS:
        raw = payload[off:off + len(expect)]
        ok = raw == expect.encode("utf-8", "replace")
        str_results.append(dict(code_off=off, file_off=off + PAYLOAD_OFF,
                                expected=expect,
                                found=raw.split(b"\x00")[0].decode("latin1"),
                                ok=ok))
    report["strings"] = str_results

    # ---- patch candidates ----
    cand_results = []
    for c in PATCH_CANDIDATES:
        fo = c["code_off"] + PAYLOAD_OFF
        actual = struct.unpack_from("<I", payload, c["code_off"])[0]
        mask_ok = (actual & c["mask"]) == (c["stock"] & c["mask"])
        exact = (actual == c["stock"])
        cand_results.append(dict(
            **{k: c[k] for k in ("key", "code_off", "func", "semantics",
                                 "ref_off", "mask")},
            file_off=fo,
            raw=f"0x{actual:08x}",
            disasm=disasm_one(md, payload, c["code_off"]),
            stock=f"0x{c['stock']:08x}",
            target=f"0x{c['target']:08x}",
            match="EXACT" if exact else ("MASK-OK" if mask_ok else "MISMATCH"),
            ok=mask_ok,
            ref_stock=f"0x{c['ref_stock']:08x}",
            ref_delta=c["code_off"] - c["ref_off"],
        ))
    report["patch_candidates"] = cand_results

    # ---- landmarks ----
    lm_results = []
    for off, kind, desc in LANDMARKS:
        ent = dict(code_off=off, file_off=(off + PAYLOAD_OFF if kind != "global" else None),
                   kind=kind, desc=desc)
        if kind == "func":
            ent["prologue"] = disasm_one(md, payload, off)
            ent["raw"] = f"0x{struct.unpack_from('<I', payload, off)[0]:08x}"
        elif kind == "insn":
            ent["disasm"] = disasm_one(md, payload, off)
            ent["raw"] = f"0x{struct.unpack_from('<I', payload, off)[0]:08x}"
        elif kind == "data":
            ent["ptr_at_0x48"] = f"0x{struct.unpack_from('<Q', payload, off + 0x48)[0]:x}"
        lm_results.append(ent)
    report["landmarks"] = lm_results

    # ---- g_DeviceStatus access sites ----
    # adrp 0x17b000 (+0x200) then ldr/str with disp 0x8c8 / 0x6c8
    gd = []
    regs = {}
    for i in iter_insns(md, payload):
        ops = i.operands
        mn = i.mnemonic
        if mn == "adrp" and len(ops) == 2:
            regs[i.reg_name(ops[0].reg)] = (i.address, ops[1].imm)
            continue
        if mn == "add" and len(ops) == 3 and ops[1].type == CS_OP_REG \
                and ops[2].type == CS_OP_IMM:
            src = i.reg_name(ops[1].reg)
            if src in regs and i.address - regs[src][0] <= 0x40:
                regs[i.reg_name(ops[0].reg)] = (i.address, regs[src][1] + ops[2].imm)
                continue
        if len(ops) >= 2 and ops[-1].type == CS_OP_MEM:
            mem = ops[-1].mem
            base = i.reg_name(mem.base) if mem.base else None
            if base in regs and i.address - regs[base][0] <= 0x40:
                if regs[base][1] + mem.disp == 0x17B8C8:
                    gd.append(dict(code_off=i.address, file_off=i.address + PAYLOAD_OFF,
                                   disasm=f"{mn} {i.op_str}".strip()))
        for o in ops:
            if o.type == CS_OP_REG and o.access is not None and o.access & 2:
                regs.pop(i.reg_name(o.reg), None)
    report["g_devicestatus_accesses"] = gd

    # ---- context dump ----
    report["contexts"] = {
        c["key"]: [dict(code_off=o, file_off=o + PAYLOAD_OFF,
                        raw=f"0x{r:08x}", disasm=t)
                   for o, r, t in context(md, payload, c["code_off"], args.context, args.context)]
        for c in PATCH_CANDIDATES
    }

    # ---------------------------------------------------------------- output
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    st = report["structure"]
    print("=" * 78)
    print("  UMS9620 / T9100 (Mario_12_2_5G, VN300E) U-Boot offset checker")
    print("  READ-ONLY - nothing is written, no patched image is produced")
    print("=" * 78)
    print(f"image      : {report['image']}")
    print(f"size       : {report['size']} (0x{report['size']:x})   "
          f"[{'OK' if report['size_ok'] else 'UNEXPECTED'}]")
    print(f"sha256     : {sha}")
    print(f"sha match  : {'OK' if report['sha256_ok'] else 'MISMATCH'}")
    print()
    print("--- A. image structure -------------------------------------------")
    print(f"  magic              : {st['magic']}")
    print(f"  DHTB data_size     : 0x{st['dhtb_data_size']:x}")
    print(f"  DHTB hash == SHA256(payload) : {'OK' if st['dhtb_hash_match'] else 'MISMATCH'}")
    print(f"  payload  (file)    : 0x{st['payload_start']:x} .. 0x{st['payload_end']:x}")
    print(f"  code offset base   : file_off = 0x200 + code_off")
    if st["simghdr_offset"]:
        print(f"  SIMGHDR  (file)    : 0x{st['simghdr_offset']:x}  "
              f"header=0x{st['simghdr_header_size']:x}  sig=0x{st['simghdr_sig_size']:x}")
    print(f"  zero padding tail  : {st['tail_zero_pad']} bytes")

    print()
    print("--- B. candidate patch points ------------------------------------")
    hdr = (f"  {'semantic':34s} {'code':>8s} {'file':>9s} {'raw':>10s}  "
           f"{'disasm':22s} {'match':9s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for c in cand_results:
        print(f"  {c['key']:34s} 0x{c['code_off']:06x} 0x{c['file_off']:07x} "
              f"{c['raw']:>10s}  {c['disasm']:22s} {c['match']:9s}")
    print()
    for c in cand_results:
        print(f"  * {c['key']}")
        print(f"      file offset     : 0x{c['file_off']:x}")
        print(f"      original        : {c['raw']}   ({c['disasm']})")
        print(f"      target          : {c['target']}   (nop)")
        print(f"      official T820   : code 0x{c['ref_off']:x} stock {c['ref_stock']} "
              f"-> delta {c['ref_delta']:+#x}")
        print(f"      semantics       : {c['semantics']}")
        print(f"      context:")
        for e in report["contexts"][c["key"]]:
            mark = "  <== PATCH POINT" if e["code_off"] == c["code_off"] else ""
            print(f"          0x{e['code_off']:06x} (file 0x{e['file_off']:07x})  "
                  f"{e['raw']}  {e['disasm']}{mark}")
        print()

    print("--- C. g_DeviceStatus (0x17b8c8) access sites --------------------")
    for g in report["g_devicestatus_accesses"]:
        print(f"  0x{g['code_off']:06x} (file 0x{g['file_off']:07x})  {g['disasm']}")

    print()
    print("--- D. landmarks -------------------------------------------------")
    for l in lm_results:
        loc = f"0x{l['code_off']:06x}" + (f" (file 0x{l['file_off']:07x})" if l["file_off"] else "")
        extra = l.get("disasm") or l.get("prologue") or l.get("ptr_at_0x48") or ""
        print(f"  {loc:22s} [{l['kind']:6s}] {extra:34s} {l['desc']}")

    print()
    print("--- E. expected strings ------------------------------------------")
    bad = [s for s in str_results if not s["ok"]]
    print(f"  {len(str_results) - len(bad)}/{len(str_results)} present and at the "
          f"expected code offset")
    for s in bad:
        print(f"  !! 0x{s['code_off']:06x} expected {s['expected']!r} "
              f"found {s['found']!r}")

    print()
    n_ok = sum(1 for c in cand_results if c["ok"])
    print("=" * 78)
    if n_ok == len(cand_results) and report["sha256_ok"]:
        print(f"  RESULT: all {n_ok}/{len(cand_results)} candidate patch points verified "
              f"on the expected image.")
        print("  RESULT: this is a read-only analysis; no image was modified.")
    else:
        print(f"  RESULT: {n_ok}/{len(cand_results)} candidate patch points verified. "
              f"Review the mismatches above.")
    print("=" * 78)
    return 0 if n_ok == len(cand_results) else 1


if __name__ == "__main__":
    sys.exit(main())
