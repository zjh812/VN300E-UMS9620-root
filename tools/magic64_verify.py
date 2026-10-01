#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
magic64_verify.py — 只读验证 + shellcode 模拟执行（Unisoc magic64 U-Boot）

改下面 CONFIG 即可复用到其它设备/固件。只读：不写任何文件。

用法:
    python magic64_verify.py --stock stock.img --patched out.img \
        --load-base 0xb5000000 --patches 0x62830,0xb504,0xb7b8,0xb7c0
"""

import argparse
import hashlib
import os
import struct
import sys

try:
    from capstone import (Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN,
                          CS_OP_REG, CS_OP_IMM, CS_OP_MEM)
except ImportError:
    sys.exit("需要 capstone:  python -m pip install capstone")

# ------------------------------------------------------------------ CONFIG
DHTB_HDR = 0x200
ADD_LENGTH = 0x100          # magic_pack 的固定增量
NOP = 0xD503201F
SECHDR_SIZE = 0x60          # SIMGHDR/sechdr footer 长度
NOOP_MNEMONICS = {"isb", "dsb", "dmb", "nop", "ic", "dc", "tlbi", "at", "sys", "hint"}

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


# ------------------------------------------------------------------ emulator
class Machine:
    def __init__(self, blob, img_base):
        self.base, self.buf, self.oob = img_base, bytearray(blob), []

    def _off(self, addr, size):
        o = addr - self.base
        if o < 0 or o + size > len(self.buf):
            self.oob.append((addr, size))
            return None
        return o

    def read(self, addr, size):
        o = self._off(addr, size)
        return 0 if o is None else int.from_bytes(self.buf[o:o + size], "little")

    def write(self, addr, size, val):
        o = self._off(addr, size)
        if o is not None:
            self.buf[o:o + size] = (val & ((1 << (size * 8)) - 1)).to_bytes(size, "little")


def run_shellcode(blob, img_base, entry, stop_at=None, limit=8_000_000):
    """跑 magic64 shellcode。stop_at=LOAD_BASE 时在交还控制权处停止。
    注意 limit：拷贝循环约 (size/8)*6 条指令，1.5MB payload 约 114 万条。"""
    mem = Machine(blob, img_base)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    regs = {f"x{i}": 0 for i in range(32)}
    flags = {"n": 0, "z": 0, "c": 0, "v": 0}
    pc, trace, steps = entry, [], 0

    def rv(rn):
        if rn in ("wzr", "xzr"):
            return 0
        return (regs.get("x" + rn[1:], 0) & 0xFFFFFFFF) if rn.startswith("w") else regs.get(rn, 0)

    def wv(rn, v):
        if rn in ("wzr", "xzr"):
            return
        if rn.startswith("w"):
            regs["x" + rn[1:]] = v & 0xFFFFFFFF
        else:
            regs[rn] = v & 0xFFFFFFFFFFFFFFFF

    while steps < limit:
        steps += 1
        off = mem._off(pc, 4)
        if off is None:
            trace.append((pc, "OOB", "")); break
        words = list(md.disasm(bytes(mem.buf[off:off + 4]), pc))
        if not words:
            trace.append((pc, "undecodable", "")); break
        ins = words[0]
        m, ops = ins.mnemonic, ins.operands
        raw = int.from_bytes(mem.buf[off:off + 4], "little")
        trace.append((pc, m, ins.op_str))
        nxt = pc + 4

        if m == "adrp":
            wv(ins.reg_name(ops[0].reg), ops[1].imm)
        elif m == "add" and len(ops) == 3 and ops[2].type == CS_OP_IMM:
            wv(ins.reg_name(ops[0].reg), rv(ins.reg_name(ops[1].reg)) + ops[2].imm)
        elif m in ("mov", "movz", "movk", "movn"):
            rd = ins.reg_name(ops[0].reg)
            if (raw & 0xFF800000) == 0xD2800000 or (raw & 0x7F800000) == 0x52800000:
                wv(rd, ((raw >> 5) & 0xFFFF) << (((raw >> 21) & 3) * 16))
            elif (raw & 0xFF800000) == 0xF2800000 or (raw & 0x7F800000) == 0x72800000:
                hw = (raw >> 21) & 3
                mask = ~(0xFFFF << (hw * 16)) & 0xFFFFFFFFFFFFFFFF
                wv(rd, (rv(rd) & mask) | (((raw >> 5) & 0xFFFF) << (hw * 16)))
            elif len(ops) == 2 and ops[1].type == CS_OP_REG:
                wv(rd, rv(ins.reg_name(ops[1].reg)))
            else:
                wv(rd, ops[1].imm)
        elif m in ("subs", "sub") and len(ops) == 3:
            a, b = rv(ins.reg_name(ops[1].reg)), rv(ins.reg_name(ops[2].reg))
            res = (a - b) & 0xFFFFFFFFFFFFFFFF
            wv(ins.reg_name(ops[0].reg), res)
            if m == "subs":
                flags = {"n": (res >> 63) & 1, "z": int(res == 0), "c": int(a >= b), "v": 0}
        elif m == "cmp" and len(ops) == 2:
            a = rv(ins.reg_name(ops[0].reg))
            b = ops[1].imm if ops[1].type == CS_OP_IMM else rv(ins.reg_name(ops[1].reg))
            res = (a - b) & 0xFFFFFFFFFFFFFFFF
            flags = {"n": (res >> 63) & 1, "z": int(res == 0), "c": int(a >= b), "v": 0}
        elif m == "cbz":
            if rv(ins.reg_name(ops[0].reg)) == 0:
                nxt = ops[1].imm
        elif m == "cbnz":
            if rv(ins.reg_name(ops[0].reg)) != 0:
                nxt = ops[1].imm
        elif m.startswith("b."):
            c = m[2:]
            take = {"eq": flags["z"] == 1, "ne": flags["z"] == 0,
                    "hs": flags["c"] == 1, "cs": flags["c"] == 1,
                    "lo": flags["c"] == 0, "cc": flags["c"] == 0,
                    "hi": flags["c"] == 1 and flags["z"] == 0,
                    "ls": not (flags["c"] == 1 and flags["z"] == 0),
                    "ge": flags["n"] == flags["v"], "lt": flags["n"] != flags["v"],
                    "gt": flags["z"] == 0 and flags["n"] == flags["v"],
                    "le": not (flags["z"] == 0 and flags["n"] == flags["v"])}.get(c, False)
            if take:
                nxt = ops[0].imm
        elif m == "b":
            nxt = ops[0].imm
        elif m == "br":
            nxt = rv(ins.reg_name(ops[0].reg))
        elif m == "ret":
            trace.append((pc, "RET", "")); break
        elif m in ("ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "ldrsh",
                   "str", "strb", "strh"):
            memop, post = None, 0
            for k, o in enumerate(ops):
                if o.type == CS_OP_MEM:
                    memop = o.mem
                    if k + 1 < len(ops) and ops[k + 1].type == CS_OP_IMM:
                        post = ops[k + 1].imm
                    break
            if memop is None:
                trace.append((pc, "UNHANDLED", f"{m} {ins.op_str}")); break
            addr = rv(ins.reg_name(memop.base)) + memop.disp
            if memop.index:
                sh = int(ins.op_str.split("lsl #")[1].split("]")[0].strip()) \
                    if "lsl #" in ins.op_str else 0
                addr += rv(ins.reg_name(memop.index)) << sh
            rd = ins.reg_name(ops[0].reg)
            if m.startswith("ldr"):
                size = (8 if rd.startswith("x") else 4) if m == "ldr" else \
                       {"ldrb": 1, "ldrh": 2, "ldrsb": 1, "ldrsh": 2, "ldrsw": 4}[m]
                wv(rd, mem.read(addr, size))
            else:
                size = (8 if rd.startswith("x") else 4) if m == "str" else \
                       {"strb": 1, "strh": 2}[m]
                mem.write(addr, size, rv(rd))
            if post:
                wv(ins.reg_name(memop.base), rv(ins.reg_name(memop.base)) + post)
        elif m in NOOP_MNEMONICS:
            pass
        else:
            trace.append((pc, "UNHANDLED", f"{m} {ins.op_str}")); break
        if stop_at is not None and nxt == stop_at:
            trace.append((nxt, "HANDOFF", f"control -> real _start 0x{nxt:08x}"))
            break
        pc = nxt
    return mem, trace, steps


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stock", required=True)
    ap.add_argument("--patched", required=True)
    ap.add_argument("--load-base", type=lambda x: int(x, 0), default=0xB5000000)
    ap.add_argument("--patches", required=True,
                    help="逗号分隔的 code offset；也支持 off=target（自定义目标指令），"
                         "例 0x62830,0xb504 或 0x6ac10=0xd503201f,0x6ac18=0x17ffffc1")
    ap.add_argument("--trace", action="store_true")
    args = ap.parse_args()

    pairs = []
    for item in args.patches.split(","):
        if "=" in item:
            o, _, t = item.partition("=")
            pairs.append((int(o, 0), int(t, 0)))
        else:
            pairs.append((int(item, 0), NOP))
    pairs.sort()
    patches = [p for p, _ in pairs]
    targets = [t for _, t in pairs]
    tgt_of = dict(pairs)
    load_base = args.load_base
    img_base = load_base - DHTB_HDR

    if not os.path.isfile(args.stock) or not os.path.isfile(args.patched):
        sys.exit("stock/patched not found")
    stock = open(args.stock, "rb").read()
    patched = open(args.patched, "rb").read()

    print("=" * 72)
    print("  magic64 offline verification (read-only)")
    print("=" * 72)
    print(f"  stock   {len(stock)} (0x{len(stock):x})  {hashlib.sha256(stock).hexdigest()}")
    print(f"  patched {len(patched)} (0x{len(patched):x})  {hashlib.sha256(patched).hexdigest()}")
    print(f"  LOAD_BASE 0x{load_base:08x}   IMG_BASE 0x{img_base:08x}")

    check("stock magic DHTB", stock[0:4] == b"DHTB")
    check("patched magic DHTB", patched[0:4] == b"DHTB")
    check("patched size == stock size (partition)", len(stock) == len(patched))

    s_size = struct.unpack_from("<I", stock, 0x30)[0]
    p_size = struct.unpack_from("<I", patched, 0x30)[0]
    check("data_size grew by 0x100", p_size - s_size == ADD_LENGTH,
          f"0x{s_size:x} -> 0x{p_size:x}")

    jump = struct.unpack_from("<I", patched, 0x200)[0]
    check("entry is unconditional B", (jump & 0xFC000000) == 0x14000000, f"0x{jump:08x}")
    imm26 = jump & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    shell_off = 0x210 + s_size
    check("entry jump -> shellcode", 0x200 + (imm26 << 2) == shell_off,
          f"-> file 0x{0x200 + (imm26 << 2):x}")

    magic_off = shell_off + 0x70
    entries, off = [], magic_off
    while True:
        a, ln, w = struct.unpack_from("<III", patched, off)
        if a == 0:
            break
        entries.append((a, ln, w)); off += 12
    check("patch table count matches", len(entries) == len(patches))
    check("patch addrs == LOAD_BASE + code_offset",
          sorted(e[0] for e in entries) == sorted(load_base + o for o in patches),
          str([hex(e[0]) for e in entries]))
    got_pairs = sorted((e[0] - load_base, e[2]) for e in entries)
    check("patch table (code_offset, word) pairs match the request exactly",
          got_pairs == sorted(pairs),
          f"got {[(hex(a), hex(w)) for a, w in got_pairs]}")

    check("stock payload byte-identical at 0x210",
          patched[0x210:0x210 + s_size] == stock[0x200:0x200 + s_size])
    s_foot, p_foot = 0x200 + s_size, 0x200 + p_size
    check("SIMGHDR at new payload end", patched[p_foot:p_foot + 7] == b"SIMGHDR")
    check("payload_offset 0x200 -> 0x210",
          struct.unpack_from("<Q", stock, s_foot + 0x18)[0] == 0x200 and
          struct.unpack_from("<Q", patched, p_foot + 0x18)[0] == 0x210)
    sig_size = struct.unpack_from("<Q", stock, s_foot + 0x20)[0]
    s_cert, p_cert = s_foot + SECHDR_SIZE, p_foot + SECHDR_SIZE
    check("cert blob byte-identical (relocated only)",
          patched[p_cert:p_cert + sig_size] == stock[s_cert:s_cert + sig_size],
          f"0x{sig_size:x} bytes")
    check("everything after cert is zero padding",
          not any(patched[p_cert + sig_size:]))

    print("\n--- simulated execution ---")
    mem, trace, steps = run_shellcode(patched, img_base, img_base + shell_off,
                                      stop_at=load_base)
    print(f"  emulated {steps} instructions")
    if args.trace:
        for pc, m, o in trace:
            print(f"    0x{pc:08x}  {m:12s} {o}")
    bad = [t for t in trace if t[1] in ("UNHANDLED", "undecodable", "OOB")]
    check("no unsupported instruction", not bad, str(bad[:1]))
    check("no out-of-range access", not mem.oob, str(mem.oob[:1]))
    check("handed control to real _start at LOAD_BASE",
          trace[-1][1] == "HANDOFF" and trace[-1][0] == load_base, trace[-1][2])

    base_off = load_base - img_base
    final = bytes(mem.buf[base_off:base_off + s_size])
    orig = stock[0x200:0x200 + s_size]
    changed = [w * 4 for w in range(s_size // 4)
               if final[w * 4:w * 4 + 4] != orig[w * 4:w * 4 + 4]]
    for d in changed:
        print(f"    code 0x{d:06x} (rt 0x{load_base + d:08x}): "
              f"0x{int.from_bytes(orig[d:d+4],'little'):08x} -> "
              f"0x{int.from_bytes(final[d:d+4],'little'):08x}")
    check("exactly the intended words changed in RAM", sorted(changed) == patches,
          str([hex(x) for x in changed]))
    check("all changed words match the requested targets",
          all(int.from_bytes(final[d:d + 4], "little") == tgt_of.get(d, NOP)
              for d in changed),
          str([hex(int.from_bytes(final[d:d + 4], 'little')) for d in changed]))

    npass = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n  RESULT: {npass}/{len(RESULTS)} passed")
    print("  LIMIT : offline cannot prove the SPL honours footer payload_offset.")
    return 0 if npass == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
