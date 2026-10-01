#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_boot_log.py — 分析 T9100 的 uboot_log 分区，判定补丁是否生效。

uboot_log 是 U-Boot 的控制台日志分区（16MB）。U-Boot 的打印函数（code 0x32E44）
同时写 UART 和这个分区，所以 `spd_dump ... r uboot_log` 读回来就能看到启动日志 ——
不需要硬件 UART。

本脚本做三件事：
  1. 定位数据真实结束位置（分区尾部通常是 0 填充，不能直接扫"文件尾部"）
  2. 切出**最新一次启动**的日志段，只统计这一段
  3. 用「补丁前从未出现过」的字符串做判据，环形缓冲免疫

用法：
    python check_boot_log.py <uboot_log.bin>
    python check_boot_log.py <uboot_log.bin> --last-boot     # 打印最新启动段的关键行
    python check_boot_log.py <uboot_log.bin> --all-boots     # 列出所有启动段概览
"""

import argparse
import os
import re
import sys

BANNER = "LK (0, restored from storage)"

MARKERS = [
    ("MAGIC64 PROBE OK",                             "★ magic64 执行证明（原厂镜像里不存在）"),
    ("androidboot.flash.locked=0",                   "★ 判据：UNLOCKED 属性"),
    ("androidboot.flash.locked=1",                   "LOCKED 属性"),
    ("INFO: LOCK FLAG IS : LOCK!!!",                 "LOCK 分支 UART 打印 (code 0xB520)"),
    ("INFO: LOCK FLAG IS : UNLOCK!!!",               "UNLOCK 分支 UART 打印 (code 0xB53C)"),
    ("WARNNING: LOCK FLAG IS : UNLOCK, SKIP VERIFY", "SKIP_VERIFY 打印 (code 0xB7B8/0xB7C0)"),
    ("Device Status is unlock, skip",                "逐分区跳过校验 (code 0x61620)"),
    ("androidboot.verifiedbootstate=green",          "verifiedbootstate=green"),
    ("androidboot.verifiedbootstate=orange",         "verifiedbootstate=orange"),
    ("SECUREBOOT_ENABLE",                            "安全启动启用"),
    ("jump to kernel",                               "启动到内核（一次完整启动的标志）"),
    # ---- get_lock_status() 内部诊断（patch① 是否被绕过的关键）----
    ("rpmb read lock flag fail",                     "get_lock_status: RPMB 读锁标志失败"),
    ("rpmb key enable, lock bootloader",             "get_lock_status: RPMB key 启用"),
    ("read miscdata error",                          "get_lock_status: 读 miscdata 失败"),
    ("lock_flag is all zero",                        "get_lock_status: lock flag 全 0"),
    ("lock status is locked",                        "get_lock_status: 判定为 LOCKED"),
    ("data buffer is all zero",                      "get_lock_status: 数据全 0"),
]


def data_end(raw):
    """分区尾部是 0 填充；返回真实数据结束位置。"""
    i = len(raw) - 1
    while i >= 0 and raw[i] == 0:
        i -= 1
    return i + 1


def field_values(t, field):
    """取出某个字段（如 'target:'）的所有取值 -> Counter。"""
    import collections
    vals = collections.Counter()
    i = 0
    while True:
        i = t.find(field, i)
        if i < 0:
            break
        j = i + len(field)
        k = j
        while k < len(t) and t[k] in " \t":
            k += 1
        e = k
        while e < len(t) and t[e] not in "\r\n\t":
            e += 1
        v = t[k:e].strip()
        if v:
            vals[v] += 1
        i = j
    return vals


def source_check(txt, end, expect_target=None):
    """核查这份日志到底来自哪台设备 / 哪个固件。返回 (ok, 说明)。"""
    print("--- 来源核查（先确认这份日志是不是你的设备）---")
    tgts = field_values(txt[:end], "target:")
    bids = field_values(txt[:end], "buildid:")
    projs = field_values(txt[:end], "project:")
    print(f"  target : {dict(tgts)}")
    print(f"  project: {dict(projs)}")
    print(f"  buildid: {dict(bids)}")
    ok = True
    if len(tgts) > 1:
        print(f"  ⚠️ 这份日志混了 {len(tgts)} 种 target —— 不是单台设备的干净日志！")
        ok = False
    if expect_target and list(tgts) and expect_target not in tgts:
        print(f"  ⚠️ 期望 target={expect_target}，但日志里是 {list(tgts)}")
        print("     => 你可能连的是**另一台设备**，或者 uboot 被刷成了别的固件。")
        ok = False
    if len(bids) > 1:
        print(f"  ⚠️ 混了 {len(bids)} 个固件版本（分区里有历史残留，或换过固件）")
    if ok:
        print("  ✅ 单设备、单固件来源")
    print()
    return ok


def boot_starts(txt, end):
    return [m.start() for m in re.finditer(re.escape(BANNER), txt[:end])]


def main():
    ap = argparse.ArgumentParser(description="分析 uboot_log（定位最新启动段）")
    ap.add_argument("logfile")
    ap.add_argument("--last-boot", action="store_true", help="打印最新启动段的关键行")
    ap.add_argument("--all-boots", action="store_true", help="列出所有启动段概览")
    ap.add_argument("--expect-target", default="ums9620_2h10",
                    help="期望的设备 target（T9100 = ums9620_2h10）")
    args = ap.parse_args()

    if not os.path.isfile(args.logfile):
        sys.exit(f"文件不存在: {args.logfile}")
    raw = open(args.logfile, "rb").read()
    end = data_end(raw)
    txt = raw.decode("latin1", errors="replace")

    print("=" * 78)
    print("  T9100 uboot_log 分析")
    print("=" * 78)
    print(f"文件      : {os.path.abspath(args.logfile)}")
    print(f"分区大小  : {len(raw)} (0x{len(raw):x})")
    print(f"数据结束  : 0x{end:x}   （其后 {len(raw)-end} 字节为 0 填充）")
    wrapped = "LK (0, restored" not in txt[:0x400]
    print(f"环形回绕  : {'是（文件开头不是启动起点）' if wrapped else '否（数据按时间顺序从文件头排列）'}")

    starts = boot_starts(txt, end)
    print(f"启动段数  : {len(starts)}")
    if not starts:
        print("\n没有找到 U-Boot 横幅，无法分析。")
        return 1
    print()

    src_ok = source_check(txt, end, args.expect_target)
    if not src_ok:
        print("  ⚠️ 来源核查未通过 —— 下面的结论**可能不适用于你的设备**，请先确认连的是哪台。")
        print()

    # ---- 最新一次启动 ----
    last = starts[-1]
    seg = txt[last:end]
    seg_len = end - last
    print(f"最新启动段: 文件 0x{last:x} .. 0x{end:x}  （{seg_len} 字节）")
    print()

    print("--- 最新启动段内的计数 ---")
    c = {}
    for pat, desc in MARKERS:
        c[pat] = seg.count(pat)
        print(f"  {c[pat]:5d}  {desc}")
    print()

    n0 = c["androidboot.flash.locked=0"]
    n1 = c["androidboot.flash.locked=1"]
    lock_msg = c["INFO: LOCK FLAG IS : LOCK!!!"]
    unlock_msg = c["INFO: LOCK FLAG IS : UNLOCK!!!"]
    skipv = c["WARNNING: LOCK FLAG IS : UNLOCK, SKIP VERIFY"]
    to_kernel = c["jump to kernel"]

    print("=" * 78)
    print("  结论")
    print("=" * 78)

    if seg_len < 0x2000:
        print(f"  ⚠️ 最新启动段只有 {seg_len} 字节，看起来是**不完整的启动**")
        print("     （设备还没跑到设置 androidboot.flash.locked 的那一步就被打断了）")
        print("     => 让设备完整启动一次再读；判据暂时无法给出结论。")
    elif n0 > 0:
        print(f"  ✅ 补丁生效：最新启动段里出现 {n0} 次 'androidboot.flash.locked=0'")
        print("     这个字符串在打补丁前从未出现过，环形缓冲无法伪造它。")
        print("     => magic64 shellcode 执行了，patch① 把 g_DeviceStatus 改成了 1")
        print()
        print(f"     LOCK 行 {lock_msg} 次 / UNLOCK 行 {unlock_msg} 次 / SKIP_VERIFY {skipv} 次")
        if lock_msg == 0 and unlock_msg == 0:
            print("     LOCK 与 UNLOCK 两行都为 0 → patch② 也生效（解锁警告分支被 NOP）")
        print()
        print("     下一步：adb shell getprop ro.boot.flash.locked  应为 0")
    else:
        print(f"  ❌ 最新启动段里没有 'androidboot.flash.locked=0'（locked=1 有 {n1} 次）")
        print(f"     LOCK 行 {lock_msg} 次 / UNLOCK 行 {unlock_msg} 次")
        if to_kernel:
            print(f"     该启动段跑到了内核（jump to kernel ×{to_kernel}），是完整启动。")
        print("     => 补丁① 没有生效：magic64 shellcode 没有执行，")
        print("        或者入口点假设不成立（跳转指令没被跑到）。")
        print("     设备本身没有损坏（payload 逐字节未改，只是补丁没应用）。")

    # ---- 全分区计数（参考）----
    print()
    print("--- 全分区计数（含历史启动，仅参考）---")
    for pat, desc in MARKERS:
        if pat == "jump to kernel":
            continue
        print(f"  {txt.count(pat):5d}  {desc}")

    # ---- 最新启动段关键行 ----
    if args.last_boot:
        print()
        print("=" * 78)
        print("  最新启动段的关键行")
        print("=" * 78)
        keep = [p for p, _ in MARKERS] + ["dram size", "sechdr_addr", "sechdr_offset",
                                          "verifiedbootstate", "LOCK FLAG"]
        shown = 0
        for line in seg.split("\n"):
            if any(k in line for k in keep):
                print("  " + line.strip()[:150])
                shown += 1
                if shown >= 40:
                    print("  ...（省略）")
                    break
        if shown == 0:
            print("  （没有关键行）")

    # ---- 所有启动段概览 ----
    if args.all_boots:
        print()
        print("=" * 78)
        print("  所有启动段概览")
        print("=" * 78)
        print(f"  {'#':>3} {'file_off':>9} {'size':>8} {'LOCK':>5} {'UNLOCK':>7} "
              f"{'lock=0':>7} {'lock=1':>7} {'toKernel':>9}")
        for i, s in enumerate(starts):
            e = starts[i + 1] if i + 1 < len(starts) else end
            t = txt[s:e]
            print(f"  {i:>3} 0x{s:08x} {e-s:>8} "
                  f"{t.count('INFO: LOCK FLAG IS : LOCK!!!'):>5} "
                  f"{t.count('INFO: LOCK FLAG IS : UNLOCK!!!'):>7} "
                  f"{t.count('androidboot.flash.locked=0'):>7} "
                  f"{t.count('androidboot.flash.locked=1'):>7} "
                  f"{t.count('jump to kernel'):>9}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
