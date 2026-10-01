#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按文件顺序列出 uboot_log 里最后 N 次启动的来源（设备 / 固件 / 时间）。"""
import re
import sys

BANNER = "LK (0, restored from storage)"


def last_tok(t, start, field):
    i = t.find(field, start)
    if i < 0:
        return "?"
    j = i + len(field)
    while j < len(t) and t[j] in " \t":
        j += 1
    e = j
    while e < len(t) and t[e] not in "\r\n\t":
        e += 1
    return t[j:e].strip() or "?"


def main():
    path = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    t = open(path, "rb").read().decode("latin1", errors="replace")
    pos = [m.start() for m in re.finditer(re.escape(BANNER), t)]
    print(f"文件: {path}")
    print(f"横幅总数: {len(pos)}   （按文件位置顺序列出最后 {n} 个）")
    print()
    print(f"  {'#':>4} {'file_off':>10} {'size':>8}  {'target':<16} {'buildid':<28} LK time")
    for i in range(max(0, len(pos) - n), len(pos)):
        s = pos[i]
        e = pos[i + 1] if i + 1 < len(pos) else len(t)
        seg = t[s:e]
        tgt = last_tok(seg, 0, "target:")
        bid = last_tok(seg, 0, "buildid:")
        lkt = "?"
        k = seg.find("LK time is")
        if k >= 0:
            lkt = seg[k + 10:k + 32].split("\n")[0].strip()
        print(f"  {i:>4} 0x{s:08x} {e-s:>8}  {tgt:<16} {bid:<28} {lkt}")


if __name__ == "__main__":
    main()
