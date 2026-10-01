#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核对一份 uboot_log 里到底混了几台设备 / 几个固件版本。"""
import collections
import sys

FIELDS = ("target:", "project:", "buildid:", "platform:")


def scan(path):
    t = open(path, "rb").read().decode("latin1", errors="replace")
    print("=" * 72)
    print(f"文件 : {path}")
    print(f"大小 : {len(t)} (0x{len(t):x})")
    for f in FIELDS:
        vals = collections.Counter()
        i = 0
        while True:
            i = t.find(f, i)
            if i < 0:
                break
            j = i + len(f)
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
        print(f"  {f:10s} {dict(vals)}")
    print()


if __name__ == "__main__":
    for p in sys.argv[1:]:
        scan(p)
