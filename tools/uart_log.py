#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
uart_log.py — 纯标准库（ctypes + Win32 API）串口日志抓取，无第三方依赖。

用途：抓 T9100 的 U-Boot 启动日志（COM3 @ 921600 8N1）。

用法：
    python uart_log.py --list                  # 列出可用串口
    python uart_log.py --port COM3             # 抓取并打印
    python uart_log.py --port COM3 --save boot.log
    python uart_log.py --port COM3 --seconds 60 --save boot.log

抓取方法：先运行本脚本（它会一直读），再给设备上电 / 重启。
按 Ctrl+C 停止。
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import sys
import time

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5


class DCB(ctypes.Structure):
    _fields_ = [
        ("DCBlength", wt.DWORD), ("BaudRate", wt.DWORD),
        ("fBinary", wt.DWORD, 1), ("fParity", wt.DWORD, 1),
        ("fOutxCtsFlow", wt.DWORD, 1), ("fOutxDsrFlow", wt.DWORD, 1),
        ("fDtrControl", wt.DWORD, 2), ("fDsrSensitivity", wt.DWORD, 1),
        ("fTXContinueOnXoff", wt.DWORD, 1), ("fOutX", wt.DWORD, 1),
        ("fInX", wt.DWORD, 1), ("fErrorChar", wt.DWORD, 1),
        ("fNull", wt.DWORD, 1), ("fRtsControl", wt.DWORD, 2),
        ("fAbortOnError", wt.DWORD, 1), ("fDummy2", wt.DWORD, 17),
        ("wReserved", wt.WORD), ("XonLim", wt.WORD), ("XoffLim", wt.WORD),
        ("ByteSize", wt.BYTE), ("Parity", wt.BYTE), ("StopBits", wt.BYTE),
        ("XonChar", ctypes.c_char), ("XoffChar", ctypes.c_char),
        ("ErrorChar", ctypes.c_char), ("EofChar", ctypes.c_char),
        ("EvtChar", ctypes.c_char), ("wReserved1", wt.WORD),
    ]


class COMMTIMEOUTS(ctypes.Structure):
    _fields_ = [("ReadIntervalTimeout", wt.DWORD),
                ("ReadTotalTimeoutMultiplier", wt.DWORD),
                ("ReadTotalTimeoutConstant", wt.DWORD),
                ("WriteTotalTimeoutMultiplier", wt.DWORD),
                ("WriteTotalTimeoutConstant", wt.DWORD)]


def list_ports():
    """从注册表 HARDWARE\\DEVICEMAP\\SERIALCOMM 读取真实串口。"""
    try:
        import winreg
    except ImportError:
        return []
    found = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"HARDWARE\DEVICEMAP\SERIALCOMM")
    except OSError:
        return []
    try:
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            found.append((value, name))
            i += 1
    finally:
        winreg.CloseKey(key)
    return found


def open_port(port, baud):
    h = kernel32.CreateFileW(f"\\\\.\\{port}", GENERIC_READ | GENERIC_WRITE,
                             0, None, OPEN_EXISTING, 0, None)
    if h == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        if err == ERROR_FILE_NOT_FOUND:
            sys.exit(f"打不开 {port}：端口不存在（设备没进 BROM / 驱动没装？）")
        if err == ERROR_ACCESS_DENIED:
            sys.exit(f"打不开 {port}：端口被占用（关掉 spd_dump / 其它串口工具）")
        sys.exit(f"打不开 {port}：Win32 错误 {err}")

    dcb = DCB()
    dcb.DCBlength = ctypes.sizeof(DCB)
    if not kernel32.GetCommState(h, ctypes.byref(dcb)):
        sys.exit("GetCommState 失败")
    dcb.BaudRate = baud
    dcb.ByteSize = 8
    dcb.Parity = 0        # NOPARITY
    dcb.StopBits = 0      # ONESTOPBIT
    dcb.fBinary = 1
    dcb.fParity = 0
    dcb.fOutxCtsFlow = 0
    dcb.fOutxDsrFlow = 0
    dcb.fDtrControl = 1   # DTR_CONTROL_ENABLE
    dcb.fDsrSensitivity = 0
    dcb.fOutX = 0
    dcb.fInX = 0
    dcb.fRtsControl = 1   # RTS_CONTROL_ENABLE
    dcb.fAbortOnError = 0
    if not kernel32.SetCommState(h, ctypes.byref(dcb)):
        sys.exit("SetCommState 失败（波特率不被支持？）")

    to = COMMTIMEOUTS(50, 0, 50, 0, 0)
    kernel32.SetCommTimeouts(h, ctypes.byref(to))
    kernel32.PurgeComm(h, 0x0004 | 0x0008)   # PURGE_RXABORT|PURGE_RXCLEAR
    return h


def main():
    ap = argparse.ArgumentParser(description="纯标准库串口日志抓取")
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--list", action="store_true", help="列出可用串口")
    ap.add_argument("--save", help="同时保存到文件")
    ap.add_argument("--seconds", type=float, default=0,
                    help="抓取时长（秒），0 = 一直抓直到 Ctrl+C")
    args = ap.parse_args()

    if args.list:
        ports = list_ports()
        if not ports:
            print("注册表里没有串口（设备没进 BROM / SPD 驱动没装？）")
        for port, driver in ports:
            print(f"  {port:8s} ({driver})")
        return 0

    h = open_port(args.port, args.baud)
    print(f"[uart_log] 已打开 {args.port} @ {args.baud} 8N1")
    print("[uart_log] 现在给设备上电 / 重启；Ctrl+C 停止\n")

    fh = open(args.save, "wb") if args.save else None
    buf = ctypes.create_string_buffer(4096)
    nread = wt.DWORD(0)
    t0 = time.time()
    total = 0
    try:
        while True:
            ok = kernel32.ReadFile(h, buf, 4096, ctypes.byref(nread), None)
            if nread.value:
                chunk = buf.raw[:nread.value]
                total += nread.value
                if fh:
                    fh.write(chunk)
                    fh.flush()
                sys.stdout.write(chunk.decode("utf-8", "replace"))
                sys.stdout.flush()
            elif not ok:
                err = ctypes.get_last_error()
                if err not in (0, 995):   # 995 = ERROR_OPERATION_ABORTED
                    print(f"\n[uart_log] ReadFile 错误 {err}")
                    break
            else:
                time.sleep(0.01)
            if args.seconds and time.time() - t0 >= args.seconds:
                break
    except KeyboardInterrupt:
        print("\n[uart_log] 用户中断")
    finally:
        if fh:
            fh.close()
            print(f"\n[uart_log] 已保存到 {os.path.abspath(args.save)}（{total} 字节）")
        kernel32.CloseHandle(h)
        print(f"[uart_log] 共收到 {total} 字节")
    return 0


if __name__ == "__main__":
    sys.exit(main())
