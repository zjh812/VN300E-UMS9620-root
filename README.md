# VN300E / T9100 (UNISOC UMS9620) — U-Boot magic64 解锁 + 去警告 + SukiSU root

> 面向 **紫光 T9100 / VN300E（Mario_12_2_5G，UMS9620，Android 14）** 的完整方案。
> 用**签名保持（magic64）**的方式改 U-Boot 运行期行为：设备报解锁、跳过 AVB 校验、
> 启动完全静默，并配合 patched `init_boot` 拿到 SukiSU root。
>
> **已在真机验证通过**（UMS9620 / VN300E，slot B）。

---

## ⚠️ 先读这段

- **🛑 动手前先做完整备份** —— 仓库提供一键脚本
  [`tools/backup_all_partitions.bat`](tools/backup_all_partitions.bat)（纯只读，
  dump 全部 73 个分区 + SHA256）。**没有备份的人不该往下走**，
  详见 [第 0 步](#-第-0-步完整备份必做先做这个)。
- 本仓库**不含任何签名私钥**，也不破解签名。做法是「让原厂签名继续有效，
  在**签名校验通过之后**于内存里改几条指令」。
- 你会**改动 U-Boot 与 init_boot 两个分区**，并**清一次 userdata**。
  **刷之前务必备份数据**。
- `ro.boot.verifiedbootstate` 会从 `green` 变成 **orange**（解锁态的正常表现），
  部分银行 / DRM / 支付类 App 可能拒绝运行。
- **只在你自己的设备上操作。** 作者不对任何损坏负责。
- **本仓库不含任何预编译镜像**（既不含原厂分区镜像，也不含打好补丁的成品）。
  你用自己的原厂 `uboot_b` / `init_boot_b`，配合 `tools/` 里的脚本现场生成 ——
  这样既没有固件再分发问题，你拿到的也一定是与你设备版本匹配的东西。

---

## 一、原理（30 秒版）

UMS9620 的 SPL 会对 U-Boot 做 **RSA 校验**，所以「改一个字节再重算 hash」会被直接拒绝。

magic64 的做法是**完全不碰签名覆盖区**：

```
文件布局（打包后）
  0x000  DHTB header（data_size += 0x100）
  0x200  entry jump  ──┐  原本这里是 payload 的第一条指令
  0x210  原厂 signed payload（逐字节不变 → hash 与 RSA 签名都还有效）
  ...    magic64 shellcode + patch table（签名覆盖区之外）
  ...    SIMGHDR footer（payload_offset 0x200 → 0x210）
  ...    RSA 证书（整体平移 +0x100）
```

SPL 校验原样的 payload → 通过 → 跳到 `0x200` 的跳转指令 → shellcode 把 payload
搬回 `0xB5000000`、按 patch table 改几个字、刷 cache → 跳回真正的 `_start`。

**LOAD_BASE = `0xB5000000`**（从设备自己的 `uboot_log` 分区实证推导，见
[`docs/逆向分析报告.md`](docs/逆向分析报告.md)）。

---

## 二、完整步骤

> ## 🛑 第 0 步：完整备份（**必做，先做这个**）
>
> **不备份就不要往下走。**
>
> 本方案会写 `uboot_b` 和 `init_boot_b` 两个分区，并触发一次清数据。
> **没有备份 = 没有退路。**
>
> ### 仓库提供了现成的一键备份脚本
>
> **[`tools/backup_all_partitions.bat`](tools/backup_all_partitions.bat)**
>
> | | |
> |---|---|
> | **做什么** | 只读 GPT → dump 全部 73 个分区 → 生成 `SHA256SUMS.txt` → 打日志 |
> | **不做什么** | **不含任何 `w`(write) / `e`(erase) / repartition 命令 —— 纯只读** |
>
> **用法**
>
> 1. 从 [CVE-2022-38694 工具包](https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader)
>    取 `spd_dump.exe`、`Channel9.dll`、`Channel.ini`、`fdl1-dl.bin`、`fdl2-dl.bin`、
>    `custom_exec_no_verify_65012f48.bin`，放到脚本**同目录**或**同目录的 `bin\` 子目录**
> 2. 设备**完全关机** → 按住 **音量-** 不松手，插入 USB（进 BROM）
>    - 成功标志：设备管理器出现新的 COM 口，或 `spd_dump` 打印
>      `BSL_REP_VER: "SPRD3"` / `CMD_CONNECT bootrom`
>    - 若进不去：换一条**数据线**（不是充电线）、重插、或试 电源+音量上 / 三键同按
> 3. 双击 `backup_all_partitions.bat`，跟着提示走
> 4. 备份落在 `backup\T9100_<时间戳>\`，含 `SHA256SUMS.txt`
>
> **刷写前必须确认这几个文件已生成**（回滚全靠它们）：
>
> ```
> uboot_b.bin      init_boot_b.bin      splloader.bin
> miscdata.bin     misc.bin
> ```
>
> **为什么这一步不能省**：BootROM 是掩膜 ROM，物理上改不了、永远可用 ——
> 所以只要 `splloader` 的备份在，即使 `uboot` 完全起不来，也能从 BROM 写回恢复。
> 反过来，**没有备份的人不该动手**。
>
> ---

### 0.1 所需工具与来源（本仓库**不打包**第三方工具）

下面这些是刷写/备份必需的，但**都是别人项目的产物**，本仓库不重复分发 ——
请从上游获取最新版：

| 工具 | 来源 |
|---|---|
| `spd_dump.exe`、`Channel9.dll`、`Channel.ini` | [TomKing062/CVE-2022-38694_unlock_bootloader](https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader) → Releases → **UMS9620 / universal 包** |
| `fdl1-dl.bin`、`fdl2-dl.bin`、`fdl2-cboot.bin` | 同上（同一个包里） |
| `custom_exec_no_verify_65012f48.bin` | 同上 —— UMS9620 的 BROM exploit payload，exec 地址 **`0x65012f48`** |
| `chsize.exe`、`gen_spl-unlock.exe`、`spl-unlock.bin`、`misc-wipe.bin` | 同上（**标准解锁流程**用的；本方案的 magic64 路线**不需要**它们） |

**DRAM 类型坑**：官方包按 DRAM 类型区分，`fdl1-dl.bin` 有多个版本。
若 `spd_dump` 报 `FDL2: incompatible partition` 或直接 timeout，
**换另一套 DRAM 类型的 `fdl1-dl.bin` 重试**（其余文件相同）。

**为什么不打包**：
1. 它们属于上游项目，重复打包既无必要，也可能与其许可冲突
2. 你从上游拿到的总是最新版
3. 二进制第三方可执行文件放进本仓库会显著增加信任成本

**本仓库提供的是**：magic64 补丁方案、patch offset 表、构建/验证工具链、
以及从自己原厂镜像重建的完整方法。

**你需要自己准备（从你自己的设备备份）**：
`uboot_b.bin`、`init_boot_b.bin` 等原厂分区镜像 —— 这些是**你设备的数据**，
别人无法也不应该提供。用上游工具的 `r all` 做全分区备份即可。

### 1. 刷 U-Boot（解锁 + 静默）

```bat
spd_dump --wait 300 exec_addr 0x65012f48 fdl fdl1-dl.bin 0x65000800 ^
         fdl fdl2-dl.bin 0xb4fffe00 exec w uboot_b <uboot镜像> reset
```

**只写 `uboot_b` 一个分区。** 刷完开机 logo 上不会再有：
- `INFO: LOCK FLAG IS : UNLOCK!!!`
- `WARNNING: LOCK FLAG IS : UNLOCK, SKIP VERIFY!!!`
- `INFO: Press power button to pause./continue.`
- `WARNNING: your device has loaded a different operating system.`

并且启动**快约 10 秒**（电源键倒计时被去掉）。

### 2. 首次开机会要求清数据

因为 `verifiedbootstate` 从 green 变 orange，Android 会提示
`Can't load Android system. Your data may be corrupt.` —— 这是**预期行为**。
在 recovery 里做一次 `Wipe data / factory reset` 即可。

> **想保住数据的话**：先写回原厂 `uboot_b` → 设备回到 green 态正常开机 →
> 备份数据 → 再刷回来。但这一次清数据最终躲不掉（除非能重新签名，而你没有私钥）。

### 3. 刷 patched init_boot（root）

```bat
spd_dump --wait 300 exec_addr 0x65012f48 fdl fdl1-dl.bin 0x65000800 ^
         fdl fdl2-dl.bin 0xb4fffe00 exec w init_boot_b <patched_init_boot> reset
```

用 SukiSU 的 LKM 方案**补丁你自己的原厂 `init_boot_b`** ——
见 [SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra)（管理器内直接对 `init_boot` 打补丁，
或按它的文档在本地操作）。

> 本仓库不提供任何预编译的 `init_boot` —— 它和 `uboot` 一样属于设备固件，
> 而且必须与你自己的固件版本匹配。**请用你自己的原厂 `init_boot_b` 现场补丁。**
>
> 补丁完成后的自检：文件仍是 `ANDROID!` 头，`0x0C` 处的 kernel size 会比原厂大
> （原厂 `0x20E3DE` → 打过 SukiSU 的约 `0x28607D`，具体以你的版本为准）。

### 4. 装管理器

```bat
adb install SukiSU_v4.2.0_40900-release.apk
adb shell /data/adb/ksu/bin/su -c id     # 期望 uid=0(root)
```

---

## 三、patch 点表

**`code_offset` 相对 DHTB payload**（`file_off = 0x200 + code_offset`）。

| code offset | 原指令 | 目标 | 作用 |
|---|---|---|---|
| `0x627E8` | `0xB948CA95` `ldr w21,[x20,#0x8c8]` | `0x52800035` `mov w21,#1` | 强制解锁（`read_lock_flag` 失败的提前返回路径） |
| `0x627F0` | `0x97FF3759` `bl free` | `0xB908CA95` `str w21,[x20,#0x8c8]` | 写 `g_DeviceStatus = 1` |
| `0x62830` | `0x350002A0` `cbnz w0,#0x62884` | `0xD503201F` `nop` | 强制解锁（读成功时的校验路径） |
| `0xB4B0` | `0x54000060` `b.eq #0xB4BC` | `0xD503201F` `nop` | 去掉 `Press power button to pause` + 10 秒 |
| `0xB504` | `0x54000180` `b.eq #0xB534` | `0xD503201F` `nop` | 去掉 `INFO: LOCK FLAG IS : UNLOCK!!!` |
| `0xB7478` | `0x1D000A16`（跳表） | `0x1D000016` | state 1 → state 2，整组「不同 OS」警告消失 |
| `0xB7B8` | `0x94009DA3` `bl #0x32E44` | `0xD503201F` `nop` | 去掉 `SKIP VERIFY`（UART） |
| `0xB7C0` | `0x9401F0BD` `bl #0x87AB4` | `0xD503201F` `nop` | 去掉 `SKIP VERIFY`（屏幕） |
| `0x6AC10` | `0xB4000060` `cbz x0,#0x6AC1C` | `0xD503201F` `nop` | 降级加载器补丁 |
| `0x6AC18` | `0xB5FFF820` `cbnz x0,#0x6AB1C` | `0x17FFFFC1` `b #0x6AB1C` | 无条件进加载流程（改过的 init_boot 靠它启动） |

机器可读版本：[`patches/vn300e_patch_set.json`](patches/vn300e_patch_set.json)

---

## 四、工具

| 脚本 | 用途 |
|---|---|
| **`tools/backup_all_partitions.bat`** | **🛑 先跑这个** —— 一键全分区只读备份（dump 全部 73 分区 + SHA256 + 日志）。**不含任何写/擦命令** |
| `tools/T9100_build_probe_magic64.py` | **通用 magic64 镜像构建器**：`--patch code_off=expected[:target]`，自带 SHA256 / 精确指令校验 |
| `tools/magic64_verify.py` | **只读验证器 + AArch64 shellcode 模拟执行**：解析 DHTB/SIMGHDR/patch table，跑一遍 shellcode 并比对 RAM |
| `tools/check_t9100_uboot_offsets.py` | 只读 offset 验证器（35 项检查 + 模拟执行） |
| `tools/check_boot_log.py` | 分析 `uboot_log` 分区：逐启动周期 + 来源核查 + 判定补丁是否生效 |
| `tools/analyze_log_sources.py` | 排查一份 `uboot_log` 到底来自哪台设备 / 哪个固件 |
| `tools/list_last_boots.py` | 列出日志里最后 N 次启动的设备与固件版本 |
| `tools/uart_log.py` | 纯标准库（ctypes/Win32）串口抓取，无第三方依赖 |

### 从你自己的原厂 uboot 构建

```bash
python tools/T9100_build_probe_magic64.py \
  --input  <你的原厂 uboot_b.bin> \
  --patch 0x627e8=0xb948ca95:0x52800035 \
  --patch 0x627f0=0x97ff3759:0xb908ca95 \
  --patch 0x62830=0x350002a0 \
  --patch 0xb4b0=0x54000060 \
  --patch 0xb504=0x54000180 \
  --patch 0xb7478=0x1d000a16:0x1d000016 \
  --patch 0xb7b8=0x94009da3 \
  --patch 0xb7c0=0x9401f0bd \
  --patch 0x6ac10=0xb4000060 \
  --patch 0x6ac18=0xb5fff820:0x17ffffc1 \
  --output my_uboot_b.img
```

脚本会先核对输入 SHA256（必须是已知原厂镜像）和每条补丁点的**原始指令逐位相等**，
任一不符即中止、不写任何字节。

构建后离线验证：

```bash
python tools/magic64_verify.py --stock <原厂uboot_b.bin> --patched my_uboot_b.img \
  --load-base 0xb5000000 \
  --patches "0x627e8=0x52800035,0x627f0=0xb908ca95,0x62830=0xd503201f,0xb4b0=0xd503201f,0xb504=0xd503201f,0xb7478=0x1d000016,0xb7b8=0xd503201f,0xb7c0=0xd503201f,0x6ac10=0xd503201f,0x6ac18=0x17ffffc1"
```

---

## 五、回滚

```bat
spd_dump --wait 300 exec_addr 0x65012f48 fdl fdl1-dl.bin 0x65000800 ^
         fdl fdl2-dl.bin 0xb4fffe00 exec w uboot_b <你的原厂uboot_b.bin> reset
```

`init_boot_b` 同理。**BootROM 是掩膜 ROM，永远可用** —— 只要 `splloader` 没动，
最坏情况都能从 BROM 恢复。

**绝对不要刷 `splloader`** —— fused 设备上它被 RSA 校验，改了必砖。

---

## 六、文档

| 文档 | 内容 |
|---|---|
| [`build/README.md`](build/README.md) | **从你自己的原厂镜像构建的完整可复制流程**（备份 → 构建 → 离线验证 → 刷入） |
| [`docs/逆向分析报告.md`](docs/逆向分析报告.md) | 镜像结构、4 个 patch 点推导、lock-state 调用链、AVB 路径 |
| [`docs/magic64-生成与验证报告.md`](docs/magic64-生成与验证报告.md) | LOAD_BASE 推导、SPL 代码级兼容性验证、模拟执行结果 |
| [`docs/操作步骤.md`](docs/操作步骤.md) | 逐步命令 |
| [`docs/刷写范围与风险.md`](docs/刷写范围与风险.md) | 写哪些分区、风险清单、回滚 |
| [`docs/项目完成总结.md`](docs/项目完成总结.md) | 最终状态、历史镜像与 SHA256 |
| [`docs/方法论-unisoc-uboot-magic64-offline.md`](docs/方法论-unisoc-uboot-magic64-offline.md) | 可复用到其他 UMS9620 机型的方法论 + 4 个高频踩坑 |

---

## 七、关键踩坑（省你几个小时）

1. **`patch 生效 ≠ 效果达成`** —— `get_lock_status()` 里 patch 了 `cbnz w0, LOCK`，
   但设备毫无变化。原因是更早的 `read_lock_flag()` 读 `miscdata` 偏移 `0x2000`
   拿到**全 0 缓冲**、返回 -1，函数**提前 return 0** 了，根本走不到被 patch 的指令。
   → 改之前先把函数**所有返回路径**列出来。
2. **函数可达性不能只扫 `bl`/`b`** —— 编译器会用「前一条指令先设好参数 + **顺序落入**
   下一条函数的 prologue」来调用（这里 `bl 0xB498`，真正的入口在 `0xB4A0`）。
   → 分支目标附近 ±2 条指令也要纳入可达集合。
3. **环形缓冲日志里「删掉一行」判不出来** —— 旧内容残留 + 计数不稳定。
   → 改成「把一个每次启动必打印的字符串改成唯一标记」，出现即证明执行。
4. **magic64 patch table 上限 0x80 字节 / 每条 12 字节 → 最多 10 条**。
   → 优先用「改跳表 / 改状态值」的单点补丁，替代「逐个 NOP 打印」的多点补丁。

---

## 八、致谢

- magic64（Patch-Post-Verification）方法来自 `unisoc_chipram_signcheck` 相关研究
- BROM 漏洞利用（CVE-2022-38694）：[TomKing062/CVE-2022-38694_unlock_bootloader](https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader)
- 参考实现：[UnisocBypass](https://github.com/)（`magic_pack_ums9620.py` 的 shellcode 与打包布局）

## License

MIT —— 见 [`LICENSE`](LICENSE)。

本仓库**只包含代码与文档**，不含任何原厂固件或预编译镜像。
你用它处理的是**你自己设备上的、你自己备份出来的**镜像。
