# T9100 / VN300E (UMS9620) magic64 解锁镜像 — 离线生成与验证报告

> **阶段**：离线生成 + 离线验证。**未刷写设备、未修改 SPL、未修改 miscdata、未修改 vbmeta、未修改原始 `uboot_b.bin`、未执行 `spd_dump write`、未执行 `fastboot flash`。**
>
> **原始输入**：`C:\Users\admin\Desktop\B\T9100\backup\T9100_back\uboot_b.bin`
> SHA256 `5935075bed5b12d35b961d0e39a4e95154b8cfb94ac177f96919700a24b8e321`（运行前后均已复验，**未变化**，mtime 仍为 `Sep 30 22:43`）
>
> **官方仓库**：`C:\Users\admin\Desktop\B\T9100\UnisocBypass-main` — **未修改任何原文件**（`tools/` 下全部文件 mtime 仍为 `Aug 1 06:31`；patcher 以 `sys.dont_write_bytecode = True` 导入，未写入新的 `.pyc`）

---

## 结论速览

| 项目 | 结果 |
|---|---|
| LOAD_BASE | **`0xB5000000`** — 由**本机 uboot_log 分区实测日志**推导，置信度 **极高（设备实证）** |
| 4 个 patch 点严格校验 | **4/4 精确匹配**（32 位原始字逐位相等） |
| 输出镜像大小 | `3145728` = `0x300000` ✅ |
| 输出 SHA256 | `dfe33c1501ee2988d46ccf9531712845dbd2779b4e427d95cbd0f0d988b7f39e` |
| 原始 signed payload | **byte-for-byte 一致** ✅ |
| RSA 签名 / SIMGHDR | **完全保持，未重新签名** ✅ |
| 模拟执行验证 | **35/35 全部通过**，RAM 中恰好出现 4 个 `0xD503201F` |
| 是否推荐进入下一阶段 | **推荐**（附 1 项必须人工确认的残余风险，见 H 节） |

---

## A. LOAD_BASE 推导过程

### A.1 结论

```
LOAD_BASE = 0xB5000000
```

**这不是照抄官方默认值** —— 官方 `magic_pack_ums9620.py` 的 `DEFAULT_LOAD_BASE = 0xB5000000` 是针对 Anbernic T820 那台机器确认的。本报告的 `0xB5000000` 来自**你这台 VN300E 自己的 `uboot_log` 分区日志**，属于设备实证。

### A.2 证据来源

`C:\Users\admin\Desktop\B\T9100\backup\T9100_back\uboot_log.bin`（16 MB，`uboot_log` 分区原样备份）

先确认这份日志确实来自**你这台设备**：

| 日志内容 | 说明 |
|---|---|
| `fixup androidboot.serialnotwo=CUVN300E**********` | VN300E 序列号，与你的设备一致 |
| `androidboot.verifiedbootstate=green`（104 次） | 与「原厂 locked / verifiedbootstate=green」一致 |
| `fixup androidboot.flash.locked=1` / `INFO: LOCK FLAG IS : LOCK`（51 次） | 抓取日志时设备处于 **LOCKED** 原厂状态 |
| `platform: qogirn6pro` / `target: ums9620_2h10` / `release: user` | UMS9620 平台 |

**✅ 日志与 `uboot_b.bin` 同源、同设备、同状态。**

### A.3 四条互相印证的关键日志行

```
[00003017] [c0] sprd_get_vboot_key(): load_buf is 0x0xb4fffe00.      (出现 63 次)
[00003017] [c0] sprd_get_vboot_key(): sechdr_addr is 0x0xb5171630.   (出现 126 次)
[00003017] [c0] sprd_get_vboot_key(): sechdr_addr: 0xb5171630. cert_addr: 0xb5171690.
[00003758] [c1] sysdump-uboot: addr is 0xb5000000, size is 0x1000000 (出现 51 次)
```

### A.4 推导（全部用你自己的镜像字节对得上）

| 推理 | 计算 | 日志值 | 一致 |
|---|---|---|---|
| 镜像基址 | `load_buf` | `0xb4fffe00` | — |
| **payload 基址** | `0xb4fffe00 + 0x200`（DHTB header 长度） | `0xb5000000` | ✅ |
| SIMGHDR 运行地址 | `0xb4fffe00 + 0x171830`（SIMGHDR 文件偏移，实测） | `0xb5171630` | ✅ |
| SIMGHDR 运行地址（另一算法） | `0xb5000000 + 0x171630`（payload size，实测 `data_size`） | `0xb5171630` | ✅ |
| 证书运行地址 | `0xb5171630 + 0x60`（sechdr 长度） | `0xb5171690` | ✅ |
| U-Boot 运行区基址 | `sysdump-uboot` 报告 | `0xb5000000`，大小 `0x1000000` | ✅ |

**两条完全独立的路径（文件偏移 vs payload 长度）算出同一个 `0xb5171630`，且与日志逐位相符 —— 这排除了"基址猜对但布局理解错"的可能。**

### A.5 二进制侧独立佐证

对 `uboot_b.bin` 的 payload 做全量扫描（8 字节对齐）：

| 检查 | 结果 |
|---|---|
| payload 中落在 `0xb4fffe00 .. 0xb6000000` 的 8 字节绝对值 | **1115 个** |
| 落在 `0xb5000000 .. 0xb5171630` 的 8 字节绝对值 | **1107 个** |
| 若基址不是 `0xb5000000`，这些指针的命中概率 | ≈ `0x1000200 / 2^64 × 377k ≈ 2e-5`（即**不可能是巧合**） |

页面分布也符合"指针表"特征（集中在 `0xb50cxxxx` ×328、`0xb50dxxxx` ×207、`0xb508xxxx` ×186、`0xb50bxxxx` ×127）。

> ⚠️ 顺带排除了一个假阳性：payload 里出现的 `0xb4fffe00` 字面量（code `0x2c814` / `0x89724`）经反汇编确认是 **`cbz x0, ...` 指令编码**（`0xb4fffe00` 恰好等于该指令字），**不是** 数据引用。已在报告中剔除，未作为证据。

### A.6 与官方 magic64 方案的一致性

官方 shellcode 是 **PC 相对自定位** 的（不硬编码 LOAD_BASE），已在本机生成的镜像上反汇编确认：

```
+0x00  f0fff469  adrp x9, #0xb5000000      <- 自动算出 payload 基址 = LOAD_BASE
+0x04  9100412a  add  x10, x9, #0x10       <- 源地址 = LOAD_BASE+0x10（SPL 按新 payload_offset 加载处）
+0x08  d2a0004b  mov  x11, #0x20000
+0x0c  f29c58cb  movk x11, #0xe2c6         <- x11 = 0x2E2C6 = 0x171630/8（payload 字数）
       ...（拷贝循环：把 payload 从 +0x10 搬回 LOAD_BASE）
+0x34  90000009  adrp x9, #0xb5171000
+0x38  911ac129  add  x9, x9, #0x6b0       <- patch table 运行地址 0xb51716b0
       ...（patch 循环：按表写绝对地址）
+0x6c  17fa3a55  b    #0xb5000000          <- 回跳 real _start
```

**因此 `LOAD_BASE` 唯一的作用就是 patch table 里的绝对地址**（拷贝与回跳都是自定位的）。这也意味着：`LOAD_BASE` 一旦错，后果是"往随机内存写 NOP" —— 所以这一项必须确认，不能猜。本报告已确认。

### A.7 置信度

| 项 | 判定 |
|---|---|
| LOAD_BASE 数值 | **`0xB5000000`** |
| 置信度 | **极高（HIGH-CONFIDENCE / 设备实证）** |
| 依据等级 | ① 本机设备运行日志（最强）② 镜像内 1115 个绝对指针自洽 ③ 与官方 T820 结论吻合 |
| 是否 UNKNOWN | **否** — 因此按你的要求，可以继续生成镜像 |

---

## B. 四个 patch 点验证结果

### B.1 严格校验（32 位原始字必须逐位相等）

`T9100_patch_uboot_unlock_ums9620.py` 在写任何字节之前执行：

```
--- patch point verification (exact 32-bit word match) ---
   #   code_off   file_off       found    expected  result  semantics
   1  0x0062830  0x0062a30  0x350002a0  0x350002a0      OK  get_lock_status(): cbnz w0 -> nop (force UNLOCK)
   2  0x000b504  0x000b704  0x54000180  0x54000180      OK  unlock warning branch: b.eq -> nop
   3  0x000b7b8  0x000b9b8  0x94009da3  0x94009da3      OK  SKIP_VERIFY UART print: bl -> nop
   4  0x000b7c0  0x000b9c0  0x9401f0bd  0x9401f0bd      OK  SKIP_VERIFY screen print: bl -> nop
```

**4/4 精确匹配**。文件 offset 由 `0x200 + code_offset` 计算，**未把文件 offset 当 code offset 传给 magic_pack**（传给 `pack()` 的是 code offset，由 packer 内部拼进 patch table）。

### B.2 另外 4 道前置闸门

| 闸门 | 结果 |
|---|---|
| `data[0:4] == b"DHTB"` | ✅ |
| SHA256 == `5935075b…b8e321` | ✅ MATCH |
| 文件大小 == `0x300000` | ✅ |
| `footer.payload_offset == 0x200`（未被打过补丁） | ✅ |
| 输出路径 ≠ 输入路径（防覆盖） | ✅ 已硬校验 |

任意一项失败即 `sys.exit`，**不写任何字节**。

---

## C. patched 镜像文件大小

```
3145728 bytes  =  0x300000   （== uboot_b 分区大小）
```

内部布局（文件 offset）：

| 区间 | 内容 | 大小 |
|---|---|---|
| `0x000000 .. 0x000200` | DHTB header（`data_size` 由 `0x171630` → `0x171730`） | `0x200` |
| `0x000200 .. 0x000210` | magic64 entry jump（`b 0x171840`）+ 12 字节 0 | `0x10` |
| `0x000210 .. 0x171840` | **原始 signed payload（逐字节未变）** | `0x171630` |
| `0x171840 .. 0x1718B0` | magic64 shellcode（28 条 AArch64 指令） | `0x70` |
| `0x1718B0 .. 0x1718E4` | patch table（4 项 × 12 字节 + 4 字节零终止） | `0x34` |
| `0x1718E4 .. 0x171930` | 0 填充 | `0x4C` |
| `0x171930 .. 0x171990` | SIMGHDR / sechdr footer（`payload_offset` = `0x210`） | `0x60` |
| `0x171990 .. 0x171DE8` | RSA 证书块（`sig_struct_size` = `0x458`） | `0x458` |
| `0x171DE8 .. 0x300000` | 全 0 padding（1630744 字节） | — |

**未超出 `0x300000`**：镜像真实内容（最后一个非零字节）从 `0x171CE7` 平移到 `0x171DE7`，**只丢弃了原文件尾部的 0 填充**（校验：`last_nonzero_patched - last_nonzero_stock == 0x100` ✅；`patched[0x171DE8:]` 全 0 ✅）。

---

## D. SHA256

| 文件 | SHA256 |
|---|---|
| 原始 `uboot_b.bin` | `5935075bed5b12d35b961d0e39a4e95154b8cfb94ac177f96919700a24b8e321` |
| **`T9100_uboot_b_unlock_magic64.img`** | **`dfe33c1501ee2988d46ccf9531712845dbd2779b4e427d95cbd0f0d988b7f39e`** |

---

## E. payload byte-for-byte 是否一致

**一致。** 分两层验证：

1. **文件层面**
   ```
   patched[0x210 : 0x210 + 0x171630]  ==  stock[0x200 : 0x200 + 0x171630]     ✅ 1513008 bytes
   ```
   （patcher 内部断言 + checker 独立复验，两处都通过）

2. **RAM 层面（模拟执行后）**
   模拟执行 shellcode 后，`LOAD_BASE .. LOAD_BASE+0x171630` 与原始 payload 对比：
   ```
   32-bit words differing from the stock payload: 4
     code 0x00b504 (runtime 0xb500b504): 0x54000180 -> 0xd503201f
     code 0x00b7b8 (runtime 0xb500b7b8): 0x94009da3 -> 0xd503201f
     code 0x00b7c0 (runtime 0xb500b7c0): 0x9401f0bd -> 0xd503201f
     code 0x062830 (runtime 0xb5062830): 0x350002a0 -> 0xd503201f
   ```
   **除这 4 个字以外，1513008 字节逐字节相同。** ✅

---

## F. SIMGHDR / RSA payload 是否保持

| 检查项 | 结果 |
|---|---|
| RSA 证书块（`0x458` 字节）byte-identical（仅整体平移 `+0x100`） | ✅ |
| RSA modulus（`0x100` 字节）一致 | ✅ |
| **RSA 签名块（`cert+0x154 .. cert+0x254`）逐字节一致 → 未被重新生成** | ✅ |
| 证书 flags / exponent 字一致 | ✅ |
| SIMGHDR magic 存在于新 payload 末尾（file `0x171930`） | ✅ |
| footer `payload_offset`：`0x200` → `0x210` | ✅ |
| footer `+0x28`（total_offset）：`0x171890` → `0x171990`（`+0x100`） | ✅ |
| 未做任何签名操作 | ✅ |

**布局逻辑**：原始 signed payload 原封不动搬到 `0x210`，footer 通过 `payload_offset = 0x210` 指向它 —— 这正是 magic64「签名校验看原样 payload、我们的代码走在签名覆盖区之外」的核心。**签名本身一个字节都没碰。**

---

## G. 四个 runtime patch address

| # | code offset | runtime address | 写入值 | 语义 |
|---|---|---|---|---|
| 1 | `0x62830` | **`0xB5062830`** | `0xD503201F` | `get_lock_status()` 强制走 UNLOCK |
| 2 | `0x0B504` | **`0xB500B504`** | `0xD503201F` | 去掉 unlock warning 分支 |
| 3 | `0x0B7B8` | **`0xB500B7B8`** | `0xD503201F` | 去掉 SKIP_VERIFY UART 打印 |
| 4 | `0x0B7C0` | **`0xB500B7C0`** | `0xD503201F` | 去掉 SKIP_VERIFY screen 打印 |

即 `LOAD_BASE (0xB5000000) + code_offset`。patch table 实际字节（file `0x1718B0`，运行时 `0xB51716B0`）：

```
+0x00: addr 0xb5062830 len 1 word 0xd503201f
+0x0c: addr 0xb500b504 len 1 word 0xd503201f
+0x18: addr 0xb500b7b8 len 1 word 0xd503201f
+0x24: addr 0xb500b7c0 len 1 word 0xd503201f
+0x30: addr 0x00000000 len 0 word 0x00000000   <- 零终止
```

---

## 模拟执行验证（第四项任务）

`T9100_check_magic64.py` 内建一个 AArch64 迷你解释器（覆盖 magic64 shellcode 用到的全部指令：`adrp / add / movz / movk / mov / subs / b / b.cond / cbz / ldr / str / ic / isb`），把 patched 镜像按 `IMG_BASE = 0xB4FFFE00` 装进内存模型后**真跑一遍 shellcode**。

```
--- 6. simulated execution of the appended shellcode ---
  image base (file 0)           : 0xb4fffe00
  entry / LOAD_BASE (file 0x200): 0xb5000000
  shellcode (file 0x171840)     : 0xb5171640
  patch table (file 0x1718b0)   : 0xb51716b0
  emulated 1513076 instructions
  [PASS] shellcode ran to completion (no unsupported instruction)  -- 0 problem(s)
  [PASS] shellcode made no out-of-range memory access              -- 0 OOB
  [PASS] shellcode handed control to the real _start at LOAD_BASE  -- 0xb5000000
  [PASS] shellcode final branch returns to the real _start         -- 0xb51716ac -> 0xb5000000
  [PASS] the first shellcode adrp resolves to LOAD_BASE (self-locating)
  [PASS] exactly the 4 intended code words changed in RAM
  [PASS] all 4 changed words are 0xD503201F (nop)
```

**逐条对应你要求的 5 项：**

| 你的要求 | 结果 |
|---|---|
| 1. magic64 entry jump 指向 shellcode | ✅ `file 0x200` 的 `b` → `file 0x171840`，与 shellcode 实际位置一致 |
| 2. shellcode 最终回跳 real `_start` | ✅ 末条 `b` @ `0xB51716AC` → **`0xB5000000`** |
| 3. patch table 四项地址正确 | ✅ 四项 = `LOAD_BASE + code_offset` |
| 4. patch word 都是 `0xD503201F` | ✅ 4/4 |
| 5. stock payload 未改变 | ✅ 文件层 + RAM 层双重验证 |

**总计 `35/35 checks passed`。**

---

## H. 是否推荐进入下一阶段

### ✅ 推荐进入下一阶段（离线阶段已完成）

理由：
1. `LOAD_BASE` **不是猜的** —— 本机 `uboot_log` 分区日志给出四条互相印证的行，且与镜像自身 1115 个绝对指针自洽。
2. 4 个 patch 点在**精确逐位匹配**下通过，不存在"掩码模糊匹配"的不确定性。
3. 原始 signed payload 与 RSA 签名**完全未动**，magic64 布局与官方实现逐字段一致（`data_size +0x100`、`payload_offset → 0x210`、footer 偏移字段 `+0x100`、证书整体平移）。
4. 模拟执行给出**预期结果**：RAM 中恰好 4 个 NOP，其余 1513008 字节不变，控制权正确交还 `_start`。
5. 镜像大小严格等于分区大小，只丢弃了原本就是 0 的尾部填充。

### ✅ 残余风险已大幅降低（本轮新增：SPL 代码级证据）

上一版报告把「SPL 是否按 `payload_offset` 定位 payload」列为离线无法证明的风险。
**本轮反汇编 `splloader.bin` 后，这个风险已经用代码证据基本消除。**

`sechdr = image_base + 0x200 + data_size` 这条规则同时出现在 U-Boot 与 SPL 两侧：

| 位置 | 代码 | 作用 |
|---|---|---|
| `uboot_b` code `0x646E4` (`sprd_get_sechdr_addr`) | `ldr w0,[x19,#0x30]` → `add x0,x0,#0x200` → `add x0,x19,x0` | 由 `data_size` 算 sechdr 地址，**无硬编码常量** |
| `uboot_b` code `0x64BC0` (`sprd_get_vboot_key`) | 同上 + 打印 `sechdr_offset is 0x%llx` | 与日志 `sechdr_offset is 0x171830` 逐位相符 |
| `splloader` code `0xBA8C` | `ldr w3,[x0,#0x30]` → `add x3,x3,#0x200` → `add x3,x0,x3` | SPL 侧同一算法 |
| `splloader` code `0xBF78` | `ldr w21,[x1,#0x30]` → `add x21,x21,#0x200` → `add x21,x1,x21` | SPL 侧同一算法 |

**决定性的一条** —— `splloader` code `0xBF50`：

```
0xBF50: ldr  w1, [x0, #0x30]     ; w1 = data_size
0xBF54: add  x1, x0, x1          ; x1 = image + data_size
0xBF58: ldr  x1, [x1, #0x218]    ; ★ 读 image + data_size + 0x218 = sechdr + 0x18
0xBF5C: add  x0, x0, x1          ; return image + sechdr[+0x18]
0xBF60: ret
```

`sechdr + 0x18` **就是** magic_pack 改写的那个字段（stock `0x200` → packed `0x210`）。
SPL 把它当作**相对镜像基址的偏移**来算 payload 指针：

```
payload_ptr = image_base + sechdr[+0x18]
```

- stock ：`image_base + 0x200` = `0xb5000000`（payload 实际位置）✓
- packed：`image_base + 0x210` = `0xb5000010`（payload 实际位置）✓

配套的另外三处也逐条对上：

| 字段 | SPL 用法 | packed 下的结果 |
|---|---|---|
| `sechdr+0x10`（payload 长度 = `0x171630`） | `splloader 0xBFA4: ldr w1,[x21,#0x10]` 作为哈希/校验长度 | **magic_pack 不改它** → 校验范围 = `[image+0x210, +0x171630)` = 原始 payload 字节 → 与未变的 `data_hash` **仍然匹配** ✓ |
| `sechdr+0x28`（cert 偏移） | `splloader 0xBA98-0xBAA0: cert = image + sechdr[+0x28]`（**绝对**偏移，不是 sechdr 相对） | magic_pack 已把它 `+0x100` → `0x171990` → cert 指针跟随搬迁后的证书 ✓ |
| `sechdr+0x20`（`sig_struct_size`） | `splloader 0xBAA4: cmp x3,#0x458` | 本机正是 `0x458`，SPL 有专门分支处理该格式 ✓ |

**结论**：magic64 改动的 4 个字段（`data_size`、`sechdr+0x18`、`sechdr+0x28`、DHTB `data_size`）在 SPL 侧**全部被按预期使用**，布局变换与 SPL 的实际解析逻辑完全自洽。

### 仍然未能 100% 排除的一点（如实说明）

我**没有**在 `splloader.bin` 里定位到"交权给 uboot 入口"的那条跳转指令（全镜像只有 12 处 `br/blr`，且都不是交接跳转），所以无法直接读出入口地址是 `image_base + 0x200` 还是 `image_base + payload_offset`。

推理链：既然 SPL 期望 sechdr 恰好位于 `image_base + 0x200 + data_size`，那么整段 data 区 `[file 0x200, file 0x200+data_size)` 必须被**连续**加载到 `[image_base+0x200, ...)`，入口自然是该区起点 `image_base + 0x200` —— 也就是我们放跳转指令的位置。

但严格说这仍是推理而非直读。**实际失败模式分三种**：

| 情形 | 结果 |
|---|---|
| 入口 = `image_base + 0x200` | ✅ 补丁生效（预期） |
| 入口 = `image_base + payload_offset` | ⚠️ 真实 `_start` 在 `+0x10` 处执行，PC 相对代码错位 → **可能卡住**（软砖，可用原厂备份回写恢复） |
| SPL 先把 payload 拷到 `image_base+0x200` 再跳 | ✅ 安全：跳转指令被覆盖，补丁不生效，设备**正常启动**（无副作用） |

官方 magic64 在 Anbernic T820 上已硬件确认可生效，且那台与本机是同 SoC、同 `ums9620_2h10` 目标、同 DHTB/SIMGHDR 格式、同 `payload_offset 0x200→0x210` 变换 —— 这是目前最强的一手证据。

### 进入下一阶段的前提条件（你已具备）

**完整原厂分区备份**（`uboot_b.bin` 等，SHA256 已记录）——即使出现最坏情况也能回写恢复。

### 本阶段明确未做（仍然禁止）

- ❌ 未刷写设备（无 `spd_dump write`、无 `fastboot flash`）
- ❌ 未修改 splloader
- ❌ 未修改 miscdata
- ❌ 未修改 vbmeta
- ❌ 未修改原始 `uboot_b.bin`
- ❌ 未重新签名

---

## 交付物

| 文件 | 说明 |
|---|---|
| `T9100_uboot_b_unlock_magic64.img` | 生成的镜像（`3145728` 字节） |
| `T9100_patch_uboot_unlock_ums9620.py` | T9100 专用离线 patcher（复用官方 `magic_pack_ums9620.pack()`，不修改官方仓库） |
| `T9100_check_magic64.py` | 只读验证器 + shellcode 模拟执行器（含 `--load-base-report`） |
| `T9100_verify_output.txt` | 本次验证的完整原始输出（35/35 + LOAD_BASE 证据） |

### 复现命令

```bash
# 1) 生成（--dry-run 可先只校验不写盘）
python T9100_patch_uboot_unlock_ums9620.py --dry-run
python T9100_patch_uboot_unlock_ums9620.py

# 2) 验证 + 模拟执行
python T9100_check_magic64.py
python T9100_check_magic64.py --trace              # 打印 shellcode 逐条轨迹
python T9100_check_magic64.py --load-base-report   # 只看 LOAD_BASE 证据
```

---

*报告结束。本阶段仅完成离线生成与离线验证；未连接设备、未刷写、未修改任何原始输入或官方仓库文件。*
