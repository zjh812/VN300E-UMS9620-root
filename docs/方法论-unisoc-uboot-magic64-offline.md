---
name: unisoc-uboot-magic64-offline
description: 离线生成与验证 Unisoc（UMS9620/T820/T9100 等）U-Boot 的 magic64 签名保持型解锁/去警告镜像。当用户要求「不重新签名就改 uboot」「magic64」「LOAD_BASE 推导」「生成可刷 uboot 但保持 RSA 签名」「离线验证 magic64 镜像」时使用。
version: 1.0.0
agent_created: true
tags: [unisoc, uboot, magic64, ums9620, t9100, dhtb, simghdr, reverse-engineering, load-base]
---

# Unisoc U-Boot magic64 离线生成与验证

处理「SPL 会对 U-Boot 做 RSA 校验，但我们没有私钥」的场景：
**不改签名区、改运行时内存**。全程离线，禁止刷写。

## 铁律

1. 原始 U-Boot 一律 `open(path, "rb")`，输出写**新文件**；先断言 `out_abs != in_abs`。
2. 不重新签名、不改 splloader/miscdata/vbmeta。
3. **LOAD_BASE 没确认就停**，不要生成「看起来能刷」的镜像。
4. 导入官方仓库脚本前设 `sys.dont_write_bytecode = True`，避免往别人仓库写 `.pyc`。

## 步骤 1：确定 LOAD_BASE（最关键，不能猜）

magic64 的 shellcode 是 **PC 相对自定位**的（`adrp x9,#LOAD_BASE` 自算基址、
末尾 `b #LOAD_BASE` 回跳），**LOAD_BASE 唯一用途是 patch table 里的绝对地址**。
错了就是往随机内存写 NOP。

**最强证据来源：`uboot_log` 分区备份**（通常 16MB，是 U-Boot 的运行期日志）。
`grep` 这些关键字：

```
load_buf is 0x0xb4fffe00           <- 镜像基址（含 DHTB header）
sechdr_addr is 0x0xb5171630        <- = 镜像基址 + SIMGHDR 文件偏移
cert_addr: 0xb5171690              <- sechdr + 0x60
sysdump-uboot: addr is 0xb5000000  <- U-Boot 运行区基址
```

`LOAD_BASE = 镜像基址 + 0x200`（DHTB header 长度）。
**两条独立路径必须互相对上**：`镜像基址 + SIMGHDR文件偏移` 与
`LOAD_BASE + payload_size` 应算出同一个值。

先确认日志与设备同源：找 `androidboot.serialnotwo=`、`verifiedbootstate=`、
`flash.locked=`、`target:` / `project:` / `buildid:`。

**二进制侧佐证**：payload 内 8 字节对齐的绝对值落在
`[镜像基址, 镜像基址+16MB)` 的数量。正常应有上千个；若为 0，说明基址不对。
⚠️ 注意假阳性：payload 里等于 `0xb4fffe00` 的 4 字节值可能是 `cbz x0, ...`
（编码 `0xb4fffe00`）指令字，必须反汇编确认，不能当数据引用。

**没有 uboot_log 时的次选**：PAC XML / 分区 XML 的 image base；BSS/SP 字面量；
但置信度显著下降，应标记 UNKNOWN 并停止。

## 步骤 2：镜像结构（实测，别按文档想当然）

```
0x000                 DHTB header (0x200)
0x200                 payload (size = u64 @0x30)
0x200+size            sechdr / SIMGHDR footer (0x60 字节)
    +0x10   payload size (u64)
    +0x18   payload_offset   stock=0x200, magic64 后=0x210  <- 已打包标记
    +0x20   sig_struct_size  (例 0x458)
    +0x28   total_offset     -> cert 文件偏移
0x200+size+0x60       RSA cert blob（长度 = sig_struct_size，**不是 0x254**）
    +0x00 flags(u32)  +0x08 exponent(BE u32, 0x10001)
    +0x0C modulus(0x100)  +0x10C data_hash  +0x154 signature(0x100)
之后                  全 0 padding 到分区大小
```

用「最后一个非零字节的位置」验证 padding 假设，不要凭空假定尾部全 0。

## 步骤 3：打包（复用官方 pack()）

patch 传 **code offset**（`code_off = file_off - 0x200`），**不要传文件 offset**。
`pack()` 产出：`data_size += 0x100`、entry jump @0x200(0x10)、payload @0x210（逐字节不变）、
shellcode(0x70)+patch table @0x210+size、footer 平移、cert 平移、截断回分区大小。

## 步骤 4：离线模拟执行验证（必做）

写一个 AArch64 迷你解释器，把镜像按 `IMG_BASE = LOAD_BASE - 0x200` 装进内存模型后
**真跑一遍 shellcode**，再比对 RAM 与 stock payload。可用 `scripts/magic64_verify.py`。

必须覆盖的指令：`adrp / add(imm) / movz / movk / mov / subs / cmp / b / b.cond / cbz / cbnz / ldr / str(含 post-index) / ic / isb`。

**两个易踩的坑**：

1. **步数上限**：拷贝循环约 `size/8 × 6` 条指令。1.5MB payload ≈ 114 万条。
   设 50 万会「跑到一半就停」，此时差异会呈现整体位移的假象，误判成失败。
2. **停止条件**：shellcode 末尾 `b #LOAD_BASE` 会把控制权交回真 `_start`。
   解释器必须在 `pc == LOAD_BASE` 时停止，否则会跑进真实 U-Boot 代码然后报
   「不支持的指令」。这本身就是「正确回跳」的证据。

**判定粒度用 32 位字**，不要用字节（一个字变 NOP 会显示成 4 个字节差异）。

期望结果：RAM 中**恰好** 4 个字变成 `0xD503201F`，其余 payload 逐字节不变。

## 步骤 5：用 SPL/sml 反汇编证明布局兼容（强烈推荐）

不要停在"推理"，去反汇编 **`splloader.bin`**（以及 `sml_b.bin`）——它们是 DHTB 包裹的，
`code_off = file_off - 0x200`。搜这两个模式即可定位 DHTB 解析函数：

```
ldr w?, [x?, #0x30]        ; data_size
add  x?, x?, #0x200        ; -> sechdr_offset
```

在 UMS9620/T9100 上实测到（可作为检查清单）：

| 语义 | 汇编特征 | magic_pack 对应动作 |
|---|---|---|
| `sechdr = image + 0x200 + data_size` | `ldr w3,[x0,#0x30]; add x3,x3,#0x200; add x3,x0,x3` | `data_size += 0x100` ✓ |
| `payload_ptr = image + sechdr[+0x18]` | `ldr w1,[x0,#0x30]; add x1,x0,x1; ldr x1,[x1,#0x218]; add x0,x0,x1`（`0x218 = 0x200+0x18`） | `footer+0x18: 0x200→0x210` ✓ |
| payload 校验长度 = `sechdr[+0x10]` | `ldr w1,[x21,#0x10]` | **不改** → 哈希仍匹配 ✓ |
| `cert = image + sechdr[+0x28]`（**绝对**偏移） | `ldr x2,[x3,#0x28]; add x2,x0,x2` | `footer+0x28 += 0x100` ✓ |
| 按 `sechdr[+0x20]`（`sig_struct_size`）分流证书格式 | `cmp x3,#0x458` / `cmp x3,#0x254` | 不改 ✓ |

只要这 5 条对得上，布局变换就是**代码级证明**过的，而不是猜的。

**剩余的唯一未知**：交权给下一级的入口跳转在哪。`splloader` 里 `br/blr` 通常只有十几处
且多为跳表 —— 若找不到，就在报告里如实标注，不要假装已确认。

## 步骤 6：证明 magic64「真的执行了」

完整解锁镜像没法回答"我们的代码到底跑了没有"——没跑的话设备与 stock 完全一样。
**而且「删掉一行日志」这类补丁在环形缓冲日志上判不出来**（旧内容残留 + 计数不稳定，
擦日志分区也不一定干净）。

**可靠做法：把一个每次启动必打印的字符串改成唯一标记。**

1. 在 payload 里找一条每次启动都会打印的字符串
   （实测好用：`welcome to lk/MP`，Unisoc u-boot15 系通用）。
2. 用 magic64 把它的前 16 字节改成一个从未出现过的标记，
   例如 `welcome to lk/MP` → `MAGIC64 PROBE OK`（4 个 word，等长，保留 NUL）。
3. 刷入 → 完整启动一次 → 读 `uboot_log` 分区 → grep 标记。

判读：
- 标记出现 → ✅ magic64 执行（同时一次性证明 LOAD_BASE 正确、
  SPL 认 `payload_offset`、SPL 不因签名拒绝该镜像）
- 标记不出现 → ❌ magic64 没执行，设备无损，需换投递方式

该标记只是日志字符串，**功能零影响**。

**实测结论（UMS9620/T9100）**：此方法确认 magic64 在该机型上可用。

## 步骤 7：报告必须写清的残余风险

> **本机 SPL 交权给 uboot 的入口是 `image+0x200` 还是 `image+payload_offset`。**

三种失败模式要写清楚：
- 入口 = `image+0x200` → ✅ 生效
- 入口 = `image+payload_offset` → ⚠️ 真实 `_start` 在 `+0x10` 执行、PC 相对错位 → 可能卡住（软砖，可回写恢复）
- SPL 先把 payload 拷回 `image+0x200` 再跳 → ✅ 安全：跳转指令被覆盖，补丁不生效，设备正常启动

**但如果步骤 6 的标记探针成功，这条风险就自动排除了**（标记出现说明 shellcode 跑了，
也就说明入口是 `image+0x200`）——所以先做步骤 6 能省掉一大段不确定性。

另外必须提醒用户：**magic64 不解锁设备**。它不写 lock flag、不动 RPMB/miscdata，
只是让运行期 U-Boot 认为已解锁。要真正解锁 bootloader 得走解锁流程本身。

## 常见 patch 语义（Unisoc u-boot15 系）

| 语义 | 找法 |
|---|---|
| 强制 UNLOCK | `get_lock_status()` 内 `cbnz w0, <LOCK>`；fall-through 写 1 到 `g_DeviceStatus` |
| 去掉解锁警告 | 启动期锁警告函数里 `cbz w0,<LOCK>` + `cmp #1` + `b.eq <UNLOCK arm>` |
| 去掉 SKIP VERIFY | 状态打印函数的跳表 unlock 分支里连续两个 `bl`（UART + screen） |

用**函数内相对偏移**与参考 build 对比，比「opcode 类型相同」强得多：
若两边 `函数入口→patch点` 的偏移一致（如都是 `+0x24`/`+0x6C`/`+0x74`），
说明是同一份源码换基址，几乎可以确定。

## ⚠️ 四个高频踩坑（都实际踩过，务必先读）

### 1. 函数可达性不能只扫 `bl`/`b`

编译器会用「前一条指令先设好参数，然后**顺序落入**下一条函数的 prologue」来调用函数。
只扫分支目标会把这类函数误判成死代码：

```
0x01FAA4: bl #0xB498          ← 分支目标看着是 0xB498
0xB498: adrp x0, #0x17b000    ← 其实是给 0xB4A0 准备参数
0xB49C: add  x0, x0, #0x200
0xB4A0: stp  x29, x30, [sp, #-0x10]!   ← 真正的函数入口
```

**做法**：把每个 `bl/b` 目标附近的 ±2 条指令也纳入可达集合，或按「prologue + 前驱可达」双向判定。

### 2. patch 生效 ≠ 效果达成 —— 先列全函数的 `return` 路径

实测案例：`get_lock_status()` 里 patch 了 `cbnz w0, LOCK`，设备毫无变化。
原因是更早的 `read_lock_flag()` 返回 -1（读 `miscdata` 偏移 `0x2000` 得到全 0 缓冲），
函数在中间就提前 `return 0` 了，**根本走不到被 patch 的那条指令**。

**做法**：改之前先把函数**所有返回路径**列出来，确认目标指令在预期路径上；必要时把提前返回路径也一并 patch。

### 3. 「删掉一行日志」无法在环形缓冲日志里判定

见步骤 6：用「改成唯一字符串标记」而不是「删掉某行」。
额度不够时可退而求其次，观察**功能效果**（警告消失、启动变快）。

### 4. 去掉一个警告后往往会冒出下一个 —— 要顺着「为什么走到这条分支」追

实测链条：去掉 UNLOCK 警告后出现 `INFO: Press power button to pause.`。
它来自 SKIP_VERIFY 状态机的 state 1（「loaded a different operating system」），
因为解锁态下校验失败被放行（`allow_verification_error=1`）→ 结果码 1 → state 1。

**做法**：先定位打印点所属的**状态机/分支**，优先用「改跳表 / 改状态值」一次性解决整组输出，
而不是一条条 NOP 打印。

## magic64 容量限制

patch table 上限 **0x80 字节**，每条 12 字节 → **最多 10 条**。
超了会报 `patch_data 0x94 exceeds 0x80`。

shellcode 本身支持 `len_words > 1`（`ldr w11,[x9],#4` 拿长度后按 x10 自增循环写），
但官方 `magic_pack.pack()` 只写 len=1。**省额度技巧**：
- 优先用「改跳表 / 改状态值」的单点补丁替代「逐个 NOP 打印」的多点补丁
- 相邻地址可合并成一条 len>1 的 entry（需自定义 packer）

## 脚本

- `scripts/magic64_verify.py` — 只读验证 + shellcode 模拟执行器骨架。
  `--patches` 支持 `off=target` 指定任意目标指令（默认 nop），
  例：`--patches "0x62830=0xd503201f,0x6ac18=0x17ffffc1"`
