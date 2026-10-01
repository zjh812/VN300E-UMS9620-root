# build/ — 从你自己的原厂镜像构建

## 这里为什么没有预编译镜像

本仓库**故意不提供任何镜像文件**，无论是原厂分区镜像还是打好补丁的成品：

- 原厂 `uboot` / `init_boot` 是**紫光/展锐的版权固件**，再分发不合适
- 固件版本会变，别人机器上的镜像**未必与你的匹配**
- 用自己的原厂镜像现场生成，你拿到的才是**确定对得上**的东西

所以这里只有**方法**。下面是可以直接复制的完整流程。

---

## 1. 先备份你的设备（只读）

**用仓库里现成的一键脚本：[`../tools/backup_all_partitions.bat`](../tools/backup_all_partitions.bat)**

它只读 GPT + dump 全部 73 个分区 + 生成 `SHA256SUMS.txt`，
**不含任何 `w`(write) / `e`(erase) / repartition 命令**。

用法见 [主 README 的「第 0 步」](../README.md#-第-0-步完整备份必做先做这个)。

它内部执行的就是这一条命令（你自己跑也一样）：

```bat
spd_dump --wait 300 exec_addr 0x65012f48 fdl fdl1-dl.bin 0x65000800 ^
         fdl fdl2-dl.bin 0xb4fffe00 exec exec path "<备份目录>" r splloader r all reset
```

你需要的是里面的 **`uboot_b.bin`** 和 **`init_boot_b.bin`**（当前激活槽是 `_b`；
用 `adb shell getprop ro.boot.slot_suffix` 确认）。

核对你的 `uboot_b.bin`：

```bat
certutil -hashfile uboot_b.bin SHA256
```

> 本方案针对的固件版本：`5935075bed5b12d35b961d0e39a4e95154b8cfb94ac177f96919700a24b8e321`
> （`ums9620_2h10` / `qogirn6pro`，build `2026-01-13-02:26:09_LOCAL`）
>
> **如果对不上**：说明你的固件版本不同，**不要直接套用下面的 patch 点** ——
> 先按 [`../docs/方法论-unisoc-uboot-magic64-offline.md`](../docs/方法论-unisoc-uboot-magic64-offline.md)
> 重新定位偏移（构建脚本会严格校验原始指令，对不上会直接中止，不会写坏文件）。

---

## 2. 构建 uboot

```bash
python ../tools/T9100_build_probe_magic64.py \
  --input  uboot_b.bin \
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

脚本会：

1. 校验 `data[0:4] == b"DHTB"`
2. 校验输入 SHA256 等于上面那个已知原厂值
3. 逐条校验每个 patch 点的**原始 32 位指令精确相等**
4. 复用官方 `magic_pack_ums9620.pack()` 打包（保持 payload 逐字节不变）
5. 自检：输出大小 == 分区大小、payload 与 stock 逐字节一致

**任何一项不符就中止，不写任何字节。**

---

## 3. 离线验证（强烈建议）

```bash
python ../tools/magic64_verify.py \
  --stock uboot_b.bin --patched my_uboot_b.img \
  --load-base 0xb5000000 \
  --patches "0x627e8=0x52800035,0x627f0=0xb908ca95,0x62830=0xd503201f,0xb4b0=0xd503201f,0xb504=0xd503201f,0xb7478=0x1d000016,0xb7b8=0xd503201f,0xb7c0=0xd503201f,0x6ac10=0xd503201f,0x6ac18=0x17ffffc1"
```

它会解析 DHTB / SIMGHDR / patch table，并**用内置的 AArch64 解释器把 shellcode 真跑一遍**，
最后比对 RAM 与 stock payload。期望结果：**19/19 通过**，
且 RAM 里**恰好只有那 10 个字**被改。

---

## 4. 刷入

```bat
spd_dump --wait 300 exec_addr 0x65012f48 fdl fdl1-dl.bin 0x65000800 ^
         fdl fdl2-dl.bin 0xb4fffe00 exec w uboot_b my_uboot_b.img reset
```

**只写 `uboot_b` 一个分区。**

---

## 5. init_boot（root）

`init_boot` 的补丁**不在本仓库范围内** —— 用
[SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) 的 LKM 方案
补丁**你自己的**原厂 `init_boot_b`，然后：

```bat
spd_dump --wait 300 exec_addr 0x65012f48 fdl fdl1-dl.bin 0x65000800 ^
         fdl fdl2-dl.bin 0xb4fffe00 exec w init_boot_b <你补丁好的init_boot_b> reset
```

自检：文件仍是 `ANDROID!` 头，偏移 `0x0C` 的 kernel size 会比原厂大
（原厂 `0x20E3DE` → 打过 SukiSU 的约 `0x28607D`）。

---

## 参考：各文件的 SHA256

这些是**哈希值**，不是内容 —— 用来让你核对「我手上的是不是同一份」。

| 文件 | SHA256 |
|---|---|
| 原厂 `uboot_b.bin` | `5935075bed5b12d35b961d0e39a4e95154b8cfb94ac177f96919700a24b8e321` |
| 原厂 `init_boot_b.bin` | `21f2a537c21c4ca40ab4fdbfbb86a722ff79b10d509ae441e2eef0f175f03dcb` |

---

## 回滚

```bat
spd_dump --wait 300 exec_addr 0x65012f48 fdl fdl1-dl.bin 0x65000800 ^
         fdl fdl2-dl.bin 0xb4fffe00 exec w uboot_b uboot_b.bin reset
```

`init_boot_b` 同理。**BootROM 是掩膜 ROM，永远可用** —— 只要 `splloader` 没动，
最坏情况都能从 BROM 恢复。**绝对不要刷 `splloader`。**
