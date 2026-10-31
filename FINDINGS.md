# 分析记录

## 设备侧事实（ADB shell，uid 2000）

```
ro.product.model      ALT-AN00
ro.soc.manufacturer   QTI
ro.soc.model          SM4450
ro.board.platform     parrot
ro.boot.hardware      qcom
ro.boot.verifiedbootstate  green
ro.boot.flash.locked  1  (locked)
ro.boot.vbmeta.device_state locked
security_patch        2026-05-01
kernel                5.10.236-android12-9-g544a0d1f1c3d
```

关键：这是一台 **Qualcomm / Gunyah** 机器，不是海思。

```
/sys/module/gh_ctrl
/sys/module/gh_rm_drv
/sys/module/gh_dbl
/sys/module/gh_msgq
/sys/module/gh_mem_notifier
/sys/module/gh_irq_lend
/sys/module/gh_virt_wdt
/sys/module/gh_arm_drv
/sys/module/hvc_gunyah
/sys/module/qrtr_gunyah
/sys/module/hyp_core_ctl
/sys/module/kvm
```

`/proc/device-tree/hypervisor/` 下存在 `qcom,gunyah-vm`、`qcom,gh-watchdog`、
`qcom,resource-manager-rpc@...`。也就是说 **EL2 上是 Gunyah**，
resource manager 通过 `gh_rm_drv` 的 message queue 与 EL1 通信。

分区表（`/dev/block/by-name`）暴露了 `hyp_a` / `hyp_b`，
这是 Gunyah hypervisor 镜像本体。

## 研究结论

### 样本 gz_a.bin

16 MiB，结构：

```
0x000  88 16 88 58  f0 e5 28 00  67 7a ("gz")
0x02c  ff ff ff ff
0x030  89 16 89 58  00 02 00 00  01 00 00 00  00 00 00 00  00 00 00 00  10 00 00 00
0x050  ff × 432 到 0x200
0x200  ── 2,831,399 字节高熵正文 ──
0x2b3626 之后 全 0 到 16 MiB
```

正文熵 7.9997，256 个字节值全出现，任意 16 字节对齐的重复块只有 632/176962（
都是 `ff…ff` / `00…00` 这类填充），512 B 与 4 KiB 块零重复。
gzip / zlib / raw deflate / xz / bzip2 / zstd / lz4 在所有候选偏移全部失败。
正文长度 % 16 = 7，不满足任何分组长度。

没有 ELF、FDT、ext4、squashfs、sparse、AVB 魔数。

判定：**加密或私有编码的不透明数据，且不在分组边界上**。
这份 dump 里没有任何可反编译的指令。

### 样本 gz_b.bin

16,777,216 字节全 0，非零页 0。空 dump。

## 与 EL2 提权的距离

`hyp_a` 才是 Gunyah 的代码。当前 shell 是 uid 2000，`dd if=/dev/block/by-name/hyp_a`
直接 Permission denied，`/data/adb` 也不可读，所以拿不到 hypervisor 镜像。

要做 root → EL2 的研究，必须先把 `hyp_a` 的实际内容取出来（需要 root 或
EDL / firehose 读盘），然后才有反汇编对象。当前手上的两个 bin 不具备这个信息量。

## 攻击面清单（Gunyah on SM4450，kernel 5.10.236）

按可达性排序，全部需要 root 才能触及：

1. `gh_rm_drv` —— resource manager 的 message queue。EL1 通过它向 EL2 发
   RM RPC（`RM_RPC_MEM_*`、`RM_RPC_VM_*`、`RM_RPC_IRQ_*`）。任何 arg 校验缺失
   都会直接落在 hypervisor 的解析代码上。
2. `gh_msgq` / `gh_dbl` —— doorbell 与 mailbox，索引越界是经典入口。
3. `gh_mem_notifier` / `gh_irq_lend` —— 内存 lend 与中断 lend 的生命周期管理，
   UAF 高发区。
4. `gh_virt_wdt` —— 虚拟看门狗喂狗路径。
5. `hvc_gunyah` —— guest 侧的 HVC 调用封装，参数直通 EL2。
6. `hyp_core_ctl` —— vendor 的 core 控制，历史上出现过直接对 EL2 发命令的接口。
7. `/dev/gunyah*` —— 本机不存在，说明 gunyah 用户态驱动没暴露给应用侧。

## 下一步需要的材料

- `hyp_a` 原始镜像（root 下 `dd`，或 EDL 读出 `sde26`）
- `xbl_a` / `abl_a`（SM4450 的 SBL 与 ABL，含 Gunyah 加载与认证流程）
- 内核 `gh_*` 驱动源码或带符号的 `vmlinux`
- 抓取方式说明：`gz_a.bin` 是哪个块设备的哪个偏移

把 `hyp_a` 丢进 `samples/`，`unpack-analyze` 会自动跑 binwalk + ELF 扫描，
`decompile` 会出 objdump 与 MRS/MSR/HVC/SMC 指令清单。