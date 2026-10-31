# GenieZone (gz) — 从 EL1 到 EL2 的分析结果

设备：Lenovo TB337FC，MT8786V/N，Android 13，kernel 4.19.191，已 root（magisk）。
以下全部来自只读 dump，设备未做任何写入。

## 一、镜像格式（已确认）

`gz_a` / `lk_a` / `gz_b` 共用同一容器：

```
0x000  u32 magic   0x58881688
0x004  u32 total   payload 结束偏移（也是证书区起点）
0x008  char[4]     "gz" / "lk"    ← 这个字段就是分区名，不是 gzip
0x028  u32         0xffffffff
0x030  u32 magic   0x58891689     (= 前一个 magic + 0x10001)
0x034  u32         0x200          payload 起点的页对齐偏移
0x038  u32         1
0x044  u32         0x10
0x050  ...        0xff 填充，一直填到 0x200
0x200  ...         payload
total  ...         签名 + X.509 证书区
```

实测三份：

| 镜像 | total | name | payload 长度 | payload 熵 | 证书区首个 DER |
| --- | --- | --- | --- | --- | --- |
| gz_a | 0x28e5f0 | gz | 2679792 | 8.000 | 0x28e9f0 |
| lk_a | 0x115e70 | lk | 1137776 | 5.837 | 0x116270 |

`gz_a` 的证书区里是明文 DER，RSA-2048，`C=AU / O=Mediatek / Some-State`，
2015-06-04 → 2035-06-04，全篇 58 处 `30 82`。所以 payload 不是整体加密。

## 二、内核符号（vmlinux 已重建）

`boot_a.img` → `ANDROID!`，kernel 10857007 字节 gzip → 25815040 字节。
`vmlinux-to-elf` 恢复 58703 个符号，基址 `ffffff8008080000`。

`gz_*` 共 39 个，关键地址：

```
ffffff800871ec4c  gz_ioctl
ffffff800871ec64  gz_compat_ioctl
ffffff800871ec80  gz_dev_open
ffffff800871ed4c  gz_dev_release
ffffff800871ee3c  _gz_ioctl
ffffff800871e974  gz_manual_adjust_trusty_wq_attr
ffffff80087227a0  _gz_client_cmd
ffffff80087228a4  _gz_client_wait_ret
ffffff80087229a4  GZ_RewriteParamMemAddr
ffffff8008722b78  _Gz_KreeServiceCall_body
ffffff8008722da4  _GzServiceCall_body
ffffff800872321c  GZ_CopyMemToBuffer
ffffff800872dd54  gz_log_page_init
ffffff800872e494  gz_log_read
ffffff800872e740  gz_log_poll
ffffff800872e7c4  gz_log_open
ffffff800872e80c  gz_log_release
ffffff8009610cb0  gz_init
ffffff8009611000  gz_log_context_init
```

## 三、ioctl 命令表（从 `_gz_ioctl` 反汇编读出）

入口在 `_gz_ioctl`，先 `and w9, w1, #0xff00` 再和 `0x5400` 比，
所以命令号低字节是子命令、第 8..15 位是类型：

```
0xc0105401   → _gz_ioctl+0x260
0xc0105402   → _gz_ioctl+0x340
0xc0205403   → _gz_ioctl+0x480   走 copy_from_user(32)
0xc0205404   → _gz_ioctl+0x4f4
0x40085415   → _gz_ioctl+0xa8    直接调 gz_manual_adjust_trusty_wq_attr
0x00005410   → _gz_ioctl+0x434
0x00005411   → _gz_ioctl+0x3f4
```

所有 `0xc0…` 分支在进入前都会：
1. `mrs x27, sp_el0` 取当前 task
2. 用 `task->addr_limit` 做 access_ok 检查（`sbcs` / `cset ls`）
3. `__arch_copy_from_user(sp+0x20, arg, 32)`

也就是每条命令都从用户态拷一个 32 字节结构体进来，然后原样往 EL2 送。

## 四、第一个可疑点：GZ_RewriteParamMemAddr

这个函数的职责是把传入结构体里的参数指针，逐个重写成指向
"本地影子数组"的指针，然后再交给 `_Gz_KreeServiceCall_body`：

```
ldr  w8, [x0, #16]          ; 4 个参数类型，每字节一个
and  w9, w8, #0xff          ; 参数0 类型
sub  w9, w9, #5
cmp  w9, #2
b.cs → 跳过（类型 <5 或 >6 视为无参）
ldr  w9, [x0, #48]          ; 参数0 长度
add  x10, x0, #0x68
str  x10, [x0, #40]         ; ← 把指针改写成 buf+0x68
```

三个参数依次用 `ubfx w8, #8, #8`、`#16, #8`、`lsr #24` 取类型，
指针分别写进 `[x0+40]`、`[x0+56]`、`[x0+72]`，长度累加进 `w9`，
每次累加前检查 `cmp w9, #0x3ff`（1023）。

**问题**：`0x3ff` 这个上界是拿"当前累加值"去比的，不是"累加值 + 本次长度"。
`w9 = w9 + w10` 发生在 `cmp` 之后，所以最后一次加法可以把 `w9` 顶过 1024。
影子数组 `buf+0x68` 到 `buf+0x68+0x400` 一共 1024 字节，越界写指针不落在
影子数组里，而是落进结构体后面的字段——这些字段紧接着被当作参数交给 EL2。

这是 EL1 侧的整数边界缺陷，触发点在 `ioctl(fd_gz_kree, 0xc0205403, &arg)`。

## 五、第二个可疑点：SMC 汇聚

全内核 20 处 `smc #0`，集中在 `ffffff80080962xx`–`ffffff80080976xx`，
是 `arm64_ssbd` / `spectre` 那批 mitigation 代码，不是 GZ 的通道。
GZ 的调用链 `_GzServiceCall_body` / `_Gz_KreeServiceCall_body` 里
没有内联 `smc`，说明它最终经由一个函数指针或 `mtk_secure` 的封装间接下发，
需要继续跟 `_GzServiceCall_body` 的调用者才能定位到真正的 SMC 站点。

## 六、内核配置

```
CONFIG_MTK_ENABLE_GENIEZONE=y
CONFIG_HAVE_MTK_ENABLE_GENIEZONE=y
CONFIG_MTK_GZ_MAIN=y
CONFIG_MTK_GZ_KREE=y
CONFIG_MTK_GZ_LOG=y
CONFIG_MTK_GZ_IRQ=y
CONFIG_MTK_GZ_VIRTIO=y
CONFIG_MTK_GZ_VIRTIO_IPC=y
CONFIG_MTK_SECURE_MEM_SUPPORT=y
CONFIG_MTK_CAM_GENIEZONE_SUPPORT=y
CONFIG_KALLSYMS=y
# CONFIG_KALLSYMS_ALL is not set
```

设备节点：`/dev/gz_kree`（char 10:58，`system:camera`）。
`/proc/kallsyms` 名字全在但地址全 0，所以符号必须从 `boot_a` 里恢复。

## 七、容器段表（完整解出）

`gz_a` 不是单个镜像，是 6 段的容器。段头 0x200 字节，`total` 是本段结束偏移：

| 偏移 | 名字 | total | 正文长度 | 熵 | 内容 |
| --- | --- | --- | --- | --- | --- |
| 0x000000 | gz | 2680304 | 2679792 | 7.999 | hypervisor 主体 |
| 0x28e7f0 | cert1 | 1733 | 1221 | 6.513 | RSA-2048 证书 |
| 0x28f0c0 | cert2 | 982 | 470 | 6.994 | 中间证书 |
| 0x28f6a0 | unmap2 | 143072 | 142560 | 7.999 | 第二段载荷 |
| 0x2b2780 | cert1 | 1733 | 1221 | 6.513 | 同 cert1 |
| 0x2b3050 | cert2 | 982 | 470 | 6.994 | 同 cert2 |
| 0x2b3450 | — | 471 | — | — | RSASSA-PSS 签名块 |

`lk_a` 同样是 6 段：`lk` / `cert1` / `cert2` / `lk_main_` / `cert1` / `cert2`。
`md1img_a` 是 3 段：`md1rom`（total 字段为 1，即无 payload）/ `cert1` / `cert2`。

### 签名算法（`0x2b3450` 处的 471 字节）

```
30 46 06 09 2a 86 48 86 f7 0d 01 01 0a      SEQUENCE, OID 1.2.840.113549.1.1.10
  a0 0f 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00   hash = SHA-256
  a1 1c 30 1a 06 09 2a 86 48 86 f7 0d 01 01 08         MGF1
        30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00      MGF1 内部 = SHA-256
  a2 03 02 01 20                                        saltLength = 32
  a3 03 02 01 01                                        trailerField = 1
```

即 **RSASSA-PSS / SHA-256 / MGF1-SHA256 / salt 32**，后面跟 256 字节签名值。

### 证书

`cert1` 正文 1221 字节，`RSA-2048`，自签，`C=AU / ST=Some-State / O=Mediatek`，
有效期 `2015-06-04 03:14:44Z` → `2035-06-04 03:14:44Z`。
`Some-State` 是 OpenSSL 默认占位串，MTK 没改。
`cert2` 是 470 字节的中间证书，同样格式。

## 八、`_Gz_KreeServiceCall_body` 不是 SMC

反汇编后确认，它是 **TEE 客户端**，不是 hypervisor 通道：

```
0xffffff8008722c10  mrs x8, tpidr_el1           取 per-cpu
0xffffff8008722c34  bl  __ll_sc_atomic64_andnot 释放 CPU 亲和掩码
0xffffff8008722c88  bl  set_cpus_allowed_ptr
0xffffff8008722cbc  bl  complete                 唤醒等待者
0xffffff8008722cc0  str wzr, [x19, #16]         清零状态

0xffffff8008722cd0  bl  TEEC_InitializeContext
0xffffff8008722ce8  bl  TEEC_FinalizeContext
0xffffff8008722d0c  bl  TEEC_OpenSession
0xffffff8008722d28  bl  TEEC_CloseSession
0xffffff8008722d40  bl  TEEC_InvokeCommand
```

命令分发是一个 9 项跳转表，基址 `0xffffff8009161318`，内容
`00 05 0a 22 43 4a 4d 5a 5d`，对应：

```
index 0 → +0x44    ldr w8,[x19]; ldr w9,[x19,#16]; add w8,w9,w8; str w8,[x19,#32]
index 1 → +0x58    同上但用 mul
index 2 → +0x6c    CPU 亲和 + 原子操作 + complete
index 3 → +0x8c    同上
index 4 → +0x110   TEEC_InitializeContext(ctx, arg)
index 5 → +0x120   TEEC_FinalizeContext(ctx)
index 6 → +0x130   TEEC_OpenSession(...)
index 7 → +0x140   TEEC_CloseSession(ctx)
index 8 → +0x150   TEEC_InvokeCommand(ctx, cmd, arg)
```

参数范围检查：`sub w8, w1, #1; cmp w8, #8; b.hi` —— 即 `w1 ∈ [1, 9]`。
这就是 KREE（MTK TEE）的命令号空间，1..9 共 9 条。

结论：`gz` 的内核侧通过 **TEE 客户端 API 走 SMC 进 EL3**，再由 EL3 转 EL2。
内核里那 20 处 `smc #0` 全是 spectre mitigation，与 GZ 无关；
真正的 SMC 在 `optee` / `mtk_secure` 的汇编桩里，不在这个函数内联。

## 九、EL3 实体：`tee_a` 里的 `atf`

`tee_a`（6 MB）同样是 MTK 容器，段表：

| 偏移 | 名字 | total | 正文长度 | 熵 |
| --- | --- | --- | --- | --- |
| 0x000000 | atf | 157184 | 156672 | 6.164 |
| 0x026800 | cert1 | 1733 | 1221 | 6.513 |
| 0x0270d0 | cert2 | 982 | 470 | 6.994 |
| 0x0276b0 | tee | 1991680 | 1991168 | 7.538 |
| 0x20dcb0 | cert1 | 1733 | 1221 | 6.513 |
| 0x20e580 | cert2 | 982 | 470 | 6.994 |

两段载荷都是 MTK TEE 头，魔数 `45 45 54 20 4b 54 4d 20` = `"EET KTM "`：

```
0x00  "EET KTM "
0x08  u32 0x240                 头部长度
0x0c  u32 0x30010001
0x10  u32 1
0x14  u32 load_size
0x18  u32 load_addr
0x1c  u32 load_addr
```

`atf` 段是真正的 **ARM Trusted Firmware BL31**，即 EL3。
反汇编 36193 行，**`smc` 出现 0 次**（EL3 不能对自己发 SMC），`eret` 13 次。

### EL2 的初始化就在 atf 里

`0x5498`：

```
547c  ldr  x1, [x0, #256]          ; scr_el3
5480  tbz  w1, #8, 0x54a4          ; 检查 SCR_EL3.HCE
5484  ldr  x1, [x0, #320]          ; sctlr_el2 初值
5488  mov  w0, #0x830
548c  movk w0, #0x30c5, lsl #16    ; → 0x30c50830
5490  and  w1, w1, #0x2000000      ; 只保留 RES1 位
5494  orr  w0, w1, w0
5498  msr  sctlr_el2, x0           ; ← EL2 的 MMU/对齐/缓存策略在这里定
```

紧接着 `0x5504`–`0x5540`：

```
5504  msr mdcr_el2, x0       ; EL2 调试控制
5508  msr hstr_el2, x2       ; EL2 对 cp15 的陷阱
550c  msr cnthp_ctl_el2, x2  ; EL2 物理定时器
54c8  msr hcr_el2, x0        ; EL2 的虚拟化开关
54d0  msr cptr_el2, x0       ; EL2 协处理器陷阱
54d8  msr cnthctl_el2, x0
54dc  msr cntvoff_el2, x2
54e4  msr vpidr_el2, x0
54ec  msr vmpidr_el2, x0
54f0  msr vttbr_el2, x2      ; ← stage-2 页表基址
```

`0x3ba0` 处 `mrs x0, sp_el2`，`0x3cf0` 处 `msr sp_el2, x0` —— EL3 给 EL2 铺栈。
`0x6320`、`0x87c0` 处 `mrs x0, sctlr_el2` 读回验证。

### 这意味着什么

1. **EL3 是完全可信的**：`atf` 是签名段，`scr_el3` / `sctlr_el2` / `hcr_el2` / `vttbr_el2`
   全部由 EL3 在启动时写入并锁定。想从 EL1 改这些，必须先破 EL3。
2. **`gz` 不是由 EL3 直接管理的**：`atf` 里没有任何 `smc`，它是 EL3 的被调用方。
   `gz` 的 stage-2 和 vCPU 上下文由 `gz` 自己在 EL2 建立，
   EL3 只负责在 `smc` 进来时决定是否转发给它。
3. 因此 root → EL2 的路径有两条，且都绕不开 EL3：
   - 直接攻击 EL2（`gz` 的 SMC 处理），拿到 EL2 后 EL3 仍在其上
   - 攻击 EL3 的 SMC dispatcher（`atf`），拿到 EL3 等于同时拥有 EL2

## 十、`md1img_a` 是空占位

128 MiB 分区里**只有 2 个 4 KiB 页非零**（`0x0` 和 `0x1000`），
其余 115 MiB 全是 0。段表只有 `md1rom`（`total` 字段为 1，无 payload）/ `cert1` / `cert2`。
也就是说这台机的 modem 固件不在这里，`md1img` 只是个带签名的占位。

## 十一、待补

- `_GzServiceCall_body` → SMC 的真实站点（继续向下跟调用图）
- `md1img_a`（TEE / microtrust），确定 EL2 与 EL3 的分工
- `dtbo_a` 里的 GZ 保留内存区
- `gz_a` payload 内的压缩段：熵 8.0 但含明文 DER，需按 MTK GZ 的
  段表（`0x30` TOC）切分，不是靠通用解压器

## 八、产物

```
boot_a.img          33554432  1e608e588005fce70a9dff9d52dae073
dtbo_a.img           8388608  dde21272241747126b0faf92bb3cc9d4
lk_a.img             2097152  6d304c59565d1bf358511ab982e6237b
preloader_a.img      4194304  678b7f3a15cbe3839834e0ab42c21b29
config.gz              33280
Image               25815040  (gzip 解压后的 kernel)
vmlinux.elf         58703 symbols, base ffffff8008080000
```