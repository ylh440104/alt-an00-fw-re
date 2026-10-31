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

## 十一、MTK Secure Boot 容器格式（`gz` 是加密的）

`gz` payload 为 2679792 字节，卡方检验对均匀分布 **282.9（df=255）**，
与真随机不可区分；按 4 KiB 窗口全量扫描，**没有任何一个窗口熵低于 7.5**。
逐字节探测 `1f 8b 08` 共 0 次命中。结论：这是真加密，不是压缩，且全段无明文。

对照表：

| 镜像 | 段 | 载荷大小 | 熵 | 状态 |
| --- | --- | --- | --- | --- |
| gz_a | gz | 2679792 | 7.999 | 加密 |
| gz_a | unmap2 | 142560 | 7.999 | 加密 |
| lk_a | lk | 1137776 | 5.837 | **代码，AArch32 + AArch64** |
| lk_a | lk_main_ | 118033 | — | **DTB，明文** |
| tee_a | atf | 156672 | 6.164 | **代码，EL3** |
| tee_a | tee | 1991168 | 7.538 | Trusty OS |
| md1img_a | md1rom | 0 | — | 空 |

`mt6797`/`mt8786` 这一代的 secure boot 容器用
**AES-256-CBC 加密 + RSA-2048 PSS 签名**，密钥由 eFuse 里的 device key
派生，分区里只放密文和证书，不放密钥。这解释了为什么 `sec1` 全零、
`proinfo` 只有序列号、`md1img` 只有占位——这台机的密钥材料在 eFuse，
磁盘上不存在。

因此 **`gz` 无法从磁盘侧解密**。要做 EL2 研究，只能走运行侧。

## 十二、运行时拓扑（`lk_main_` DTB，已完整还原）

`lk_a` 的第二段 `lk_main_` 是 DTB（`d00dfeed`，totalsize 118033，
off_dt_struct 56，off_dt_strings 102136，version 17）。段本身只带 117521 字节，
缺 512 字节，从下一段的头补齐后 `dtc` 正常解析，共 4930 行。

关键节点：

```
trusty {
    compatible = "android,trusty-smc-v1";
    tee-id = <0x00>;
    tee-name = "trusty";
    mtee {
        compatible = "mediatek,trusty-mtee-v1";
    };
    gz-main {
        compatible = "mediatek,trusty-gz";
    };
    trusty-irq {
        compatible = "android,trusty-irq-v1";
        ppi-interrupt-parent = <0x13>;
    };
    trusty-virtio {
        compatible = "android,trusty-virtio-v1";
    };
    trusty-gz-log {
        compatible = "android,trusty-gz-log-v1";
    };
};

nebula {
    compatible = "android,nebula-smc-v1";
    tee-id = <0x01>;
    tee-name = "nebula";
    nebula-virtio { compatible = "android,nebula-virtio-v1"; };
    nebula-irq   { compatible = "android,nebula-irq-v1"; };
    nebula-gz-log{ compatible = "android,nebula-gz-log-v1"; };
};
```

要点：

1. 这台机有**两个 TEE**：`trusty`（id 0）和 `nebula`（id 1），都通过 SMC 访问。
2. `gz-main` 是 **trusty 的子节点**，说明 GenieZone 由 Trusty 引导/管理，
   不是独立第三方 hypervisor。这与 MTK 的 gz 设计一致：Trusty 在 EL3/EL1s
   侧，gz 在 EL2 侧，两者用 SMC 对话。
3. `trusty-gz-log` / `nebula-gz-log` 对应 `/proc/gz_log`，即 EL2 的日志
   通过 virtio 或共享内存暴露给 EL1。实测 `/proc/gz_log` 是
   **一次性可读**（读一次即清空），我已消耗掉当前实例的缓冲。
4. `nebula` 是 MTK 的第二代 TEE 框架（替代 Trusty 的方向），
   两个同时在跑说明固件处于过渡期。

## 十三、EL2 运行时日志（已捕获片段）

`/proc/gz_log` 在第一次 `head -c 2000` 时返回了 EL2 的真实启动日志：

```
====> GZ (0)[    0.023940][memlog_static_init] register pa 0x7f600000, size 0x41000
====> GZ (0)[    0.023946]INIT: cpu 0, calling hook 0x3802230c (hyp_mmu_init) at level 0x50005, flags 0x1
====> GZ (0)[    0.023952]hyp_mmu_init:1015: skip init global pgd
====> GZ (0)[    0.023956]hyp_mmu_init:1028: init done
====> GZ (0)[    0.023960]INIT: cpu 0, calling hook 0x3803a80c (rkp_init) at level 0x50005, flags 0x1
====> GZ (0)[    0.023966][GZ_EXPORT] 996: no RKP, rkp is not enable
====> GZ (0)[    0.023970]INIT: cpu 0, calling hook 0x3803ea34 (test_kta_api_init) at level 0x50005, flags 0x1
[KTEE UT]KTA mem api:
====> GZ (0)[    0.023978][TEST KTA API] 29: KTA_Mem_AllocMem:
====> GZ (0)[    0.023983][TEST KTA API] 37: Get mem_handle = 1
====> GZ (0)[    0.023987][TEST KTA API] 38: Memory addr= 0x3830d828
====> GZ (0)[    0.023991][TEST KTA API] 39: Stored value = 66   // should be 66
====> GZ (0)[    0.023994][TEST KTA API] 41: KTA_Mem_ReferenceMem: should return pointer to the memory of the input handle
====> GZ (0)[    0.024000][TEST KTA API] 46: Memory addr = 0x3830d828
====> GZ (0)[    0.024004][TEST KTA API] 47: Stored value = 33   // should be 33
====> GZ (0)[    0.024008][TEST KTA API] 49: KTA_Mem_UnreferenceMem: should return reference count of the memory handle
====> GZ (0)[    0.024013][TEST KTA API] 52: Ref count of handle = 1   // should be 1
[KTEE UT]KTA mem api: PASSED
[KTEE UT]======== UT report =======
[KTEE UT]total test cases: 6
[KTEE UT]FAILED test cases: 0
[KTEE UT]===========> UT SUCCESSED
====> GZ (0)[    0.024022]INIT: cpu 0, calling hook 0x3803ed9c (test_mtee_api_init) at level 0x50005, flags 0x1
====> GZ (0)[    0.024028][KTEE SYS UT] 130: UT start
====> GZ (0)[    0.024031][KTEE SYS UT] 57: dummy value: 10, name: QQQ
====> GZ (0)[    0.024035][KTEE SYS UT] 58: dummy2 value: 20, name: OAQ
====> GZ (0)[    0.024040][KTEE SYS UT] 72: handle type: 0x3805b3a0
====> GZ (0)[    0.024044][KTEE SYS UT] 76: handle value: 0x2
```

这是**极有价值的一手信息**：

- `memlog_static_init: register pa 0x7f600000, size 0x41000`
  → EL2 的日志缓冲区在物理 `0x7f600000`，大小 266240 字节。
  这是 EL2 与 EL1 的共享内存点，也是潜在的攻击面（EL1 若可写这块，
  就能伪造日志甚至影响 EL2 的环形缓冲区状态）。
- `hyp_mmu_init at 0x3802230c`、`rkp_init at 0x3803a80c`、
  `test_kta_api_init at 0x3803ea34`、`test_mtee_api_init at 0x3803ed9c`
  → **EL2 代码的运行时加载基址是 `0x38000000`**，函数指针全部高于这个值。
  EL2 的 MMU 初始化、RKP（Root of Key Protection）、KTA API、MTEE API
  的入口地址都拿到了。
- `no RKP, rkp is not enable`
  → **这台机没有启用 RKP**。RKP 是 MTK 的密钥保护根，
  用它可以在 EL2 侧保护密钥不被 EL1 读取。它关闭意味着 EL2 的密钥
  可能在 EL1 可读的内存里。这是本轮最重要的发现。
- `[KTEE UT] ... UT SUCCESSED`，6 个测试用例全过
  → EL2 里带着 **KTEE 自测代码**，且可被触发/执行。
- `handle type: 0x3805b3a0` → KTA 句柄表在 EL2 的 `0x3805b3a0` 附近。

这些地址和状态，比 `gz_a` 里的密文有用得多。

## 十四、当前可走的 EL2 路径（按可行性排序）

### 路径 1：RKP 未启用 → EL2 密钥可能在 EL1 可读区

日志明说 `no RKP, rkp is not enable`。RKP 的作用是把密钥锁在 EL2，
EL1 读不到。没开的话，`gz` 在 EL2 里保存的会话密钥、stage-2 页表
（`vttbr_el2` 指向的那块）有可能落在普通内存里。

验证方法（只读，不改设备）：在 EL1 扫物理内存找 `vttbr_el2` 的值和
KTA 句柄表的特征，看是否可读。需要 root，这台机有。

### 路径 2：EL2 日志缓冲区 `0x7f600000`

EL2 的 memlog 在 `0x7f600000`，266240 字节。如果 EL1 侧对这块
**有写权限**（而不是只读映射），可以在里面伪造日志条目，
或者破坏环形缓冲区的 head/tail 指针。EL2 读日志时若不校验，
就可能被引导到任意地址。

`/proc/gz_log` 是只读的（`-r--r-----`），但这只说明 proc 接口，
不说明物理内存映射。

### 路径 3：KTEE 自测代码 `test_kta_api_init` / `test_mtee_api_init`

EL2 里带着自测代码，入口在 `0x3803ea34` 和 `0x3803ed9c`。
自测代码通常**不做参数校验**（因为假设只被自己调用）。
如果 EL1 能通过某个 ioctl 触发这些 hook，就是现成的入口。

### 路径 4：`unmap2` 段

`gz_a` 里第二段叫 `unmap2`，142560 字节，同样是密文。
"unmap" 这个名字暗示它是**被 unmap 掉的内存区域描述**，
可能对应 EL2 里做 stage-2 反映射的逻辑。等能读到 EL2 内存后再看。

## 十五、EL1 侧内存访问原语实测（全部只读，设备未修改）

目标：验证"RKP 未启用是否导致 EL2 数据暴露给 EL1"。

### 结果：无法验证，因为 EL1 根本读不到物理内存

| 原语 | 状态 |
| --- | --- |
| `/dev/mem` | 不存在，且 `# CONFIG_DEVMEM is not set` |
| `/dev/kmem` | 不存在 |
| `/proc/kcore` | 不存在，且 `# CONFIG_PROC_KCORE is not set` |
| `/sys/kernel/debug` | 不存在，`mount -t debugfs` 报 `No such file or directory` |
| `mknod /dev/mem_test c 1 1` | 节点能建，但 `dd` 读报 `Permission denied` |

关键：**`CONFIG_DEVMEM` 是编译期关闭的**，不是权限问题。
即使用 root + magisk 域手动 `mknod`，内核也根本没有 `/dev/mem` 的
字符设备实现。这条路不是"被拦住"，是"不存在"。

同时 `CONFIG_MTK_DEVMPU` 和 `CONFIG_MTK_DEVMPU_EMI` 都未设置，
说明不是靠 DEVMPU 挡的，而是单纯没编进去。

### 仍然可用的只读通道

```
dmesg              可用（内核环形缓冲）
/dev/kmsg          可用（root）
/proc/kallsyms     可用，但地址全 0（CONFIG_KALLSYMS_ALL 未设）
/proc/gz_log       曾可用，一次性，现已耗尽
/proc/config.gz    可用
```

`CONFIG_SECURITY_DMESG_RESTRICT` 未设置，所以 `dmesg` 对普通 shell 也可读。

### 相关内核配置（实测）

```
# CONFIG_DEVMEM is not set
# CONFIG_PROC_KCORE is not set
CONFIG_ARCH_PROC_KCORE_TEXT=y
# CONFIG_KALLSYMS_ALL is not set
# CONFIG_SECURITY_DMESG_RESTRICT is not set
CONFIG_MTK_M4U=y
CONFIG_MTK_TEE_GP_SUPPORT=y
CONFIG_MTK_TEE_SANITY=y
CONFIG_TRUSTY_INTERRUPT_MAP=y
CONFIG_TRUSTY_INTERRUPT_FIQ_ONLY=y
# CONFIG_MTK_IOMMU is not set
# CONFIG_MTK_IOMMU_V2 is not set
# CONFIG_MTK_DEVMPU is not set
# CONFIG_MTK_DEVMPU_EMI is not set
# CONFIG_OPTEE is not set
```

## 十六、TEE 运行时实例（实测进程表）

```
 60-67  [id0_trusty_n/0..7]     8 个 normal world 入口线程
 68     [trusty_poll_tas]
222-224 [id0_trusty_k/0..2]     3 个 kernel world 线程
225     [id0_trusty_c/0]
288     [teei_switch_thr]
289     [teei_bdrv_threa]
290     [teei_log_thread]
449     teei_daemon               用户态服务（uid system）
```

设备节点：

```
crw-rw---- system system 250, 0  /dev/trusty-ipc-dev0
crw-rw---- system system 502, 0  /dev/teei_client
crw-rw---- system system 501, 0  /dev/teei_config
crw-rw---- system root   499, 0  /dev/teei_fp
crw-rw---- system camera  10,58  /dev/gz_kree
```

`id0_trusty_*` 这个命名说明 TEE 实例 id 是 0，与 DTB 里 `trusty { tee-id = <0x00>; }` 一致。

### `teei_daemon` 在持续刷错误

`dmesg` 里 `tz_vfs_read: wait_for_completion was interrupt` 反复出现，
累计 19 次，间隔约 1 秒：

```
[45370.856693] [tz_vfs][ERROR]: [tz_vfs_read][155] wait_for_completion was interrupt
[45372.168549] ...
[45373.080668] ...
```

意味着 `teei_daemon` 不停向 TEE 发起读取，但每次都被信号中断。
这可能是：

1. 某个 TEE 服务未响应，daemon 在重试
2. `teei_daemon` 自己收到信号后没正确处理 EINTR
3. TEE 侧有服务挂起

这个循环本身就是一个可观察的攻击面：`tz_vfs_read` 在
`wait_for_completion_interruptible` 返回 `-ERESTARTSYS` 时没有清理状态，
如果这个循环里存在资源泄漏（比如每次都分配一个 buffer 而不释放），
长时间运行会耗尽某个池。但目前只看到错误日志，没有看到泄漏证据。

## 十七、结论：静态线到此为止

经过这一轮，可以明确给出结论：

**从 EL1（即使有 root）无法静态读取 EL2 的内存。** 原因有三层：

1. `gz_a` 在磁盘上是 AES 加密的，密钥在 eFuse，分区里没有
2. EL2 的代码在运行时加载到 `0x38000000`，但 EL1 没有物理内存访问原语
3. 唯一能看到 EL2 的窗口 `/proc/gz_log` 是一次性的，已耗尽

**RKP 关闭这件事无法在 EL1 侧验证。** 这是一个真实的配置弱点
（MTK 的 RKP 本可以在 EL2 侧保护密钥），但要利用它需要先有一个
能读/写任意物理内存的 EL1 原语——而这台机恰好没有。

换句话说：**RKP 缺失降低了攻击门槛，但还缺一把钥匙。**
那把钥匙就是一个 EL1 的内核内存破坏漏洞（任意读/写）。
有了它之后，RKP 缺失会让从 EL1 到 EL2 的跳跃变得可行；
没有它，RKP 缺失只是个纸面弱点。

## 十八、下一步真正的方向

要突破 EL1 → EL2，必须先有 EL1 的任意读写。可选的路径：

1. **`gz_ioctl` 的影子数组越界**（第四章那个 `cmp w9, #0x3ff` 的位置问题）。
   这是 EL1 内核堆溢出，成功后有希望拿到任意读写。
   需要写 PoC 在设备上跑，有崩溃风险。
2. **`teei_daemon` 的 `tz_vfs_read` 循环**。如果存在 buffer 泄漏，
   可能可以耗尽内存或触发 UAF。需要长时间观察。
3. **`m4u` / `MTK_M4U=y` 的 IOMMU 路径**。`/dev/m4u` 若可访问，
   IOMMU 映射错误可以给出物理内存访问。
4. **已知的 MTK 内核 CVE**，kernel 4.19.191 且安全补丁 2026-05-01，
   需要查这个版本之后公布的漏洞。

前三条都需要动手写代码并在设备上执行。第四条是查资料。

## 十九、待补

- `mmcblk0boot0` / `boot1`（eMMC boot 分区，可能存 preloader 和密钥）
- `otp` 分区（eFuse 的镜像，若可读则直接拿到 device key）
- EL2 运行时内存 dump（需要 root + /dev/mem 或 kcore，Android 默认不给）
- `nebula` 相关分区（第二 TEE，可能是新的攻击面）

## 十六、产物

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