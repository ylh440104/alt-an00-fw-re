# alt-an00-fw-re

HONOR ALT-AN00 (HNALT-Q) 镜像 dump 的解包 / 反编译流水线。
所有解析与反汇编都在 GitHub Actions 上跑，本地只推文件。

## 目标设备

- build fingerprint: `HONOR/ALT-AN00/HNALT-Q:14/HONORALT-AN10/8.0.0.616C00E603R104P1:user/release-keys`
- 内核: `Linux 5.10.236-android12-9-g544a0d1f1c3d`
- Android 14，arm64

## 目录

```
samples/                      待分析样本，放原始 dump 或它的 gzip
tools/inspect.py              头部解析、熵、魔数、分页图、压缩流试探
.github/workflows/unpack-analyze.yml   binwalk 递归解包 + strings + ELF 扫描
.github/workflows/decompile.yml        apktool / jadx / objdump / dtc
```

## 跑法

往 `samples/` 推文件，或 Actions → unpack-analyze → Run workflow。
产物在 run 页面的 artifact 里，报告在 job summary 里。

decompile 支持 mode = apk / elf / dtb / all。

## 样本现状

### gz_a.bin（16 MiB dump）

| 偏移 | 内容 |
| --- | --- |
| 0x000 | `88 16 88 58` 魔数，随后 u32 `0x0028e5f0`、ASCII `gz`、`0xffffffff` |
| 0x030 | `89 16 89 58`（前一个魔数 +0x10001），u32 `0x200`、`1`、`0`、`0`、`0x10` |
| 0x050 - 0x200 | 全 `0xff` |
| 0x200 - 0x2b3627 | 2,831,399 字节正文 |
| 0x2b3627 - 0x1000000 | 全 0 |

正文特征：熵 8.000，256 个字节值全部出现，512 B / 4 KiB 块零重复，长度 % 16 = 7。
gzip、zlib、raw deflate、xz、bzip2、zstd、lz4 全部在 0x0 / 0x30 / 0x38 / 0x100 / 0x200 / 0x400 / 0x1000 这些偏移解不开。
没有 ELF、FDT、ext4、squashfs、sparse、AVB 魔数。

### gz_b.bin（16 MiB dump）

全 0，非零页 0。

## 结论

这两个样本不含可反编译的代码。正文是长度不对齐分组、没有容器魔数、不可解的高熵数据，解包链在这一步终止，没有走到能反汇编的 ELF / DTB / apk。

要往下走需要其中任意一项：

- 原始分区镜像：boot、vendor_boot、init_boot、dtbo、super、xbl、abl、tz、hyp
- 加密层的算法与密钥，或明文侧的 IV
- 该 dump 的抓取方式（dd 的是哪个块设备 / 偏移）

拿到之后把文件丢进 `samples/`，workflow 会自动解包、反汇编、出报告。
