---
name: mtk-tee-nogz
description: 离线检查和修改联发科 tee.img 中的 ATF，实现已知 yunluo/peral 样本的 NoGZ、LK EL1h 与内核 EL2h 交接，检测 preloader 的 new/legacy 证书模式并调用 pwnage 签名和回归；不用于自动刷机、永久解锁或 RPMB/eFuse 操作。
---

# MTK TEE NoGZ

保留用户原始输入，只生成独立的 ATF 修改副本。读取匹配的 LK 用于交接回归，但不修改 LK、preloader、GZ、RPMB 或 eFuse。文件处理授权不代表设备写入授权。

## 使用入口

- 环境、命令和安装说明：[README](README.md)。
- 指令原理、配置字段、完整测试边界：[技术手册](docs/technical-guide.md)。
- 未知版本与排错：[适配说明](references/adaptation.md)。
- 精确输入身份及偏移：[profiles.json](references/profiles.json)。

## 已知样本

先核对用户输入；仅完整 SHA-256 与 profile 匹配时，才能运行已知补丁。
机型相同不代表版本相同。未知哈希先停止套用，按适配说明重新分析，不得仅替换哈希或删掉断言。

```text
python scripts/build.py --profile peral --tee <original-tee> --lk <original-lk> --check-only
python scripts/build.py --profile peral --tee <original-tee> --lk <original-lk> --preloader <matching-preloader> --tools <pwnage-directory> --out-dir <new-directory>
```

实际执行时根据 skill 的安装位置解析脚本路径。依赖 Python、Capstone、Unicorn；签名时另需用户提供对应 preloader 和完整且可信的 pwnage 目录。输出目录必须尚不存在。check-only 仅验证 TEE/LK，不检测签名模式。

## 必须保留的检查

1. `D2A21E08` 实际是 `0x10f00000`，正确 LK 地址 `0x50f00000` 的编码是 `D2AA1E08`。独立解码并执行 PC writer，不能只比对旧报告。
2. 这两份原版 LK 以 EL1h 进入；其 EL2 路径会访问 CPTR_EL3。后续内核 EL2h 是另一段交接，不得混同。
3. 同步 ATF/LK 共享 GZ-info tag，保持 callback 约定和缓存清理顺序，防止 LK 仍进入 GZ unmap。
4. 使用原样收录的 `scripts/detect_pl_cert_mode.py` 检测 preloader：`NEW_PARSER`（new）不加任何模式参数；`LEGACY` 才加 `--legacy`。保留 `--all -w -o`，不存在 `--new` 参数。
5. `NEED_MANUAL`、未知结果或检测失败时停止，不按机型或旧结果猜测。签名只执行一次，验签后从最终成品提取数据再回归。

## 交付与边界

- 保留 manifest、完整检测报告、sign/verify 日志、补丁反汇编及输入输出哈希。
- 将输入身份、离线回归、工具 VALID、实际设备验证分别报告，不把其一代替其他证据。
- 模型包含合成 CPU 特征、CurrentEL、系统寄存器和缓存边界；不宣称完整模拟 ERET、LK、Linux、PSCI 或外设。
- GZ 内存和 remap 保留；不宣称返还内存或自动获得 KVM。
- expdb 可能混有旧缓冲和多轮启动；PC=0x200、亮屏、preloader 的 next-is-GZ 均不能独立确定首次故障点。
- 用户要求持续研究不代表允许反复刷写。实际设备操作需要另行明确授权。
- 公开仓库只收录源码和通用文档。不得上传用户固件、设备日志、签名令牌、密钥或带有个人绝对路径的运行 manifest。
