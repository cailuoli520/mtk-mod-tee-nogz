# MTK TEE NoGZ

面向精确固件样本的 ATF-only NoGZ 离线研究工具，同时提供可安装的 Codex skill。

修改 `tee.img` 中的 ATF 启动交接，保持 **LK 进入 EL1h、AArch64 内核交接到 EL2h**，并同步 ATF/LK 共享的 GZ-info tag。签名前检测 preloader，按结果选择 pwnage 的 new/legacy 模式并离线验签。

> **实验性项目。** 离线回归和 `VALID` 不等于设备一定接受或能够启动。脚本没有自动刷写功能，不应在没有恢复条件的设备上盲目使用。本项目仅用于有权访问的固件与设备研究。

## 支持范围

| Profile | 目标样本 | 匹配方式 |
|---|---|---|
| `yunluo` | 已分析的 yunluo TEE/LK 配对 | 两个输入文件的完整 SHA-256 |
| `peral` | 已分析的 Xiaomi 13T TEE/LK 配对 | 两个输入文件的完整 SHA-256 |
| `xaga` | 已分析的 Redmi Note 11T Pro (xaga) TEE/LK 配对 | 两个输入文件的完整 SHA-256 |

完整哈希和地址定义见 [profiles.json](references/profiles.json)。机型名称相同、固件版本相近或文件大小一致，都不能替代哈希匹配。

- 原始文件保持不变，只生成独立的修改副本。
- LK 仅用于读取和回归；不修改 LK、preloader、GZ、RPMB 或 eFuse。
- 保留 GZ 内存预留和 remap，不宣称返还内存或直接获得 KVM。
- 不包含固件、预编译刷机镜像、设备日志、证书私钥或第三方签名工具。

## 为什么需要这些修改

此项目保留了三类可复现问题的反例检查：

1. `D2A21E08` 实际装入 `0x10f00000`，不是 LK 的 `0x50f00000`。正确编码为 `D2AA1E08`。
2. 当前两份原版 LK 的 EL2 入口路径会访问 `CPTR_EL3`，不能把 LK 和内核的入口级别一并强制为 EL2h。
3. 只修改 ATF 的 GZ getter 不会自动改变 LK 的状态；必须同步共享 tag，避免后续仍进入 GZ unmap 路径。

完整指令、偏移和验证边界见 [技术手册](docs/technical-guide.md)。

## 环境准备

Python 3.10+，建议使用独立虚拟环境。运行依赖见 [requirements.txt](requirements.txt)。
Windows 和 Linux 可以使用同一份脚本；实际固件回归仍需用户自行提供匹配的文件。

Linux / macOS：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

macOS 的底层依赖可用性需按自己的环境验证；本仓库 CI 配置覆盖 Ubuntu/Windows，不把命令可用等同于固件在设备上可用。

需要生成签名副本时，另行准备可信的完整 pwnage 工具目录及其依赖。
签名与验签调用其中的 `sign_mtk_cert.py` 和 `verify_mtk_image.py`，不会下载、安装或捆绑它们。
仓库另外原样收录了 [detect_pl_cert_mode.py](scripts/detect_pl_cert_mode.py)，用来离线检测 preloader 的证书遍历模式。

## 快速使用

以下命令均在仓库根目录运行。将输入和第三方工具放在仓库外，输出放在被忽略的 `outputs/` 中。

### 只做离线检查

Linux / macOS 示例：

```bash
.venv/bin/python scripts/build.py \
  --profile peral \
  --tee "$HOME/private-firmware/peral/tee.img" \
  --lk "$HOME/private-firmware/peral/lk.img" \
  --check-only
```

Windows PowerShell 示例：

```powershell
$inputDir = Join-Path $HOME 'private-firmware\peral'
.\.venv\Scripts\python.exe scripts/build.py --profile peral --tee "$inputDir\tee.img" --lk "$inputDir\lk.img" --check-only
```

LK 文件可以重命名，脚本匹配的是文件内容。处理 yunluo 时，使用 `--profile yunluo` 和对应的一对原始输入；处理 xaga（Redmi Note 11T Pro）时使用 `--profile xaga` 和该机型的原始 TEE/LK。

`--check-only` 只进行 TEE/LK 补丁回归，不检测签名模式，不生成镜像或输出目录，也不调用 pwnage。

### 先检测签名模式

```bash
.venv/bin/python scripts/detect_pl_cert_mode.py \
  "$HOME/private-firmware/peral/preloader.bin" --json
```

默认将完整证据保存到 `logs/` 下的新文件，目录已被 Git 忽略。报告包含输入路径和反汇编，不应直接上传。

| 检测结果 | pwnage 模式参数 |
|---|---|
| **new：`NEW_PARSER`** | **不加模式参数**，既不加 `--legacy`，也没有 `--new` |
| **legacy：`LEGACY`** | **加 `--legacy`** |
| `NEED_MANUAL`、不支持或结果不明确 | 停止签名，先人工分析，不按机型猜测 |

保留正常的 `--all -w -o` 输出选项。“new 什么也不加”指不增加模式选项，不是省略输入文件和写入选项。
检测脚本是静态证据分析，不是 efuse、漏洞可利用性或设备启动验证。

### 按检测结果生成签名副本

```bash
.venv/bin/python scripts/build.py \
  --profile peral \
  --tee "$HOME/private-firmware/peral/tee.img" \
  --lk "$HOME/private-firmware/peral/lk.img" \
  --preloader "$HOME/private-firmware/peral/preloader.bin" \
  --tools ../pwnage24mtk \
  --out-dir outputs/peral-run-01
```

签名必须提供与目标启动链对应的 `--preloader`。脚本自动调用检测器，不要求手动选择模式。
preloader 哈希会记入 manifest，但脚本不能仅凭文件名证明它与设备实际使用的一致。
`--out-dir` 必须是尚不存在的新目录。重复运行时更换目录，不要覆盖旧结果或将签名产物当成原始输入。

输出内容：

```text
outputs/peral-run-01/
  cert-mode.txt          # 完整检测证据
  detect.log             # 检测器 JSON 输出或错误
  tee.unsigned.img        # 中间文件，不是签名成品
  tee_nogz_legacy.img     # LEGACY 时；NEW_PARSER 时为 tee_nogz_new.img
  sign.log
  verify.log
  disassembly.txt
  manifest.json
```

检测到 `NEW_PARSER` 时使用 `--all -w`，检测到 `LEGACY` 时使用 `--legacy --all -w`。
随后要求两个 `Result: VALID`，并从最终成品重新提取 ATF 做回归。
这些是外部工具的证书处理方式，不代表拥有厂商私钥或获得新的官方授权。

查看退出码、完整日志和 `manifest.json`，不要仅凭 `.img` 文件存在判断成功。

## 作为 Codex Skill 使用

仓库根目录本身就是完整 skill，入口为 [SKILL.md](SKILL.md)。安装时保持 `scripts/`、`references/` 和 `docs/` 的相对结构。

先生成不含固件和本机记录的 skill 包：

```bash
python scripts/package.py --output dist
```

将 `dist/mtk-tee-nogz-skill.zip` 解压到 Codex 的 skills 目录，使最终结构为：

```text
<CODEX_HOME>/skills/mtk-tee-nogz/SKILL.md
```

未设置 `CODEX_HOME` 时，一般使用 `~/.codex/skills`。已有同名 skill 时先自行备份，不使用强制覆盖。安装不会一并安装 Python 或 pwnage 依赖。
skill 包只保留运行与阅读所需文件，不包含仓库的 CI、测试和打包脚本；开发维护请使用源码包。

调用示例：

```text
使用 $mtk-tee-nogz 检查我提供的 tee.img 和 LK。
匹配已知版本后生成 NoGZ 副本，检测对应 preloader，并按 new/legacy 结果签名和回归，不刷设备。
```

## 仓库结构

```text
.
├── README.md
├── SKILL.md
├── requirements.txt
├── agents/openai.yaml
├── docs/technical-guide.md
├── references/
│   ├── adaptation.md
│   └── profiles.json
├── scripts/
│   ├── build.py
│   ├── detect_pl_cert_mode.py
│   └── package.py
├── tests/
│   ├── test_build.py
│   ├── test_cert_mode.py
│   └── test_repository.py
└── .github/workflows/ci.yml
```

仓库只有一份补丁实现和一份 profile，不另复制一套 skill 专用代码。

## 测试和发布

以下维护命令需要源码仓库，而不是精简的 skill 安装包：

```bash
python -m unittest discover -s tests -v
python scripts/package.py --output dist
```

- 单元测试使用合成数据，不需要固件、pwnage、网络访问或设备；签名调度测试中的工具返回值是明确的 mock，不用于证明密码学验证。
- CI 配置在 Ubuntu/Windows 和 Python 3.11/3.12 上运行单元测试与打包。
- CI 不包含真实固件，因此不能替代 `build.py --check-only` 的已知镜像回归，更不能证明硬件兼容性。
- `package.py` 使用明确的文件白名单，生成源码包和可安装 skill 包；不打包目录里碰巧存在的镜像、日志或缓存。
- `.gitignore` 是防误提交措施，不是敏感信息审计替代品。公开 Issue、PR 和发布附件前仍需检查内容。

新增版本的要求见 [适配说明](references/adaptation.md)。不要通过修改已有哈希或删除断言绕过版本检查。

## 验证边界

已知镜像回归会检查 PC/SPSR、真实 ATF/LK tag parser、共享 flags、GZ gate 和有意构造的错误反例。
当前报告中的 14 条记录是有边界的检查记录，不是 14 次整机启动测试。

CPU 特征、CurrentEL、部分系统寄存器和缓存维护被显式建模；没有执行完整 LK 初始化、Linux、真实 ERET、PSCI 或外设。
离线验签若显示 `Trusted root check: skipped`，设备信任根仍未验证。

请在报告中分别注明：输入身份、离线结果、实际设备反馈和未验证项。

## 第三方与许可

运行依赖 [Capstone](https://www.capstone-engine.org/) 和 [Unicorn](https://www.unicorn-engine.org/)；可选签名流程依赖外部 pwnage 工具。各第三方项目遵循其自身许可证。

本仓库尚未指定代码与文档的分发许可证。公开发布前，应由仓库所有者确定并补充 `LICENSE`；不能把“可查看源码”解释为已授予任意再分发权。
