# MTK TEE NoGZ 技术与使用手册

文档日期：2026-09-29。对应仓库根目录的 `scripts/build.py` 和 `references/profiles.json`。

这是当前实现的说明，不是适用于所有联发科固件的通用刷机教程。文中的“通过”必须结合具体检查范围理解。
安装与快速使用见 [README](../README.md)。本手册说明精确样本上的实现，不授权实际设备写入。

## 目录

- [1. 范围与验收](#scope)
- [2. 文件结构与依赖](#files)
- [3. 启动链与执行级别](#boot)
- [4. 三个已确认的问题](#defects)
- [5. 补丁布局与指令语义](#patches)
- [6. 地址与配置字段](#profiles)
- [7. 运行方法](#usage)
- [8. 构建与签名流程](#build)
- [9. 回归检查及模型边界](#tests)
- [10. 产物与历史重现](#outputs)
- [11. 故障排查](#troubleshooting)
- [12. 新版本适配](#adaptation)
- [13. 迁移、维护与交接](#maintenance)

<a id="scope"></a>
## 1. 范围与验收

### 1.1 做什么

针对经过精确哈希匹配的 yunluo/peral 样本，在 `tee.img` 容器中的 ATF 数据区应用 NoGZ 补丁：

1. 将 ATF 首次交接的下一入口固定为 LK 的 `0x50f00000`。
2. 保持首次进入 LK 的 SPSR 为 EL1h。
3. 让 ATF 和 LK 对共享 GZ-info tag 的理解一致。
4. 将后续 AArch64 内核交接的 SPSR 强制为 EL2h。
5. 使用原样收录的检测器分析对应 preloader，按 new/legacy 结果调用 pwnage，再离线验签和对成品回归。

### 1.2 不做什么

- 不覆盖原始输入，不修改 LK、preloader 或 GZ 分区文件。
- 不执行 fastboot、ADB、下载代理、刷写、擦除、RPMB 或 eFuse 操作。
- 不实现 Bootloader 永久解锁，不更改设备身份。
- 不回收 GZ 保留内存，不关闭或重配 remap 硬件。
- 不捆绑固件、设备令牌、密钥、pwnage 工具或 Python 第三方依赖。
- 不证明所有内核、外设、PSCI、多核唤醒、休眠或厂商服务均兼容。

### 1.3 四种不同的“成功”

| 层次 | 证据 | 可以得出的结论 |
|---|---|---|
| 输入匹配 | TEE/LK 的完整 SHA-256 均符合 profile | 使用的是已知版本，不是仅机型名称相同 |
| 补丁正确性检查 | 原指令匹配、补丁集合一致、独立解码、指定路径回归 | 在列明的模型边界内得到预期行为 |
| 离线签名验证 | pwnage 对 ATF/TEE 输出两个 `Result: VALID` | 在该工具语义下通过检查 |
| 实机兼容性 | 用户明确反馈或设备日志、实际镜像回读等 | 只能按实际证据覆盖的设备与场景表述 |

前三项都通过，也不自动等于第四项。`device_tested: false` 是脚本的固定事实声明，不会因离线测试通过而变成 true。

<a id="files"></a>
## 2. 文件结构与依赖

```text
mtk-tee-nogz/
  README.md
  SKILL.md
  requirements.txt
  agents/openai.yaml
  docs/technical-guide.md
  references/
    profiles.json
    adaptation.md
  scripts/
    build.py
    detect_pl_cert_mode.py
    package.py
  tests/
    test_build.py
    test_cert_mode.py
    test_repository.py
  .github/workflows/ci.yml
```

| 文件 | 作用 |
|---|---|
| `README.md` | GitHub 展示入口、依赖、使用和发布说明 |
| `SKILL.md` | 技能入口、适用范围和关键限制 |
| `requirements.txt` | Python 运行依赖 |
| `agents/openai.yaml` | 展示名称与默认调用提示 |
| `profiles.json` | 两组已知输入哈希及经过定位的地址参数 |
| `adaptation.md` | 未知版本的审计要求和日志判读注意事项 |
| `docs/technical-guide.md` | 本手册 |
| `scripts/build.py` | 可执行的哈希检查、补丁、回归、签名与输出检查 |
| `scripts/detect_pl_cert_mode.py` | 原样收录的 preloader 证书遍历模式检测器 |
| `scripts/package.py` | 按文件白名单创建源码包和 skill 包 |
| `tests/` | 无固件单元测试和发布文件检查 |
| `.github/workflows/ci.yml` | GitHub Actions 测试与打包配置 |

以上为源码包结构。精简 skill 安装包保留 README、SKILL、依赖清单、agents、
docs、references、`scripts/build.py` 和检测器，不包含测试、CI 或打包脚本。
需要运行维护与打包命令时，应使用完整源码包。

运行依赖：

- Python 3.10+，推荐独立虚拟环境。
- `capstone`：独立反汇编检查补丁指令。
- `unicorn`：执行有明确边界的 AArch64 指令测试。
- 完整的 pwnage 工具目录，包括其 Python 模块依赖；不能只复制两个入口脚本后假定一定可运行。

依赖约束见 [requirements.txt](../requirements.txt)。不同库版本需要重新测试，不把版本号视为兼容性保证。
第三方 pwnage 程序由 `--tools` 指定，应使用可信、经过检查的工具副本。

脚本从自身相对路径读取 `profiles.json`，不依赖任何作者本机目录或其他分析工程。
输入固件与第三方工具应由使用者通过命令行显式指定，并放在仓库之外。
命令行参数解析前就会导入 Capstone/Unicorn，因此连 `--help` 也要求这两个模块可导入。

<a id="boot"></a>
## 3. 启动链与执行级别

### 3.1 本方案关注的两次交接

为突出补丁关系，以下省略安全世界初始化和许多平台步骤：

```text
preloader / BL2_EXT
  -> ATF/BL31 处理启动参数和 tags
  -> 首次下一镜像交接：LK，PC=0x50f00000，SPSR=0x3c5
  -> LK 初始化、读取共享 GZ tag
  -> LK 准备内核交接
  -> ATF 的 AArch64 kernel helper 构造内核入口与 SPSR=0x3c9
  -> 后续上下文恢复与 ERET
```

这不是 `build.py` 从头到尾实际运行的一次完整启动。脚本分别调用其中几个函数或片段，并在合成内存中检查结果。

### 3.2 EL1h 和 EL2h

这里使用的 AArch64 SPSR 低位模式编码：

| SPSR | 模式 | 本方案用途 |
|---|---|---|
| `0x3c5` | EL1h，包含异常屏蔽位 | 首次进入原版 LK |
| `0x3c9` | EL2h，包含异常屏蔽位 | 后续 AArch64 内核交接 |
| `0x1da` | 原 AArch32 路径所用值 | 保留该路径，不改成 AArch64 |

“内核进入 EL2h”不要求“LK 先在 EL2h 正常运行”。两者是不同阶段的调用和上下文。
把所有 SPSR 站点统一改成 `0x3c9`，会破坏当前这两份原版 LK 的早期入口路径。

### 3.3 NoGZ 的范围

本补丁让被检查的 ATF 路由和 LK GZ 判定走禁用状态，但不追溯撤销更早阶段的加载或保留内存行为。
不能把“跳过 GZ 下一入口”写成“preloader 从未加载 GZ”。

内核是否具备 KVM、VHE/nVHE 的具体能力，需要内核配置和实际运行状态证明。
内核入口 SPSR 的检查不能代替 `/dev/kvm`、虚拟机运行或设备功能验证。

<a id="defects"></a>
## 4. 三个已确认的问题

### 4.1 报告写对目标地址，不代表机器码写对

旧成品使用了 `D2A21E08`，并被误记为装入 LK 地址。独立解码和执行结果为：

```text
指令字 D2A21E08 -> mov x8, #0x10f00000
指令字 D2AA1E08 -> mov x8, #0x50f00000
```

当前代码通过字段组合生成：

```python
0xD2A00000 | (0x50F0 << 5) | 8
```

它表示 64 位 `MOVZ`、立即数 `0x50f0`、左移 16 位、目标寄存器 x8。
随后使用 Capstone 解码，并执行完整 cold PC writer 检查写入 `ep_info` 的实际 PC。

指令字展示和文件字节顺序也必须区分。正确指令字 `D2AA1E08` 在小端文件中的字节是：

```text
08 1E AA D2
```

### 4.2 强制 LK EL2h 会访问 EL3 寄存器

当前样本的 LK 在入口读取 `CurrentEL`：

- 来自 EL1 时，早期检查直接返回，随后继续初始化。
- 来自 EL2 时，会走到 `mrs x9, cptr_el3`。

两份 LK 中对应的非法读取位置：

| 样本 | LK 数据偏移 | 按本样本基址换算的地址 |
|---|---|---|
| yunluo | `0x3878` | `0x50f03878` |
| peral | `0x3a18` | `0x50f03a18` |

EL2 无权读取 `CPTR_EL3`。这是原版入口路径上的可达权限错误。
测试以架构规则显式拦截此读取；并没有完整模拟硬件如何投递异常、异常向量和看门狗。

该问题与错误 PC 是两个独立缺陷。不能因为存在这条指令，就断言旧日志中最初一定执行到了它。

### 4.3 ATF 认为禁用，不代表 LK 也认为禁用

ATF 与 LK 均消费共享 `gz_info`，但各有自己的 flags 缓存和 getter。
只让 ATF getter 返回 0，仍可能把原始 flags=0 的 tag 留给 LK，使后者继续认为 GZ enabled。

当前样本的判断表达式为：

```text
gz_enabled = (~flags) & 1
flags = 0 -> enabled
flags = 1 -> disabled
```

LK 后续 GZ gate 位于内核交接前。状态不一致会让 LK 进入与 ATF 路由不匹配的 GZ unmap 路径。
因此补丁必须同时解决路由和共享状态，而不是只改一个布尔函数。

<a id="patches"></a>
## 5. 补丁布局与指令语义

### 5.1 共享 tag 的最小结构

回归测试构造的有效 GZ-info tag 为 12 字节：

| 相对 tag 起点 | 内容 |
|---|---|
| `+0x00` | size，测试值为 12 |
| `+0x04` | id，`0x88610023` |
| `+0x08` | flags，4 字节 |

ATF tag dispatcher 传给 callback 的 x0 已经是 tag 起点加 8，即 flags 的地址。
LK 对应 callback 接收 tag 起点，再读取 `+8`。

这是解释为何补丁在 ATF callback 写 `[x0]`，而不是再写 `[x0,#8]` 的关键。
此回归不是针对任意损坏 tags 的格式加固测试，不证明所有 size、链表或重复 tag 输入都安全。

### 5.2 修改后的 callback

用语义表示，原 5 条指令位置变为：

```asm
mov w8, #1
adrp x9, <ATF flags 所在页>  // 原指令保留
str w8, [x0]                // 写共享 tag
str w8, [x9, #<原偏移>]      // 原指令保留，更新 ATF flags 全局
b <getter + 8>
```

getter 及借用的尾部：

```asm
getter:
    mov w0, #0
    ret
cache_tail:
    dc cvac, x0
    dsb sy
    b getter
```

正常调用 getter 会在前两条返回，不会使用调用者的 x0 做缓存操作。
callback 则携带 tag 地址进入尾部，先 clean，再 barrier，最后经 getter 返回 0。
使用 `b` 而非 `bl`，保持 callback 的原始 LR。

这里把整个 32 位 flags word 置为 1，不是仅对 bit 0 做 OR。
这一行为只对已审计样本成立；其他版本若高位有独立含义，必须重新分析。

`dc cvac`/`dsb sy` 的目标和顺序会被检查，但模拟器不包含真实 SoC 缓存或内存保护硬件。

### 5.3 全部 10 个指令槽

下表偏移均相对 ATF 数据起点，不是整个分区的绝对文件偏移。

| 用途 | yunluo ATF 偏移 | peral ATF 偏移 | 新指令字 |
|---|---|---|---|
| 正确 LK 入口 | `0x12914` | `0x1a8a8` | `D2AA1E08` |
| AArch64 内核 SPSR | `0x47ac` | `0x65fc` | `5280792C` |
| GZ getter 返回零 | `0xac7c` | `0xe18c` | `52800000` |
| getter 提前返回 | `0xac80` | `0xe190` | `D65F03C0` |
| callback flags=1 | `0xa578` | `0xdaa8` | `52800028` |
| 写共享 flags | `0xa580` | `0xdab0` | `B9000008` |
| 跳转清理尾部 | `0xa588` | `0xdab8` | yunluo `140001BF`，peral `140001B7` |
| clean tag cache line | `0xac84` | `0xe194` | `D50B7A20` |
| barrier | `0xac88` | `0xe198` | `D5033F9F` |
| 尾部返回零 | `0xac8c` | `0xe19c` | `17FFFFFC` |

原 getter 首两条和全部其他原值在 `patches()` 中校验；getter 的原始页/偏移指令由 profile 区分。
每次应用补丁前，都需要原指令字精确相等。

10 个槽覆盖 40 字节，但不能写成“恰有 40 个字节值改变”，因为新旧指令可能共享部分字节。
ATF 数据长度不变，没有附加独立 payload；签名后成品整体增长来自证书区域的变化，大小取决于检测选择的模式及工具版本。

首次进入 LK 的 cold SPSR selector 保持原版：

- yunluo：ATF 数据偏移 `0x1295c`。
- peral：ATF 数据偏移 `0x1a8f0`。

<a id="profiles"></a>
## 6. 地址与配置字段

### 6.1 三类地址不要混用

当前两个输入中 ATF 是 tee 容器的第一组，数据起点为文件 `+0x200`：

```text
tee.img 文件偏移 = ATF 数据偏移 + 0x200
ATF 测试地址    = ATF 数据偏移 + 0x48200000
LK 测试地址     = LK 数据偏移  + 0x50f00000
```

例如 peral 的 PC 补丁：

```text
ATF 数据偏移：0x1a8a8
tee 文件偏移：0x1aaa8
ATF 测试地址：0x4821a8a8
```

脚本确实硬编码了补丁写入容器时的 `+512`，不是通用自动定位任意子镜像偏移的工具。
它还只支持此处所用 512 字节 header、16 字节对齐及已知布局。
完整输入哈希检查是这些假设能够受控使用的前提。

`0xffff000000000000` 高位 alias 用于 LK 的链接地址。
测试中的高低地址通过 `mem_map_ptr` 指向同一底层缓冲，避免把 tag 当成两份互不相干的数据副本。

### 6.2 精确匹配的输入

完整机器可读值以 [profiles.json](../references/profiles.json) 为准：

```text
yunluo tee:
bef7809d0990a921e83108cbdf938b68dab74839ec58d195a3bf89a958aa0568
yunluo LK:
fb17770070d1367440e185474a5c2b1ddce42edbd19f2e260d6d664eaa173b76

peral tee:
457cc18c9abdf6efd19fb06f913370a195e59bfaf4fe0398de70713bb2e541dd
peral LK:
b667a393d6d5bf573424f0e96615bea8207f27ba28dc7ba7097f7b3b5b09e5e2
```

重命名文件不影响匹配；同机型的另一个固件版本、旧签名成品或已打过其他补丁的 LK 通常不匹配。
不得为了通过检查，直接将 profile 哈希替换成手头文件的哈希。

### 6.3 profile 字段

除完整哈希外，当前所有十六进制地址字符串都是相对 ATF 或 LK 数据的偏移。
区间字段采用 `[start, end)`，end 为不包含的上界；`kernel` 的 end 同时是显式停止点。

| 字段 | 含义 |
|---|---|
| `tee_sha256`、`lk_sha256` | 输入文件身份 |
| `historical_output_sha256` | 原工具版本下的历史修正版成品哈希 |
| `historical_output_cert_mode` | 历史成品采用的模式；仅用于比较，不决定本次签名模式 |
| `pc_patch` | cold writer 中设置下一入口的指令 |
| `kernel_patch` | AArch64 kernel helper 中选择 SPSR 的指令 |
| `getter`、`getter_before` | ATF GZ getter 入口及原前两条指令 |
| `callback`、`flag` | ATF GZ-info callback 入口和 flags 全局位置 |
| `cold`、`cold_helpers` | cold writer 及其直接辅助读取函数的测试范围 |
| `kernel` | 内核交接 helper 的有界执行范围 |
| `ep` | 用于检查输出的 ep_info 位置 |
| `kernel_args` | 模型填写内核入口及参数的位置 |
| `tag_parser`、`args_getter` | ATF tag dispatcher 和启动参数 getter 范围 |
| `handoff_global` | ATF 保存 handoff 指针的位置 |
| `lk_parser` | LK 真实 tag dispatcher 范围 |
| `lk_getter`、`lk_callback` | LK GZ getter、GZ-info callback |
| `lk_gate`、`lk_skip` | LK 内核交接前 GZ gate 和禁用时的跳转目标 |
| `lk_stack`、`lk_elcheck` | LK 早期栈设置和 CurrentEL 检查范围 |
| `lk_illegal` | 已定位非法读取的记录字段；当前通用脚本并不直接使用此字段判定 |

关键数据位置对照：

| 对象 | yunluo 数据偏移 | peral 数据偏移 |
|---|---|---|
| ATF flags 全局 | `0x2ffb4` | `0x43f00` |
| ATF ep_info | `0x3d930` | `0x598b0` |
| ATF handoff 指针全局 | `0x3daf0` | `0x59a70` |
| LK GZ getter | `0x19d54` | `0x1e8d8` |
| LK GZ-info callback | `0x19d68` | `0x1e8ec` |
| LK GZ gate | `0x280c` | `0x28d4` |
| LK 跳过 GZ 的目标 | `0x283c` | `0x2904` |

<a id="usage"></a>
## 7. 运行方法

### 7.1 对话调用

```text
使用 $mtk-tee-nogz 检查这份 tee.img 和对应 LK。
版本匹配后生成 ATF-only NoGZ 副本，检测对应 preloader 并按 new/legacy 结果签名，不刷设备。
```

补丁回归需要正确的 TEE 和对应 LK，签名还需要对应 preloader。其他分区不会因为在同一目录就自动被处理。

### 7.2 依赖检查

以下是 PowerShell 命令，不是 cmd.exe 或 Bash：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -c "import capstone, unicorn; print(capstone.__version__, unicorn.__version__)"
```

在仓库根目录运行；上述安装命令仅配置虚拟环境，不由构建脚本自动执行。
使用 Linux/WSL 时采用 `.venv/bin/python`。不要在不同操作系统间复制含原生扩展的虚拟环境。

### 7.3 只检查，不生成镜像

peral：

```powershell
$inputDir = Join-Path $HOME 'private-firmware\peral'
.\.venv\Scripts\python.exe scripts/build.py --profile peral --tee "$inputDir\tee.img" --lk "$inputDir\lk.img" --check-only
```

yunluo：

```powershell
$inputDir = Join-Path $HOME 'private-firmware\yunluo'
.\.venv\Scripts\python.exe scripts/build.py --profile yunluo --tee "$inputDir\tee.img" --lk "$inputDir\lk.img" --check-only
```

`--check-only` 仍会检查 TEE/LK 身份、在内存中构造补丁并执行回归。
它不检测签名模式，即使传入 `--preloader` 也不运行检测器；结果中的 `cert_mode` 为 null。
它不调用 pwnage、不生成镜像或指定输出目录；结果 JSON 输出到标准输出，不会自动另存 `manifest.json`。

### 7.4 单独检测 preloader

```powershell
$inputDir = Join-Path $HOME 'private-firmware\peral'
.\.venv\Scripts\python.exe scripts/detect_pl_cert_mode.py "$inputDir\preloader.bin" --json
```

检测器按 preloader 的 GFH 和证书遍历指令证据判断，不按机型名称或是否有重试循环判断：

| 检测状态 | 解释 | 签名参数 |
|---|---|---|
| `NEW_PARSER`，即 new | 识别到已支持的 tag-aware 证书遍历 | 不加模式参数 |
| `LEGACY` | 识别到需要 legacy wrapper 的 enter-value 遍历 | 加 `--legacy` |
| `NEED_MANUAL` | 证据不足、冲突、格式或指令不受支持 | 停止，人工分析 |

**new 不加 `--legacy`，也不存在 `--new`。** `--all -w -o` 仍是正常的签名输出选项。

无 `--report` 时，检测器创建 `logs/cert_mode_*.txt` 保存完整证据；该目录被 Git 忽略。
指定 `--report` 时，父目录应已存在，目标报告必须是新文件，不能覆盖 preloader。
`--json` 输出结构化结果；正常识别退出 0，NEED_MANUAL 退出 3，报告保存错误退出 2。
检测器还提供 `--regress`，只用于按顺序检查两个输入是否分别返回 NEW_PARSER 和 LEGACY，不应由构建流程强制某个机型符合固定模式。

原脚本完整保留，SHA-256 为：

```text
a11f209e8cef3a08f43b39875386d345c00836c7f4c25f48712a58308fe041c7
```

当前检测器支持其代码识别范围内的 Thumb/AArch64 preloader；静态模式识别不等于证明 efuse、漏洞可利用性或设备启动。

### 7.5 生成并签名

以下 peral 示例使用新的唯一输出目录，可避免重复运行误覆盖旧结果：

```powershell
$inputDir = Join-Path $HOME 'private-firmware\peral'
$tools = '..\pwnage24mtk'
$outDir = Join-Path 'outputs' ('peral-' + [guid]::NewGuid().ToString('N'))
.\.venv\Scripts\python.exe scripts/build.py --profile peral --tee "$inputDir\tee.img" --lk "$inputDir\lk.img" --preloader "$inputDir\preloader.bin" --tools "$tools" --out-dir "$outDir"
```

处理 yunluo 时同时更换 profile 和输入文件；示例中的 LK 文件名可以按实际情况调整，文件内容哈希不可更改。
普通构建要求 `--tools`、`--out-dir` 和 `--preloader`；输出目录必须尚不存在，即使已有目录为空也会拒绝。
脚本在写出 unsigned 镜像前自动检测模式；检测失败时只保留已生成的证据/错误报告，不继续签名。
preloader 不按 profile 固定哈希选择模式，但会记录并检查本次输入的哈希；使用者必须确保提供的是目标启动链对应的文件。

### 7.6 CLI 参数全集

| 参数 | 必需条件 | 说明 |
|---|---|---|
| `--profile` | 始终 | 当前仅 `yunluo` 或 `peral` |
| `--tee` | 始终 | 原始 tee.img 路径 |
| `--lk` | 始终 | 匹配 profile 的原始 LK 路径，仅用于读取测试 |
| `--preloader` | 普通构建 | 对应 preloader，仅用于模式检测与哈希记录 |
| `--check-only` | 可选 | 只检查，无签名输出 |
| `--tools` | 普通构建 | pwnage 所在目录 |
| `--out-dir` | 普通构建 | 尚不存在的新输出目录 |

脚本没有 `--force`、自动刷写、下载固件或绕过哈希选项。
PowerShell 中可用 `$LASTEXITCODE` 判断命令是否失败；不要只看是否曾出现 VALID 或是否已有 `.img` 文件。

<a id="build"></a>
## 8. 构建与签名流程

当前 `main()` 的顺序为：

1. 读取 profile 和两份完整输入。
2. 精确匹配 TEE/LK SHA-256。
3. 解析容器，确认 TEE 中是 `atf`、`tee` 两组。
4. 对 ATF 原始指令逐项校验，在内存中构造补丁。
5. 运行补丁前置回归。
6. 若为 check-only，打印结果后结束。
7. 普通构建要求 preloader、工具和新输出目录，再创建目录。
8. 调用原样收录的检测器，保存 `cert-mode.txt` 和 `detect.log`。
9. 只接受一个明确的 NEW_PARSER 或 LEGACY 结果，核对报告路径和 preloader 哈希；其他情况停止。
10. 写出 `tee.unsigned.img`，在原始容器的 ATF 区应用同一组补丁。
11. NEW_PARSER 不加模式参数，LEGACY 加 `--legacy`，调用 pwnage 签名一次。
12. 调用验签工具，要求输出中有两个 `Result: VALID`。
13. 重新解析签名成品，确认 TEE 数据区不变、ATF 只包含指定修改，再次回归。
14. 检查原 TEE/LK 和 preloader 未改变，保存反汇编和 manifest。

签名命令的语义：

```text
# NEW_PARSER / new:
sign_mtk_cert.py tee.unsigned.img --all -w -o tee_nogz_new.img
verify_mtk_image.py --all tee_nogz_new.img

# LEGACY:
sign_mtk_cert.py tee.unsigned.img --legacy --all -w -o tee_nogz_legacy.img
verify_mtk_image.py --all tee_nogz_legacy.img
```

`--all` 处理容器中的两组证书，`-w` 写入新输出。
这里按检测结果选择 pwnage 的 new/legacy 证书处理模式，不意味着拥有厂商私钥或生成了新的官方授权。
具体效果以所用工具源码、完整日志和设备验证为准。

不要把已签名成品当成新的原始输入重复执行 override 插入，也不要在检测不明确时自动重试另一模式。
若签名工具失败，日志和可能的中间文件会保留；脚本没有自动回滚或清理输出目录。
下次重试应使用新目录，不应跳过失败检查去使用残留成品。

脚本自动判定依赖工具退出码和 VALID 计数；人工复核仍应检查完整 `verify.log` 中的
CERT1/CERT2、header/data hash 和 Trusted root 行，不能把日志中的任意“OK”当作全部通过。

<a id="tests"></a>
## 9. 回归检查及模型边界

### 9.1 当前报告的 14 条记录

这是 `passed_checks` 数组的条目数，不是完整硬件测试数，也不等于旧分析工程的 unittest 数量。
preloader 检测是单独的签名前置步骤，其完整证据保存在检测报告中，不算入这里的 14 条 ATF/LK 回归记录。

| 记录 | 数量 | 实际检查 |
|---|---:|---|
| `shared_chain ...` | 8 | flags 为 0、1、2、0xffffffff，与 GZ tag 在前/在后组合 |
| `missing_tag_defaults` | 1 | 空 tag 链时，原数据初始状态使 LK 跳过 GZ gate |
| `LK_EL2_illegal_EL3_negative_control` | 1 | 强制模型 CurrentEL=EL2，检出非法 CPTR_EL3 访问 |
| `kernel_feature_and_AArch32_controls` | 1 | 多组特征输入和原 AArch32 路径，其中包含多个子检查 |
| `wrong_PC_negative_control` | 1 | 人为恢复错误编码，确认 writer 写出 0x10f00000 |
| `missing_tag_sync_negative_control` | 1 | 人为恢复原 callback，确认 LK 重新进入 GZ 分支 |
| `budget_exhaustion_rejected` | 1 | 仅给一条指令预算时必须报错 |

还有输入身份、补丁集合相等、PC 指令独立解码、签名后的组结构和 TEE 数据区等检查，
它们不会全部各自追加一条 `passed_checks`。

负例“通过”表示测试成功检出故意构造的问题，不表示错误固件可用。

### 9.2 八组共享链具体做什么

每一组新建一个 Machine：

1. 建立共享 tag 内存，包含有效 GZ-info、一个不认识的邻接 tag 和结束标记。
2. 执行真实 ATF parser，然后执行真实 LK parser。
3. 检查只有预期 flags word 改为 1，其他构造的 tag 字节不变。
4. 检查 ATF flags 全局为 1，并记录到 tag 地址上的 clean 与 barrier 顺序。
5. 执行 cold writer，要求 `(PC,SPSR)=(0x50f00000,0x3c5)`。
6. 执行 LK 的最早入口片段，停止于 `LK+8`。
7. 执行 LK GZ gate，要求进入 skip 目标。
8. 执行 AArch64 kernel helper，要求模型入口 `0x40080000` 与 SPSR `0x3c9`。

特别注意第 2 步中的 LK parser 在这个测试程序里被提前单独调用。
函数调用顺序、每次 `run()` 重设的测试栈和 LR，都不是实机启动时序的完整复现。
它证明共享数据和相关函数的契约在模型中一致，不是连续 boot ROM 到内核的启动模拟。

`0x40080000`、`0x44000000`、`0x1000` 是模型填写的内核入口/参数值，不是从某次真机寄存器读取的值。

### 9.3 实际执行和显式建模的分界

| 内容 | 处理方式 |
|---|---|
| 被允许片段内的普通算术、分支、访存、真实 parser | Unicorn 执行镜像原指令或指定补丁指令 |
| `CurrentEL` | 由测试选择值后写入目标寄存器 |
| `ID_AA64PFR0_EL1` | 由测试提供合成特征值 |
| 部分 EL2 系统寄存器写入 | 记录事件并跳过实际硬件效果 |
| EL2 下读取 CPTR_EL3 | 按架构规则显式标记错误并停止 |
| `dc cvac`、`dsb sy` | 记录地址、数据和顺序，不模拟真实缓存 |
| 地址映射 | 合成内存，LK/tag 高低地址共享底层缓冲 |
| 内存权限 | 测试映射采用 `UC_PROT_ALL`，不验证真实 MMU/EMI/TrustZone 权限 |
| 片段外执行、预算耗尽 | 立即失败，不默认为成功 |

默认每次 `run()` 的指令预算为 20,000。成功要求到达指定停止点或明确的负例错误状态。
预算检查避免把未执行完当成返回成功。

### 9.4 当前 skill 脚本没有覆盖什么

- 不执行内核 helper 后面的完整上下文初始化和真实 ERET。
- 不验证 SCR_EL3.HCE/RW 在硬件上的最终值。
- 不运行完整 LK 初始化、DT 修改、Android、KVM 或外设。
- 不验证所有有效或无效 tags、所有中断、所有间接调用。
- 不重新进行整个镜像的代码/数据分类或全面入边扫描。
- 不自动检查备用分区、槽位、实际分区容量或设备中运行文件的哈希。
- 不验证缓存 clean 后实机观察到的数据与模型完全相同。

早期独立分析工程的用例集合与当前脚本不同。引用历史报告时须注明来源和范围，
不能把历史分析具备的检查都归到当前脚本。
仓库 CI 的无固件单元测试是第三种测试范围，也不能代替上述真实镜像回归。

<a id="outputs"></a>
## 10. 产物与历史重现

### 10.1 输出目录

```text
新的输出目录/
  cert-mode.txt
  detect.log
  tee.unsigned.img
  tee_nogz_new.img 或 tee_nogz_legacy.img
  sign.log
  verify.log
  disassembly.txt
  manifest.json
```

| 文件 | 说明 |
|---|---|
| `cert-mode.txt` | 检测器保存的完整证书遍历证据 |
| `detect.log` | 检测器 stdout/stderr；成功时包含 JSON 结果 |
| `tee.unsigned.img` | 改过 ATF、尚未由本次 pwnage 重签的中间文件，不是交付成品 |
| `tee_nogz_new.img` / `tee_nogz_legacy.img` | 根据模式选择的签名成品名，仍有实机验证边界 |
| `sign.log` | 签名子进程完整 stdout/stderr |
| `verify.log` | 验签子进程完整 stdout/stderr |
| `disassembly.txt` | 最终签名镜像中 10 个补丁槽的反汇编，不是完整 ATF 反汇编 |
| `manifest.json` | 当前运行的身份、输出、检查、补丁和工具记录 |

不同机型输出文件名相同，但必须放在不同目录中。
交付时用 manifest 的 profile、模式、完整路径和哈希识别，不能只靠文件名猜机型。

### 10.2 manifest 解释

| 字段 | 说明 |
|---|---|
| `profile` | 当前选择的已知样本 |
| `input_tee_sha256`、`input_lk_sha256` | 实际读入文件的哈希 |
| `input_preloader_sha256` | 检测的 preloader 哈希 |
| `cert_mode`、`signing_mode_flags` | `new`/`legacy` 和实际使用的模式选项列表 |
| `cert_detection`、`cert_detection_report` | 检测状态、ISA、原因和完整报告的相对路径 |
| `output`、`output_size`、`output_sha256` | 成品路径、字节数与哈希 |
| `passed_checks` | 签名后重新执行回归的记录列表 |
| `historical_output_cert_mode` | profile 中历史成品采用的模式 |
| `historical_output_matches` | 模式相同时比较完整哈希，模式不同时为 null |
| `device_tested` | 当前固定为 false |
| `scope` | 有界指令回归，不是完整启动验证 |
| `patches` | 每个槽的 ATF 偏移、文件偏移、原指令和新指令 |
| `tool_hashes` | 两个 pwnage 入口脚本与原样检测器的哈希 |

`tool_hashes` 不是完整 Python 环境或 pwnage 全目录的锁文件。
`historical_output_matches` 为 false 时，脚本不会仅因此退出失败；它与输入身份拒绝属于不同检查。
此时要比较工具版本、证书布局和完整日志，不能直接认定成品错误，也不能直接忽略差异。
为 null 时表示本次模式与历史模式不同，未执行跨模式哈希比较；不能因此改回历史模式。

### 10.3 已经复现过的成品

以下是引入自动检测之前，两份输入以 legacy 模式生成的历史成品，仅供追溯：

```text
yunluo
大小：3415872 字节
SHA-256：
7147b1bf057e942d5935dd6eeda37486f5627db923bf73b13fcd5dcd3b43f6e2

peral
大小：3296560 字节
SHA-256：
64efbf74b2c28f5063d3bf43109ebd4919579054a8cf8326e3521024fe7fecfd
```

当时两个 profile 的原始 tee 分别为 3,413,728 和 3,294,416 字节，
签名输出均增长 2,144 字节。这个增长值是该工具版本和样本的结果，不是未来所有工具版本的硬性常数。

两份历史日志都包含 `Trusted root check: skipped`，不等于设备信任根已验证。
历史 legacy 成品不能决定本次模式；无论机型叫什么，均以当前提供的对应 preloader 检测结果为准。

<a id="troubleshooting"></a>
## 11. 故障排查

### 11.1 脚本错误

| 错误或现象 | 优先检查 | 不应采取的做法 |
|---|---|---|
| `Unknown tee SHA256` | 是否选错版本、已签名成品或修改过的 tee | 改 profile 哈希掩盖不匹配 |
| `Unknown LK SHA256` | 是否是对应原版 LK、其他锁态补丁版 | 把机型相同当作代码一致 |
| `--preloader required when signing` 或缺少必需参数提示 | 是否提供了对应 preloader | 继续使用旧版统一 legacy 命令 |
| 检测器非零退出、`NEED_MANUAL`、未知状态 | `cert-mode.txt` / `detect.log` 中的证据和原因 | 按机型猜测或自动回退另一模式 |
| Detector input path/hash mismatch | 文件是否在检测期间变化，检测 JSON 是否对应本次输入 | 忽略检测与输入绑定 |
| `Original instruction mismatch` | profile/脚本是否被改动，偏移或输入是否错误 | 去掉原值断言继续写 |
| `Unsupported image header`、`Truncated image` | 容器布局、完整性和文件选择 | 强行按已知布局切片 |
| `ModuleNotFoundError` | 使用的 Python、依赖路径及平台是否一致 | 无依据切换另一解释器并假定结果相同 |
| `Output directory exists` | 换全新的输出目录 | 删除或覆盖不明旧产物 |
| `Unmodelled PC` | 执行轨迹、真实依赖函数或 profile 范围 | 给未知函数直接注入成功返回 |
| `Instruction budget exhausted` | 是否死循环、异常跳转或缺少模型边界 | 仅无限增加预算直到无输出 |
| `Wrong cold PC/SPSR` | 指令实际立即数、PC writer、cold selector | 只检查写入字节与旧报告一致 |
| `LK still enters GZ unmap` | 共享 flags 地址、parser、callback 和缓存顺序 | 只强制 ATF getter 返回零 |
| pwnage 失败或 VALID 不足两个 | 完整 sign/verify 日志、工具及模块版本 | 重复给残留 signed 文件插入 override |
| 目录里有成品但无 manifest | 是否在中途失败，查看退出码 | 因为文件存在就宣称全部通过 |

签名后原输入一致性检查只证明脚本结束时重新读取的 TEE/LK 与开始时一致，preloader 哈希与本次检测一致，
不是对整个磁盘做过完整审计，也不是设备分区回读。

### 11.2 expdb 和实机现象

这部分用于解释用户已经导出的日志，不授权自动连接设备：

- 先确认导出文件的位置，Windows HOME 与 WSL HOME 是不同目录。
- 先确定是否包含多轮启动、多个日志区或旧环形缓冲，再使用时间戳排序。
- `image atf auth pass` 和 BL31 banner 支持“该轮已经执行 ATF”，但不提供运行镜像 SHA-256。
- `PC=0x200`、SP/LR 异常和 watchdog 支持早期故障判断，不唯一确定首次出错指令。
- `ESR_EL2=0x02000000` 的 EC 为 0，不能把它误读成已经定位某种特定数据异常。
- preloader 的 `next is GZ` 是早期选择打印，不能否定 ATF 之后重新选择 PC。
- 仅看到 GZ 日志，不能排除旧缓冲；仅看到亮屏，也不能证明 LK 已完成初始化。
- 把用户明确报告、日志中直接出现的事实、静态指令推导和假设分别记录。

关于实际硬件恢复或下一次刷写，应由用户另行明确授权并确认工具、槽位和恢复条件。
本 skill 不包含自动恢复命令，也不因用户希望“继续直到成功”就自行执行写入。

<a id="adaptation"></a>
## 12. 新版本适配

当前 CLI 的 `--profile` choices 明确只有 `yunluo` 和 `peral`。
新增 JSON 项本身不足以完成支持，也不能仅更新哈希；需要重新审计代码、布局和测试。

适配前读 [未知版本与排错](../references/adaptation.md)，重点包括：

1. 固定并记录新 TEE/LK 输入身份，定位 ATF 数据、基址及容器头。
2. 区分 cold writer、kernel helper、最终上下文恢复，而不是按出现的 `0x3c9` 全部替换。
3. 定位新 GZ getter、全部消费者、共享 tag parser、callback 和 flags 默认值。
4. 检查 LK 的入口约束及 GZ gate，确认新机型是否真的需要相同处理。
5. 确认 callback 的 x0 语义、执行时序、内存写权限、缓存可见性。
6. 确认借用尾部没有其他代码入口或数据用途，保留调用约定。
7. 为该版本建立正例与反例，再调整 profile、CLI 和必要的模型。
8. 在独立新目录构建，对签名成品重跑；记录硬件尚未覆盖的部分。

若基址、tag 位置、寄存器分配或入口 ABI 不同，仅加 profile 偏移可能仍不够。
脚本中的固定常量、特定系统指令识别和模拟地址空间也需要随证据调整。

<a id="maintenance"></a>
## 13. 迁移、维护与交接

### 13.1 迁移 skill

保持整个 `mtk-tee-nogz` 目录结构，尤其是 `scripts/` 与 `references/profiles.json` 的相对关系。
在目标机器准备用户自有 TEE/LK/preloader、可用 Python 依赖和 pwnage 目录，重新跑 check-only、检测模式后再构建。

迁移 skill 不意味着迁移固件、密钥、设备证据或第三方工具。
路径由使用者明确提供，不应扫描或修改无关分区。公开包不包含个人机器的路径记录。

仓库根目录执行 `python scripts/package.py --output dist` 可生成源码包和 skill 包。
打包器按文件白名单收录内容；新增需要发布的文件时，应同步维护白名单和相关测试。
重复打包前应选择新的输出目录或先自行保存旧压缩包；打包器不会覆盖已有同名包。

### 13.2 维护时的检查

- 文档修改：核对参数、字段和计数与当前代码一致，验证引用链接与打包内容。
- profile/脚本修改：在新目录重跑两个已知样本，检查已知负例仍可被检出。
- pwnage 变更：记录工具哈希和完整输出，重新比较 ATF 修改集合及 TEE 数据区。
- 若需要声称相同构建可重现，比较完整输出 SHA-256，而非只比较文件大小。
- 不把文档示例、历史备注或设备日志中的文字当成新的执行授权。

skill 格式验证命令为 skill-creator 提供的：

```text
quick_validate.py <mtk-tee-nogz 所在目录>
```

它检查技能格式，不验证补丁或设备安全性；依赖的 YAML 模块也属于验证环境，而不是构建镜像所需依赖。

### 13.3 最小交接信息

交接时至少保留：

- profile、实际 TEE/LK SHA-256。
- 最终成品绝对路径、大小、SHA-256，以及 new/legacy 模式。
- manifest、完整 preloader 检测报告、sign/verify 日志和补丁反汇编。
- 使用的 skill/工具版本或文件哈希。
- 明确的测试范围、失败记录和实机验证状态。

推荐结论写法：

> 已完成精确样本匹配、指定 ATF 补丁、签名成品回归和离线验签。
> 相关输入保持不变。未执行设备操作，未验证整机启动及硬件兼容性。

只有获得额外实机证据后，才增加具体设备与场景下的运行结论，不覆盖或抹去此前离线边界。
