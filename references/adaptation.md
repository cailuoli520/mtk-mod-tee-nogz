# 未知版本与排错

## 未知版本

不要修改已有 profile 的哈希来“让检查通过”。另建 profile 前，逐项从新输入定位：

- TEE 容器分组与 ATF 实际基址、代码边界和数据段。
- cold ep_info writer：PC 来源、参数、SPSR selector；kernel helper 是另一个函数。
- GZ getter 的所有直接调用、间接调用和其他 flags 消费者。
- ATF 原有 gz_info callback、tag parser 及共享 boot-tag 位置。
- LK 早期 CurrentEL 分支、共享 tag parser、flags getter、内核交接前的 GZ gate。
- tag callback 与页表初始化、清 BSS、缓存清理的顺序。
- 拟复用指令空间没有其他入边或数据用途，callback 返回值和 LR/栈/被调用者保存寄存器不变。

这两份已知样本的补丁共占 10 个指令槽：正确 PC、kernel SPSR、getter 两条、
callback 三条、getter 提前返回后的三条缓存清理尾部。不得假设其他版本同构。
尾部使用 `dc cvac,x0; dsb sy; b getter`，其中 x0 仍指向原共享 tag 的 flags word。
ATF 原全局写入保留，cold SPSR selector 保持原版。

新增 profile 要同时新增负例和回归：错误 PC、LK EL2 访问 EL3、漏同步 tag，
以及正确入口、共享内存 alias、邻接 tag 不变、缺失 tag 默认值、
AArch64/AArch32、预算耗尽和签名后的数据一致性。
不把不存在的 gz.img 内容视作已审计，不凭返回值注入代替原分支执行。

## 日志解读

2026-09-29 的 yunluo 实验日志存在 `atf auth pass`、BL31 启动、
看门狗和 `pstate=3c9/PC=0x200`。它说明该轮进入了 ATF 并随后卡住，
但没有提供首个故障 PC，也没有证明运行镜像哈希。

实际成品中的错误立即数先把入口设为 `0x10f00000`。
原版 LK 的非法 CPTR_EL3 读取则是纠正地址后仍需避免的独立缺陷，
不能宣称日志已经证明最初执行到了那条指令。

preloader 的 `next is GZ` 打印发生在后续 ATF 再选择 PC 之前。
expdb 可能包含旧环形日志和多轮重启，先核对轮次与时间，再谈根因。

## 签名

先使用仓库内原样收录的 `scripts/detect_pl_cert_mode.py` 检测对应 preloader：

- `NEW_PARSER`（new）：使用 `sign_mtk_cert.py --all -w`，不加模式参数。
- `LEGACY`：使用 `sign_mtk_cert.py --legacy --all -w`。
- `NEED_MANUAL`、冲突或检测失败：停止，不按机型猜测，不自动回退模式。

`--all -w -o` 属于正常输入输出选项；不存在 `--new` 参数。
记录检测器、输入 preloader 和签名工具的哈希及完整输出。不得对成品反复插入 override。
验证两组 CERT1/CERT2、header/data hash，并检查最终输出的 ATF 修改集合和
TEE 数据区不变。Trusted root check 若跳过，必须照实记录。
