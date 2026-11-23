---
type: index
status: Accepted
updated: 2026-11-24
---

# stuhelper-storage-bhpan

BHpan 是 StuHelper 的北航云盘协议适配库。Go 包名为 `bhpan`，导入路径为 `github.com/StuHelper/stuhelper-storage-bhpan`。库仅依赖 Go 标准库，提供 通过 BHpan 官方入口登录、会话续期、容量、文件、传输与分享接口。

backend 装配 BHpan 客户端，storage 的 BHpan 驱动管理平台目录、对象位置与物理副本。media 通过 storage 的公开接口管理文件与引用。数据归属和容量采样见[接入设计](docs/design/storage-adapter.md)。

运行 `make setup` 安装锁定的工程工具，运行 `make check` 检查依赖、协议、文档、Go race、vet、构建及工作流。Makefile 默认使用 `GOWORK=off`。调用示例和真实账号验证步骤见[使用指南](docs/guide/bhpan.md)。

接口和验证记录见[文档导航](docs/README.md)。代码与文档使用 [AGPL-3.0-only](LICENSE) 许可。
