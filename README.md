# stuhelper-storage-bhpan

StuHelper 开源 BHpan 存储适配模块，拥有独立 Go module、契约、测试和版本。包名为 `bhpan`，导入路径为 `github.com/StuHelper/stuhelper-storage-bhpan`。

模块只使用 Go 标准库，支持北航 SSO 与网盘本地账号登录、容量与文件操作、普通和分片传输、分享。实现不依赖 campus-adapters、media、backend 或旧 StuHelper。旧项目仅作为供应商 API 参考。

使用方通过 Go 接口在程序入口装配模块。业务授权、凭据保管、文件引用、存储贡献与任务恢复由业务模块管理；具体边界和导入示例见[接入设计](docs/design/storage-adapter.md)。

执行 `make setup` 安装锁定工程工具，执行 `make check` 检查模块依赖、协议场景、文档、Go race、vet、构建和工作流。正式检查使用 `GOWORK=off`，真实账号不进入自动测试。

仓库为 public，默认分支 develop 提供当前实现，短期分支经 PR 合入 develop。发行与生产部署单独授权。接口范围和验证状态见[文档导航](docs/README.md)。代码与文档使用 [AGPL-3.0-only](LICENSE) 许可。
