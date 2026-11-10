---
type: guide
status: Accepted
updated: 2026-10-25
---

# BHpan 使用与验证

## 本地检查

使用架构仓库声明的 Go、Node.js 和 pnpm 版本。执行 `make setup` 与 `make check`，运行独立模块构建、Go race、vet、接口来源摘要、场景映射、文档和工作流检查。自动测试只使用本地 TLS 服务与合成数据，不连接真实网盘。

## 服务端调用

本仓库公开提供源码，拉取本模块不需要 GitHub 登录或专用 `GOPRIVATE` 配置。实际访问网盘仍需由调用方提供获授权的账号，凭据不进入 go.mod。

BHpan 位于独立 Go module 根包。正式消费者在 go.mod 固定本仓已验证版本或提交，构建时设置 `GOWORK=off`。本地可以通过 go.work 引入任务工作树，正式依赖不保存本机 replace 路径。

以 `github.com/StuHelper/stuhelper-storage-bhpan` 导入包。调用 `New` 创建独立客户端，根据账号类型选择 `Login` 或 `LoginLocal`，退出时调用 `Close`。各请求传入具有截止时间的 context，不把一个客户端复用于多个同时登录的账号。

调用 `Libraries` 选择文档库，再执行所需文件操作。普通上传使用 `BeginUpload`、`WriteUpload`、`FinishUpload`；分片上传使用 `MultipartOptions`、`BeginMultipart`、`PartGrants`、`WritePart`、`CompleteMultipart`。调用方必须保留成功创建的文件标识，以便处理后续失败。

`Delete` 将文件放入回收站。先通过 `RecycleBin` 获取对应回收站条目，再以其标识调用 `Restore` 或 `Purge`。业务程序应保存准确的对象归属，不依赖文件名进行日常删除。

## 真实账号验证

`go run ./cmd/bhpan-probe` 从标准输入读取一个 JSON 对象。`Accounts` 最多包含两个账号，每项包含 `Username`、`Password` 和 `Mode`；Mode 为 `sso` 或 `local`。不要把凭据放入命令参数、源码、普通文件或终端历史。

默认只验证登录、文档库、容量和根目录读取。`Files=true` 会创建随机命名的临时目录，验证普通上传下载、重命名、复制、移动、回收站恢复和彻底删除。程序只清理该次生成的目录，不删除既有文件。

在 Files 模式下，`Multipart=true` 增加两片上传与内容校验，最大测试文件约 32 MiB；`Shares=true` 增加一小时有效、随机密码保护的测试分享，并验证匿名下载后撤销。测试数据只包含固定说明和随机字节。

程序只输出账号序号、各阶段结果和固定错误。退出前清理临时目录与分享；失败返回非零状态，并标明清理结果。进程被强制终止或网络中断可能阻止清理，此时应由受控任务按已创建对象核查，不执行全账号批量删除。

## 能力边界

图形验证、短信或动态密码、风险确认续接和账号密码管理未实现。遇到交互验证返回 `ErrChallenge`，不要自动重试密码。库不执行后台续期，也不把供应商失败转成空目录或删除事件。

配置中的 Transport 供服务端受控网络与测试使用，不接受前端用户指定。真实测试账号只用于当前授权范围；生产接入、贡献业务、持久化凭据与正式 backend 装配按各自任务实施。
