---
type: guide
status: Accepted
updated: 2026-11-21
---

# BHpan 使用与验证

## 本地检查

使用架构仓库声明的 Go、Node.js 和 pnpm 版本。执行 `make setup` 与 `make check`，运行独立模块构建、Go race、vet、接口来源摘要、场景映射、文档和工作流检查。自动测试只使用本地 TLS 服务与合成数据，不连接真实云盘。

## 服务端调用

本仓库公开提供源码，拉取本模块不需要 GitHub 登录或专用 `GOPRIVATE` 配置。实际访问云盘仍需由调用方提供获授权的账号，凭据不进入 go.mod。

BHpan 位于独立 Go module 根包。正式消费者在 go.mod 固定本仓已验证版本或提交，构建时设置 `GOWORK=off`。本地可以通过 go.work 引入任务工作树，正式依赖不保存本机 replace 路径。

以 `github.com/StuHelper/stuhelper-storage-bhpan` 导入包。调用 `New` 创建独立客户端，根据账号类型选择 `Login` 或 `LoginLocal`，退出时调用 `Close`。各请求传入具有截止时间的 context，不把一个客户端复用于多个同时登录的账号。

调用 `PersonalLibrary` 获取唯一的个人文档库，或使用 `Libraries` 读取全部文档库。使用 `Quota` 查询账号的原始空间，使用 `DirectorySize` 查询指定目录的占用。容量口径见[适配规格](../spec/bhpan.md)。

普通上传使用 `BeginUpload`、`WriteUpload`、`FinishUpload`（或 `FinishUploadResult`）；分片上传使用 `MultipartOptions`、`BeginMultipart`、`PartGrants`、`WritePart`、`CompleteMultipart`。调用方必须保留成功创建的文件标识。

按字节区间读取使用 `DownloadRange` 或 `DownloadSharedRange`，根据返回的 `DownloadInfo` 获取实际写入长度、对象总大小、内容类型与 ETag。

`Delete` 将文件放入回收站。先通过 `RecycleBin` 获取对应回收站条目，再以其标识调用 `Restore` 或 `Purge`。业务程序应保存准确的对象归属，不依赖文件名进行日常删除。

导入外链分享时，先用 `ParseShareURL` 从完整链接提取分享标识，再调用 `InspectShare` 判断分享是否有效及是否需要提取码，最后按需调用 `ResolveShare`。

## 真实账号验证

`go run ./cmd/bhpan-probe` 从标准输入读取一个 JSON 对象。`Accounts` 最多包含两个账号，每项包含 `Username`、`Password` 和 `Mode`；Mode 为 `sso` 或 `local`，留空时使用 SSO。不要把凭据放入命令参数、源码、普通文件或终端历史。

默认只验证登录、稳定身份、文档库、容量和个人文档库根目录读取。`Files=true` 仅在唯一的 `user_doc_lib` 个人文档库中创建随机命名的临时目录，验证普通上传下载、重命名、复制、移动、回收站恢复和彻底删除；缺少个人库时报错退出，不向部门库或群组库写入。程序只清理该次生成的目录，不删除既有文件。

在 Files 模式下，`Multipart=true` 增加两片上传与内容校验，最大测试文件约 32 MiB；`Shares=true` 增加一小时有效、随机密码保护的测试分享与分享历史核验，并在匿名下载后撤销。

在 Files 模式下还可开启 `FastUpload=true`、`Archive=true` 和 `SharedDirectory=true`，分别验证秒传预检与创建、批量归档下载以及共享文件夹子项遍历下载。测试数据只包含固定说明和随机字节。

程序输出账号序号、文档库数量、各阶段结果和脱敏错误。退出前清理临时目录与分享；失败返回非零状态，并标明清理结果。进程被强制终止或网络中断可能阻止清理，此时应由受控任务按已创建对象核查，不执行全账号批量删除。

## 能力边界

遇到交互验证时，通过 `ChallengeOf` 判断 `ErrChallenge` 对应的 `risk_confirm`、`captcha` 或 `mfa`。验证码和双因素需用户交互。调用方取得用户对异地登录风险的明确确认后，可调用 `LoginWithOptions` 并传入 `AcknowledgeRisk: true` 续接。

使用方需要定期续期时负责调度 `RefreshSession`。供应商失败按[适配规格](../spec/bhpan.md)返回，由使用方依据错误类别决定是否重试。

`Transport` 和 `LocalPublicKeyPEM` 由服务端维护，用于受控网络、测试或供应商公钥轮换。生产装配和凭据保管归 backend，数据归属见[接入设计](../design/storage-adapter.md)。
