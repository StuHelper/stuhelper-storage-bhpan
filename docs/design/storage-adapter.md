---
type: design
status: Accepted
updated: 2026-11-21
---

# 独立存储适配与业务接入

## 职责与数据归属

BHpan 封装北航云盘的登录、会话、容量、文件和传输协议，维护独立 Go module、发行版本、协议快照和测试。运行请求访问云盘，选择 SSO 登录时还访问北航 SSO。campus-adapters 独立维护学校认证与教务数据接入。

模块只依赖 Go 标准库。`module.json` 将本模块登记为 `library`，`required` 与 `optional` 为空，`adapters` 登记 `bhpan`。Node.js、pnpm 和工程工具用于开发检查。

调用方为每个账号创建客户端，客户端在进程内保存会话，任务结束时调用 `Close`。凭据保管、账号绑定、授权和重试由调用方负责。库直接链接到使用方进程，通过 Go 接口调用。

## 业务装配

backend 装配客户端和 storage 的 BHpan 驱动。驱动在个人文档库内管理平台目录，将供应商文件位置、修订和错误转换成 storage 的接口结果。物理副本、容量样本和平台写入预算归 storage 管理。

storage-contribution 管理申报、期限及退出。media 管理逻辑文件、版本、校验、上传会话和业务引用，通过 storage 公开接口存取副本。resources 等所属业务模块负责资料的访问资格、审核和发布。

## 容量采样

`Quota` 读取整个云盘账号的原始分配量和已用量。`Available` 返回剩余字节数，超配额时为零。storage 驱动在成功验证实例时将原始值交给 storage 持久化。上层采样时效、预占、个人保留空间和贡献上限由 storage 与 storage-contribution 管理。接口失败语义见[适配规格](../spec/bhpan.md)。

## 传输与版本

传输接收 `io.Reader` 和 `io.Writer`，操作接收 context。调用方按返回结果处理超时、取消和部分传输，并依据业务规则恢复或重试。对象请求隔离个人会话与临时授权。

正式消费者使用 go.mod 固定已验证版本或提交，设置 `GOWORK=off` 构建。本地可通过 go.work 或临时 replace 接入任务工作树。调用方式、配置与验证见[使用指南](../guide/bhpan.md)。
