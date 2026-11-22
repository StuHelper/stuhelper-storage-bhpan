---
type: development
status: Accepted
updated: 2026-11-21
---

# BHpan 实施状态

## 当前实现

独立 Go 适配库支持 SSO 与云盘本地账号登录、显式会话续期、交互挑战分类、稳定账号和文件标识、个人文档库、容量、文件和回收站。传输覆盖普通与分片上传、秒传、归档和分段下载，以及分享管理、匿名预检和解析。

backend 已通过 storage 的 BHpan 驱动装配本库。当前 develop 支持同源根相对回调和同源中间跳转。storage 驱动采集云盘原始配额，业务层独立管理写入预算和贡献申报。职责见[接入设计](../design/storage-adapter.md)。

## 验证结果

当前接口快照记录 35 个观测操作，协议夹具校验请求和响应。模块清单登记 BH-01 至 BH-16。develop 的 CI 通过依赖、协议场景、文档、Go race、vet、构建和工作流检查。[BHpan checks](https://github.com/StuHelper/stuhelper-storage-bhpan/actions/runs/44903633584)

本地登录回调回归使用 TLS 夹具覆盖 19 个子用例。接受根相对地址、同源绝对地址及同源中间跳转，核对认证只提交一次、有效会话能读取身份与容量，以及拒绝的外部目标未获请求。[回归测试](https://github.com/StuHelper/stuhelper-storage-bhpan/blob/8695e00e68688eb532d414aff776f69b2b1d1d01/local_auth_redirect_test.go)

获准账号曾通过 SSO 和云盘本地登录，完成文档库、容量读取、普通与分片传输、内容摘要核对、文件生命周期和密码分享。短时续期验证覆盖登录后和闲置十二分钟后的刷新与读取。

StuHelper v0.1.31 的正式组合使用 BHpan v0.1.1。根相对回调修复已进入 develop。[正式组合](https://github.com/StuHelper/stuhelper/blob/v0.1.31/workspace.lock.json)

## 待验证

根相对回调修复与云盘容量采样需在采用该源码组合的环境用获准账号复验。供应商会话的实际到期时间、跨到期续期及重启后的恢复仍待实测。

秒传、归档下载、分享历史、共享目录遍历已由隔离夹具覆盖。真实账号验证和分享历史分页参数仍待核对。探针入口及清理范围见[使用指南](../guide/bhpan.md)。
