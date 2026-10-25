# stuhelper-storage-bhpan 工程约定

* 本仓库为 public，独立维护 BHpan 存储协议适配、契约、测试和版本。
* 模块不依赖 campus-adapters、media、backend 或旧 StuHelper。业务授权、凭据持久化、存储贡献和任务调度由使用方负责。
* 凭据与个人数据不写入源码、日志、文档或测试夹具。真实账号验证按任务授权进行，只清理本任务创建的资源。
* 使用主仓库声明的工具链。正式构建与检查设置 `GOWORK=off`，共享检查使用锁定版本的工程工具。
* 短期分支从最新 origin/develop 创建，经 PR squash 合入 develop。首次引导建立 main/develop；正式发布使用 develop 到 main 的 merge commit。tag、镜像与生产部署按 owner 授权执行。
* 任务工作树位于 Next 的 `workspace/worktrees/<任务>/<仓库名>`，保留其他任务改动。Docker 测试使用任务专属资源并按范围清理。
* 普通 CI 使用 GitHub `ubuntu-26.04`；Docker/OCI 任务使用自建 runner。Actions 使用明确版本 tag，不启用共享缓存或 artifact。
* 接口、关键行为与失败路径同步维护针对性测试，在 module.json 的 scenario_tests 登记实际测试函数。
* 文档使用 design/spec/development/guide/adr 分类，保持状态、日期、导航与当前实现一致。正文单段最多 200 个可见字符，长期文档遵循相关写作技能。
* 回复先给结果，再说明检查、真实账号验证、发行和部署各自状态。

完整工程规则见[Next 工程约定](https://github.com/StuHelper/stuhelper-next/blob/develop/AGENTS.md)和[文档约定](https://github.com/StuHelper/stuhelper-next/blob/develop/docs/authoring.md)。
