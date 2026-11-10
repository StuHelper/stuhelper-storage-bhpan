---
type: index
status: Accepted
updated: 2026-10-25
---

# 文档写作与维护

本仓库使用 design、spec、development、guide、adr 五类文档。分类、状态、模板和检查遵循[公共文档约定](https://github.com/StuHelper/stuhelper-next/blob/develop/docs/authoring.md)。本仓库维护可公开的存储协议和接入说明，真实配置、凭据与个人数据保存在获准的运行环境。

文档直接描述当前行为、实现与剩余任务。规则变化时替换原文并修复引用，历史内容由 Git 保存。用自然、具体的中文说明对象、条件、动作和结果，长期文档使用相关写作技能。

每份文档包含 type、status、updated 元信息。status 表示文档确认状态，正文单独说明实现和验证范围。新增主题从所属分类模板开始，并更新文档导航。

`make setup` 安装锁定依赖，`make check` 执行仓库、文档和工具检查。真实业务、身份与生产结果由对应实施任务分别验收。
