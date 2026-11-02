---
name: egern-docs
description: >
  Egern iOS 代理工具的官方配置文档参考。当用户要求编写、修改、解释、检查或优化
  Egern 配置，涉及 DNS、代理节点、策略组、规则集、脚本或 YAML 格式时，使用本 Skill。
---

# Egern Documentation Skill

## 工作目标

根据随附的 Egern 官方文档帮助用户完成配置工作。优先以本 Skill 内的文档为依据，不要直接套用 Mihomo、Surge 或 Loon 的配置语法。

## 文档查找流程

1. 首先查看下方文档导航，根据问题确定相关主题。所有路径相对于本 `SKILL.md` 所在目录。
2. 只读取对应参考文档；涉及多个配置模块时，按依赖补充相关文档，不要默认读取整个目录。
3. 对较长文档，先搜索字段、协议名或章节标题，再读取对应章节及其公共字段、约束和示例。
4. 根据文档编写或检查配置。检查跨模块引用时，核对节点、策略组、DNS 上游组和规则引用的名称。
5. 如果文档未说明某个功能，不要猜测其支持情况。需要确认新版行为时，查看参考文档的 `source` 官方页面，并区分在线资料与随附快照。

## 文档导航

- DNS：[en/docs/configuration/dns.md](en/docs/configuration/dns.md)
- 代理节点与协议：[en/docs/configuration/proxies.md](en/docs/configuration/proxies.md)
- 代理策略组与订阅：[en/docs/configuration/policy_groups.md](en/docs/configuration/policy_groups.md)
- 分流规则与规则集：[en/docs/configuration/rules.md](en/docs/configuration/rules.md)
- 脚本配置：[en/docs/configuration/scriptings.md](en/docs/configuration/scriptings.md)；脚本实现：[en/docs/javascript-api.md](en/docs/javascript-api.md)
- 官方完整配置示例与全局字段：[en/docs/configuration/example.md](en/docs/configuration/example.md)
- URL 重写：[en/docs/configuration/url_rewrites.md](en/docs/configuration/url_rewrites.md)
- HTTP 头重写：[en/docs/configuration/header_rewrites.md](en/docs/configuration/header_rewrites.md)
- HTTP 正文重写：[en/docs/configuration/body_rewrites.md](en/docs/configuration/body_rewrites.md)
- HTTP 捕获：[en/docs/configuration/http_captures.md](en/docs/configuration/http_captures.md)
- 环境变量：[en/docs/configuration/env.md](en/docs/configuration/env.md)
- 模块与参数替换：[en/docs/configuration/modules.md](en/docs/configuration/modules.md)
- 小组件与 Widget DSL：[en/docs/configuration/widgets.md](en/docs/configuration/widgets.md)
- 产品概览：[en/docs/intro.md](en/docs/intro.md)
- 常见问题：[en/docs/faq.md](en/docs/faq.md)
- URL Scheme：[en/docs/url-scheme.md](en/docs/url-scheme.md)
- 代理使用教程：[en/docs/example/proxy.md](en/docs/example/proxy.md)
- HTTP 抓包教程：[en/docs/example/http-traffic-sniffer.md](en/docs/example/http-traffic-sniffer.md)

从零编写配置时先读取完整配置示例，再按需读取模块文档；编写脚本时结合脚本配置与 JavaScript API；处理模块中的脚本或小组件时补读环境变量文档。教程图片位于 `en/assets/`，按文档内的相对链接查看。

## 回答要求

- 优先使用官方文档中的配置字段；配置示例使用 Egern YAML，脚本示例使用文档定义的 JavaScript API。
- 明确示例是完整配置还是局部片段；修改现有配置时保留无关配置和用户已有值。
- 区分官方已证实的行为、基于文档的推断与尚未确认的支持情况。文档不一致时指出冲突，不擅自合并为确定结论。
- 说明对应参考文档的路径或章节；使用在线补充资料时附官方来源链接。
- 不要未经验证就使用其他代理软件的语法。YAML 能解析不代表 Egern 支持其字段，未进行实际运行验证时不声称配置已在 Egern 中通过测试。
