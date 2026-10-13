# MyClash → Egern

根据 [AIsouler/MyClash 的 mihomo 全量配置](https://github.com/AIsouler/MyClash/blob/main/Config/mihomoConfig.yaml)转换。原作者 AIsouler；配置和规则快照读取于 2026-10-13（Asia/Taipei）。

## 导入

配置地址：<https://raw.githubusercontent.com/Yoobohl/EgernTest/main/Profile.yaml>

下载 `Profile.yaml`，在开头的 `机场订阅` 组填写订阅，再导入 Egern：

```yaml
urls: &subscriptions
  - "你的机场订阅地址"
```

多个订阅继续添加列表项。保留 `&subscriptions` 和地区手动组中的 `*subscriptions`，只需填写一次。不要将私人订阅地址提交到公开仓库。订阅须为 Egern 支持的格式；官方明确展示的是 Egern 原生 `proxies:` YAML，不能保证直接接受机场提供的 mihomo YAML，必要时使用机场的 Egern 专用订阅。

当前模板的订阅列表为空。Profile 约 32 KB，规则集和模块会从本仓库自动下载，不需一起导入 iOS。

首次加载后确认选择：FCM 为直连；AI / PayPal / EHentai 为美国；TikTok / Crypto 为日本；Patreon 为香港。相应策略已放在列表首位，但首次是否自动选中需在设备上确认。

后续增加订阅建议修改上述 YAML 列表。只通过界面向 `机场订阅` 添加订阅，不保证同步修改各地区手动组分别挂载的 URL。

## 文件与转换

| 文件 | 作用 |
| --- | --- |
| `Profile.yaml` | 全局参数、策略组、DNS、规则集和模块的远程引用，以及原有少量自定义规则。 |
| `rulesets/*.yaml` | 全部 47 个原规则集的 Egern 原生版本，另加 CN IP 的 no-resolve 版本，共 48 个文件。 |
| `modules/real-ip-domains.yaml` | 用官方模块字段 `real_ip_domains` 保存原 Fake-IP 排除集合。 |
| `source/` | 原 mihomo 配置、文本规则快照、国内补充 MRS 和来源/数量清单。 |
| `scripts/` | 从已保存的快照重建配置及验证转换；不会联网更新快照。 |
| `licenses/` | 原配置及规则项目的许可。 |

原 `payload` 中的精确域名转成 `domain_set`，`+.域名` 转成 `domain_suffix_set`，少量单标签通配符与仅匹配子域的模式转成 `domain_regex_set`。IPv4/IPv6 分别转成 `ip_cidr_set` / `ip_cidr6_set`，**不使用 mihomo 的 MRS 或 payload 格式，也不把远程规则内容展开到 Profile**。

IP 规则的 `no_resolve` 放在规则集文件顶层。`cn_ip.yaml` 用于末尾直连规则，允许解析；`cn_ip-no-resolve.yaml` 用于 UDP 443 逻辑规则，不触发解析。

路由通过 `rule_set` 引用；DNS 的 private / douyin / cn 通过 `proxy_rule_set` 引用相同规则文件。原 UDP 443 拒绝规则保留 `and` / `not` / `or` 结构，子条件引用国内补充及 CN IP 规则集。原规则顺序保留；最前面增加 DNS 上游地址的显式路由，替代 mihomo DNS URL 的 `#DIRECT` / `#默认代理` 后缀。

测速地址仅设置全局 `proxy_latency_test_url` / `direct_latency_test_url`。组内只保留测速间隔、超时、容差等必要参数。

规则集、模块和订阅均设置 86400 秒更新。规则更新表示 Egern 重新读取本仓库文件；**不会自动把上游 mihomo/MRS 的新内容转换并提交到本仓库**。更新上游快照后重运行转换、检查并提交才会改变托管内容。

## 差异

| 原功能 | Egern 处理 |
| --- | --- |
| HTTP/SOCKS 混合端口 7890 | HTTP 7890 / SOCKS 7891，保留允许局域网连接。 |
| 五种 direct 节点及 IP 版本偏好 | 合并为 `直连 → DIRECT`；文档没有 direct 节点或 DIRECT 的对应 IP 偏好字段。 |
| sticky-sessions 负载均衡 | 使用 Egern `hash`，并不完全等同原粘性会话算法。 |
| default-selected | 把目标策略放在首位，导入后确认实际选中项。 |
| AdBlock 的 REJECT-DROP / PASS | 只保留文档支持的 REJECT。关闭拦截时禁用或移除对应广告规则。 |
| empty-fallback、失败次数、懒测速 | 无官方对应字段，省略；不能保证无节点时与原配置相同。 |
| 订阅名称前缀、类型排除、AGE 解密 | 无文档化一一对应字段，只保留名称过滤；多订阅应避免节点同名，并提供 Egern 可读取的订阅。 |
| proxy-server-nameserver | 不硬套到 Egern 的 `proxy_nameservers`：后者用于代理目标域名解析并绕过全部 Forward。当前不设置，让解析共享 Forward，不能独立复现原节点服务器域名专用 DNS 池。 |
| Bootstrap 中加密 DNS | Egern Bootstrap 只支持普通 UDP DNS，保留原 114.114.114.114。 |
| direct-nameserver-follow-policy | 用原域名集合分流近似，手动改为直连不会同步切换 DNS。Egern 代理侧 DNS 上游连接强制直连，行为见官方 DNS 文档。 |
| Fake-IP 排除通配符 | `+.域名` 展开为域名本身及 `*.域名`。少量单标签通配符在 real_ip_domains 的 glob 中可能匹配更广。 |
| 7 条 Emby PROCESS-NAME | 删除，保留 Emby 域名规则。列表见 `source/manifest.json`。 |
| TUN 内核参数、控制 API、Zashboard、NTP、连接并发、keep-alive、ARC 缓存、系统 hosts、Fake-IP 地址段和持久化 | 省略未文档化的对应字段，使用 Egern 本身的 VPN 和界面。 |

## 校验和重建

已通过 YAML 解析、48 个原生规则集字段/IP 检查、212,727 条源数据逐项转换核对、远程引用对应本地文件检查、策略引用与循环检查、PCRE2 通配符和地区过滤检查；转换与校验脚本通过 Ruff 和 ty。

尚未在 iOS Egern 内实际导入与联网验证。

```powershell
$env:UV_CACHE_DIR = Join-Path $PWD '.cache/uv'
uv run --with pyyaml --with zstandard python scripts/convert.py
uv run --with pyyaml --with zstandard --with pcre2 python scripts/validate.py
```

转换脚本支持 `--raw-base` 修改托管仓库前缀，默认 `https://raw.githubusercontent.com/Yoobohl/EgernTest/main`。

## 官方依据

- [全局字段](https://egernapp.com/docs/configuration/example/)
- [策略组](https://egernapp.com/docs/configuration/policy_groups/)
- [规则与原生规则集格式](https://egernapp.com/docs/configuration/rules/)
- [DNS](https://egernapp.com/docs/configuration/dns/)
- [模块与 real_ip_domains](https://egernapp.com/docs/configuration/modules/)
- [Mihomo MRS 读取](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/provider/mrs_reader.go)及[域名二进制布局](https://github.com/MetaCubeX/mihomo/blob/Meta/component/trie/domain_set_bin.go)

转换以 egern-docs 技能随附官方文档为依据。规则源 URL 和数量见 `source/manifest.json`。保留 MyClash MIT 许可及 bett-rules / 666OS-rules GPLv3 许可，见 `licenses/`；原项目的许可和署名适用于其内容。
