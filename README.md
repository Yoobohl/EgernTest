# MyClash → Egern

根据 [AIsouler/MyClash 的 mihomo 全量配置](https://github.com/AIsouler/MyClash/blob/main/Config/mihomoConfig.yaml)转换。原作者 AIsouler；配置和规则快照读取于 2026-10-13（Asia/Taipei）。47 个基础规则集由实际 MRS 经官方 mihomo v1.19.32 `DumpMrs` 导出，另合入 Yoobohl/proxy-profiles 的 NSFW / Web3 classical 规则。

配置、规则集、Real IP 模块与 PNG 图标统一托管在 [Yoobohl/EgernTest](https://github.com/Yoobohl/EgernTest)。

## 导入

配置地址：<https://cdn.jsdmirror.com/gh/Yoobohl/EgernTest@main/Profile.yaml>

下载 `Profile.yaml`，在开头的 `全部节点` 组填写订阅，再导入 Egern：

```yaml
urls:
  - "你的机场订阅地址"
```

多个订阅继续添加列表项，只需在 `全部节点` 填写一次。地区及倍率策略组设置 `flatten: true`，通过 `policies: [全部节点]` 引用该组并筛选节点。不要将私人订阅地址提交到公开仓库。订阅须为 Egern 支持的格式；官方明确展示的是 Egern 原生 `proxies:` YAML，不能保证直接接受机场提供的 mihomo YAML，必要时使用机场的 Egern 专用订阅。

当前模板的订阅列表为空。Profile 约 32 KB，规则集和模块会从本仓库自动下载，不需一起导入 iOS。

首次加载后确认选择：FCM 为直连；AI / PayPal / EHentai 为美国；TikTok / Crypto 为日本；Patreon 为香港。相应策略已放在列表首位，但首次是否自动选中需在设备上确认。

后续增加订阅或自定义节点统一添加到 `全部节点`，其他节点筛选组通过展平获取节点，不再分别配置订阅 URL。

保留全局 `自动选择`；香港、日本、美国、新加坡、台湾、低倍率节点、高倍率节点和其他节点组直接选择筛选后的订阅节点，不再包含独立的自动选择子组。

## 文件与转换

| 文件 | 作用 |
| --- | --- |
| `Profile.yaml` | 全局参数、策略组、DNS、规则集和模块的远程引用，以及原有少量自定义规则。 |
| `rulesets/*.yaml` | 47 个原规则集（Crypto 已与 Web3 合并）、CN IP 的 no-resolve 版本和 NSFW，共 49 个文件。 |
| `modules/real-ip-domains.yaml` | 用官方模块字段 `real_ip_domains` 保存原 Fake-IP 排除集合。 |
| `modules/drcom-egern/` | 可独立安装的 Dr.COM 校园网流量小组件模块及其 CDN 脚本。 |
| `icons/*.png` | 36 个 256×256、8-bit RGBA 图标，包含真实透明像素；Profile 只引用 PNG。 |
| `source/icons/` | 原始 SVG、来源和 SVG/PNG 校验值，供重新渲染与核对。 |
| `source/mrs/` | 全部 47 个实际 MRS 文件。 |
| `source/text/` | 官方 mihomo v1.19.32 从 MRS 导出的 47 个文本文件。 |
| `source/classical/` | NSFW 与 Web3 的原始 classical 文件快照。 |
| `source/manifest.json` | MRS 来源、行为、插入数量、导出数量和 SHA256。 |
| `source/mrs-tool.json` | 官方转换器版本、下载地址及校验值。 |
| `source/rule-sources.json` | 上一版 YAML/文本快照，仅供比对，不再参与转换。 |
| `scripts/` | 从已保存的快照重建配置及验证转换；不会联网更新快照。 |
| `licenses/` | 原配置及规则项目的许可。 |

MRS 导出文本中的精确域名转成 `domain_set`，`+.域名` 转成 `domain_suffix_set`，少量单标签通配符与仅匹配子域的模式转成 `domain_regex_set`。IPv4/IPv6 分别转成 `ip_cidr_set` / `ip_cidr6_set`。Egern 输出不含 MRS 或 mihomo `payload`，Profile 只保留远程集合引用。

源码 `ConvertToMrs` 在输入格式为 `MrsRule` 时调用 `DumpMrs` 导出文本。域名策略会合并精确域名与同名后缀项为 `+.域名`；IP 策略会按 IP 范围导出规范 CIDR。本项目直接调用固定版本官方二进制执行这一流程，不在 Python 中重写 trie 或 IP 范围二进制解码。

```text
实际 MRS → 官方 DumpMrs 文本 → Egern 原生规则集 YAML
```

47 个 MRS 的插入数量总计 212,727，规范化后导出 212,558 个条目。导出数量变化不代表丢弃匹配范围；全部文本均通过官方转换器往返核对。

IP 规则的 `no_resolve` 放在规则集文件顶层。`cn_ip.yaml` 用于末尾直连规则，允许解析；`cn_ip-no-resolve.yaml` 用于 UDP 443 逻辑规则，不触发解析。

路由通过 `rule_set` 引用；DNS 的 private / douyin / cn 通过 `proxy_rule_set` 引用相同规则文件。原 UDP 443 拒绝规则保留 `and` / `not` / `or` 结构，子条件引用国内补充及 CN IP 规则集。保留私网、国内直连、QUIC、广告规则的优先级；NSFW 和合并后的 Crypto 放在广告规则之后、其他代理服务及兜底规则之前。最前面增加 DNS 上游地址的显式路由，替代 mihomo DNS URL 的 `#DIRECT` / `#默认代理` 后缀。

## NSFW 与 Web3 补充规则

- [nsfw.list](https://github.com/Yoobohl/proxy-profiles/blob/main/rules/classical/nsfw.list) 转为 `rulesets/nsfw.yaml`，包含 60 条规则。新增 `NSFW` 策略组，首项为 `默认代理`。
- [web3.list](https://github.com/Yoobohl/proxy-profiles/blob/main/rules/classical/web3.list) 的 417 条可转换域名规则与原加密货币规则的 235 条合并。删除 222 条相同类型/值的重复项，以及 4 条已由父域名后缀覆盖的项，最终 `rulesets/cryptocurrency.yaml` 包含 426 条，继续使用 `Crypto` 策略组。Profile 仅引用一次合并后的规则集。
- classical 中的 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 分别转换为 `domain_set`、`domain_suffix_set`、`domain_keyword_set`，去除字段周围空白。
- Web3 的 `Binance.exe`、`Huobi.exe`、`OKX.exe` 三条进程规则没有 Egern 文档对应字段，未迁移。来源校验值、跳过记录与去重统计在 `source/manifest.json` 的 `supplemental_sets` 中。
- 转换脚本先从原 MRS 重建基础集合，再合并 classical 快照，重复运行不会重复添加条目。已核对合并前后的域名匹配并集，包含大小写、子域名和后缀边界样例。

测速地址仅设置全局 `proxy_latency_test_url` / `direct_latency_test_url`。组内只保留测速间隔、超时、容差等必要参数。

图标由原 SVG 使用 `@resvg/resvg-js@2.6.2` 渲染为 PNG，透明画布不填充底色。全部 PNG 为 8-bit RGBA，Alpha 最小值 0、最大值 255，图形颜色和原有背景形状保持原样。Profile 不再引用 SVG；NSFW 使用 [nsfw_diamond.svg](https://github.com/Yoobohl/proxy-profiles/blob/main/icons/nsfw_diamond.svg) 转换出的 `icons/nsfw_diamond.png`。

全局设置 `default_proxy_group: 全部节点` 和 `default_subscription_group: 全部节点`，添加节点和订阅时统一使用该组。

国内 DNS 上游使用阿里 `https://dns.alidns.com/dns-query` 和腾讯 `https://doh.pub/dns-query`，通过 DIRECT 连接。Bootstrap 使用 `223.5.5.5` / `119.29.29.29`；hosts 固定阿里 DNS 地址为 `223.5.5.5` / `223.6.6.6`，腾讯为 `1.12.12.12` / `120.53.53.53`。其他 DNS 分流和国外 DoH 保留。

Dr.COM 小组件可从[独立模块地址](https://cdn.jsdmirror.com/gh/Yoobohl/EgernTest@main/modules/drcom-egern/drcom.module.yaml)安装，安装说明见 `modules/drcom-egern/README.md`。

开启兼容路由 `compat_route: true`。全局不指定 `block_quic`，使用默认行为；不设置 HTTP / SOCKS 端口，使用 Egern 默认端口。

规则集、模块和订阅均设置 86400 秒更新。规则更新表示 Egern 重新读取本仓库文件；**不会自动把上游 mihomo/MRS 的新内容转换并提交到本仓库**。更新上游快照后重运行转换、检查并提交才会改变托管内容。

## 差异

| 原功能 | Egern 处理 |
| --- | --- |
| HTTP/SOCKS 混合端口 7890 | 不指定端口，使用 Egern 默认端口；保留允许局域网连接。 |
| 五种 direct 节点及 IP 版本偏好 | 合并为 `直连 → DIRECT`；文档没有 direct 节点或 DIRECT 的对应 IP 偏好字段。 |
| sticky-sessions 负载均衡 | 使用 Egern `hash`，并不完全等同原粘性会话算法。 |
| default-selected | 把目标策略放在首位，导入后确认实际选中项。 |
| AdBlock 的 REJECT-DROP / PASS | 只保留文档支持的 REJECT。关闭拦截时禁用或移除对应广告规则。 |
| empty-fallback、失败次数、懒测速 | 无官方对应字段，省略；不能保证无节点时与原配置相同。 |
| 订阅名称前缀、类型排除、AGE 解密 | 无文档化一一对应字段，只保留名称过滤；多订阅应避免节点同名，并提供 Egern 可读取的订阅。 |
| proxy-server-nameserver | 不硬套到 Egern 的 `proxy_nameservers`：后者用于代理目标域名解析并绕过全部 Forward。当前不设置，让解析共享 Forward，不能独立复现原节点服务器域名专用 DNS 池。 |
| Bootstrap 中加密 DNS | Egern Bootstrap 只支持普通 UDP DNS；当前使用 223.5.5.5 / 119.29.29.29。 |
| direct-nameserver-follow-policy | 用原域名集合分流近似，手动改为直连不会同步切换 DNS。Egern 代理侧 DNS 上游连接强制直连，行为见官方 DNS 文档。 |
| Fake-IP 排除通配符 | `+.域名` 展开为域名本身及 `*.域名`。少量单标签通配符在 real_ip_domains 的 glob 中可能匹配更广。 |
| 7 条 Emby PROCESS-NAME | 删除，保留 Emby 域名规则。列表见 `source/manifest.json`。 |
| TUN 内核参数、控制 API、Zashboard、NTP、连接并发、keep-alive、ARC 缓存、系统 hosts、Fake-IP 地址段和持久化 | 省略未文档化的对应字段，使用 Egern 本身的 VPN 和界面。 |

## 校验和重建

已通过 YAML 解析、49 个原生规则集字段/IP 检查、212,558 个官方导出条目的匹配覆盖核对、MRS/文本 SHA256 检查、47 次官方“文本 → MRS → 文本”往返核对、NSFW/Web3 合并语义检查、PNG 格式/尺寸/Alpha/校验值检查、远程引用对应本地文件检查、策略引用与循环检查、PCRE2 通配符和地区过滤检查；转换与校验脚本通过 Ruff 和 ty。

尚未在 iOS Egern 内实际导入与联网验证。

先从 [mihomo 官方 v1.19.32 发布页](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.32)下载 `mihomo-windows-amd64-v1-v1.19.32.zip`，解压到 `.cache/mihomo-v1.19.32/`。ZIP SHA256 必须为 `00549b347d8e124600e46cac67d59293358454f465e9d86d2511567da56b7029`；本次已经校验并准备好。二进制不包含在转换结果压缩包中。

```powershell
$env:UV_CACHE_DIR = Join-Path $PWD '.cache/uv'
uv run --with pyyaml --with zstandard python scripts/convert.py
uv run --with pyyaml --with zstandard --with pcre2 --with pillow python scripts/validate.py
```

转换脚本支持 `--raw-base` 修改托管前缀，默认 `https://cdn.jsdmirror.com/gh/Yoobohl/EgernTest@main`；支持 `--mihomo` 指定其他位置的同版本官方可执行文件。

单个 MRS 可使用通用转换入口，行为自动从 MRS 头读取：

```powershell
uv run --with pyyaml --with zstandard python scripts/mrs_to_egern.py source/mrs/google.mrs rulesets/google.yaml --text-output source/text/google.txt
uv run --with pyyaml --with zstandard python scripts/mrs_to_egern.py source/mrs/google_ip.mrs rulesets/google_ip.yaml --text-output source/text/google_ip.txt --no-resolve
```

支持 `--behavior domain` / `--behavior ipcidr` 强制校验类型。类型不符、损坏或空 MRS、转换器版本不符会报错；不会回退读取同名 YAML 或文本替代源文件。

重建 PNG 图标：

```powershell
New-Item -ItemType Directory -Path .cache/icon-renderer -Force
pnpm --dir .cache/icon-renderer add @resvg/resvg-js@2.6.2 --store-dir .cache/pnpm-store
node scripts/render_icons.cjs
```

NSFW 图标中的文字使用 Windows 的 `Arial Black` 字体文件；其他环境可设置 `RESVG_FONT` 指向对应字体。字体不包含在仓库或压缩包中。

## 官方依据

- [全局字段](https://egernapp.com/docs/configuration/example/)
- [策略组](https://egernapp.com/docs/configuration/policy_groups/)
- [规则与原生规则集格式](https://egernapp.com/docs/configuration/rules/)
- [DNS](https://egernapp.com/docs/configuration/dns/)
- [模块与 real_ip_domains](https://egernapp.com/docs/configuration/modules/)
- [v1.19.32 MRS 转换器](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/rules/provider/mrs_converter.go)、[域名导出策略](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/rules/provider/domain_strategy.go)及[IP 导出策略](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/rules/provider/ipcidr_strategy.go)

转换以 egern-docs 技能随附官方文档为依据。规则源 URL 和数量见 `source/manifest.json`。保留 MyClash MIT 许可及 bett-rules / 666OS-rules GPLv3 许可，见 `licenses/`；原项目的许可和署名适用于其内容。
