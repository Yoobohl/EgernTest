"""Build an Egern profile and native rule sets from actual MRS snapshots.

Run: uv run --with pyyaml --with zstandard python scripts/convert.py
MRS is exported by the official mihomo v1.19.32 convert-ruleset command.
"""

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TypeVar, overload

import yaml
from classical_to_egern import add_supplemental_sets
from mrs_to_egern import (
    DEFAULT_MIHOMO,
    VERSION,
    check_version,
    dump_mrs,
    sha256,
    write_native,
)

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "source"
TEST_URL = "https://www.apple.com/library/test/success.html"
RAW_BASE = "https://cdn.jsdmirror.com/gh/Yoobohl/EgernTest@main"


# YAML/JSON 边界包含多种字段值，使用 Any 保留外部配置的扩展字段。
# 包装层始终只有一个键，如 {"select": {...}} 或 {"domain": {...}}。
ConfigFields = dict[str, Any]
ConfigEntry = dict[str, ConfigFields]
Value = TypeVar("Value")


class NoAliasDumper(yaml.SafeDumper):
    """直接输出重复值，避免 Egern 配置中出现 YAML 锚点与别名。"""

    def ignore_aliases(self, data: object) -> bool:
        """覆盖 PyYAML 别名判断，不依据对象是否被多处引用生成别名。"""
        return True


@overload
def policy_name(name: str) -> str: ...


@overload
def policy_name(name: None) -> None: ...


def policy_name(name: str | None) -> str | None:
    """统一旧直连组名称；缺失的默认选择继续保持 None。"""
    return "DIRECT" if name == "直连" else name


def rule(condition: ConfigEntry, policy: str) -> ConfigEntry:
    """为单键条件包装添加路由策略，不修改传入的条件字典。"""
    kind, value = next(iter(condition.items()))
    return {kind: {**value, "policy": policy_name(policy)}}


def build(raw_base: str = RAW_BASE, mihomo: Path = DEFAULT_MIHOMO) -> None:
    """从本地快照重建 Profile、规则集、Real IP 模块和来源清单。

    本函数会覆盖生成物，但不会联网更新上游快照。处理顺序为：
    官方 MRS 导出 → 合并补充规则 → 生成策略/DNS/路由 → 排序并写文件。
    路由列表顺序决定匹配优先级，字段排序阶段只调整字典键的顺序。
    """
    src: ConfigFields = yaml.safe_load(
        (SOURCE / "mihomoConfig.yaml").read_text(encoding="utf-8")
    )
    version_output = check_version(mihomo)
    downloads = {
        item["name"]: item
        for item in json.loads(
            (SOURCE / "mrs-downloads.json").read_text(encoding="utf-8")
        )
    }
    entries: dict[str, list[str]] = {}
    manifest: list[ConfigFields] = []
    for name, provider in src["rule-providers"].items():
        if name == "epicgames":
            continue
        mrs_path = SOURCE / "mrs" / (name + ".mrs")
        text_path = SOURCE / "text" / (name + ".txt")
        payload, behavior, mrs_count = dump_mrs(
            mrs_path, text_path, mihomo, provider["behavior"]
        )
        entries[name] = payload
        no_resolve = behavior == "ipcidr" and name not in {"cn_ip", "private_ip"}
        write_native(
            ROOT / "rulesets" / (name + ".yaml"), payload, behavior, no_resolve
        )
        manifest.append(
            {
                "name": name,
                "source": provider["url"],
                "fetch_url": downloads.get(name, {}).get("fetch_url", provider["url"]),
                "format": "mrs",
                "behavior": behavior,
                "count": len(payload),
                "mrs_insertion_count": mrs_count,
                "mrs_sha256": sha256(mrs_path),
                "text_sha256": sha256(text_path),
            }
        )
    # 国内 IP 另生成不触发 DNS 的副本，供 UDP/443 逻辑规则使用。
    write_native(
        ROOT / "rulesets/cn_ip-no-resolve.yaml", entries["cn_ip"], "ipcidr", True
    )
    supplemental: ConfigFields = add_supplemental_sets(ROOT)
    # Preserve user additions separately from the original MRS snapshot.
    douyin_extra_path = SOURCE / "douyin-extra.yaml"
    douyin_extra = yaml.safe_load(douyin_extra_path.read_text(encoding="utf-8"))
    douyin_path = ROOT / "rulesets/douyin.yaml"
    douyin = yaml.safe_load(douyin_path.read_text(encoding="utf-8"))
    original_count = sum(len(values) for values in douyin.values())
    for field, values in douyin_extra.items():
        if field not in {"domain_set", "domain_suffix_set", "domain_keyword_set"}:
            raise ValueError(f"Unsupported Douyin supplemental field: {field}")
        douyin[field] = sorted(set(douyin.get(field, [])) | set(values))
    douyin_path.write_text(
        yaml.safe_dump(douyin, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    supplemental["douyin"] = {
        "source": "source/douyin-extra.yaml",
        "source_sha256": sha256(douyin_extra_path),
        "original_mrs_text_count": original_count,
        "supported_input_count": sum(len(values) for values in douyin_extra.values()),
        "output_count": sum(len(values) for values in douyin.values()),
    }
    (SOURCE / "mrs-tool.json").write_text(
        json.dumps(
            {
                "version": VERSION,
                "version_output": version_output,
                "source": "https://github.com/MetaCubeX/mihomo/blob/v1.19.32/rules/provider/mrs_converter.go",
                "release_asset": "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-windows-amd64-v1-v1.19.32.zip",
                "release_sha256": "00549b347d8e124600e46cac67d59293358454f465e9d86d2511567da56b7029",
                "executable_sha256": sha256(mihomo),
                "command": "mihomo convert-ruleset <domain|ipcidr> mrs <source.mrs> <target.txt>",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    def reference(name: str) -> ConfigFields:
        """生成路由和 DNS 共用的远程集合引用，不在这里指定策略。"""
        return {"match": f"{raw_base}/rulesets/{name}.yaml", "update_interval": 86400}

    # Subscription is entered once, then flattened and filtered by consumer groups.
    uk_filter = (
        r"(🇬🇧|英国|伦敦|曼彻斯特|(?<![A-Za-z])(?:UK|GBR?)(?![A-Za-z])"
        r"|united\s*kingdom|great\s*britain|britain)"
    )
    exclude = src["global_exclude_filter"]["exclude-filter"].removeprefix("(?i)")
    groups: list[ConfigEntry] = [
        {
            "select": {
                "name": "全部节点",
                "urls": [],
                "update_interval": 86400,
                "filter": "(?i)^(?!.*" + exclude + ").*$",
                "hidden": True,
            }
        }
    ]
    for original in src["proxy-groups"]:
        if original["name"] in ("直连", "FCM") or original["name"].endswith(
            "-自动选择"
        ):
            continue
        kind = {"url-test": "auto_test", "load-balance": "load_balance"}.get(
            original["type"], original["type"]
        )
        group: dict[str, Any] = {"name": original["name"]}
        policies = [
            policy_name(name)
            for name in original.get("proxies", [])
            if not name.endswith("-自动选择")
        ]
        if original["name"] == "AdBlock":
            policies = ["REJECT", "DIRECT"]
        # No documented default-selected: preserve intended choice as first item.
        initial = policy_name(original.get("default-selected"))
        if initial in policies:
            policies.remove(initial)
            policies.insert(0, initial)
        if original.get("include-all"):
            policies = ["全部节点"]
            group["flatten"] = True
            if original.get("filter"):
                group["filter"] = original["filter"]
            if original.get("exclude-filter"):
                group["filter"] = (
                    "(?i)^(?!.*"
                    + original["exclude-filter"].removeprefix("(?i)")
                    + ").*$"
                )
        if group["name"] == "其他节点":
            group["filter"] = (
                "(?i)^(?!.*" + uk_filter + ")" + group["filter"].removeprefix("(?i)^")
            )
        if policies:
            group["policies"] = policies
        for field in ("icon", "hidden"):
            if field in original:
                group[field] = original[field]
        if group.get("icon", "").endswith(".svg"):
            group["icon"] = f"{raw_base}/icons/{Path(group['icon']).stem}.png"
        if group["name"] == "GitHub":
            group["icon"] = f"{raw_base}/icons/GitHub_monochrome.png"
        if kind in ("auto_test", "load_balance"):
            group["interval"] = original["interval"]
            # mihomo 的 timeout 单位是毫秒，Egern 的 timeout 单位是秒。
            group["timeout"] = original["timeout"] // 1000
        if kind == "auto_test":
            group["tolerance"] = original["tolerance"]
        if kind == "load_balance":
            group["algorithm"] = "hash"
        if group["name"] == "Apple":
            # 复制列表，避免后续插入英国选项时同时修改两个组的候选项。
            groups.append(
                {
                    "select": {
                        "name": "APNs",
                        "policies": list(group["policies"]),
                        "icon": f"{raw_base}/icons/APNs.png",
                    }
                }
            )
        groups.append({kind: group})
        if group["name"] == "台湾":
            groups.append(
                {
                    "select": {
                        "name": "英国",
                        "flatten": True,
                        "filter": "(?i)" + uk_filter,
                        "policies": ["全部节点"],
                        "icon": f"{raw_base}/icons/United_Kingdom.png",
                    }
                }
            )

    nsfw_group: ConfigEntry = {
        "select": {
            "name": "NSFW",
            "policies": [
                policy_name(name)
                for name in src["proxies_common"]["proxies_default"]["proxies"]
            ],
            "icon": f"{raw_base}/icons/nsfw_diamond.png",
        }
    }
    ehentai_index = next(
        i
        for i, group in enumerate(groups)
        if next(iter(group.values()))["name"] == "EHentai"
    )
    groups.insert(ehentai_index + 1, nsfw_group)
    for wrapped in groups:
        policies = next(iter(wrapped.values())).get("policies", [])
        if "台湾" in policies:
            policies.insert(policies.index("台湾") + 1, "英国")

    forward: list[ConfigEntry] = []
    for name, value in (("private", "system"), ("douyin", "douyin"), ("cn", "china")):
        forward.append({"proxy_rule_set": {**reference(name), "value": value}})
    forward.append({"domain_wildcard": {"match": "*", "value": "foreign"}})
    hosts: dict[str, list[str]] = {}
    for domain, values in src["hosts"].items():
        if domain.startswith("+."):
            hosts[domain[2:]] = values
            hosts["*." + domain[2:]] = values
        else:
            hosts[domain] = values
        if domain == "doh.pub":
            hosts["dns.alidns.com"] = ["223.5.5.5", "223.6.6.6"]
    hosts["doh.pub"] = ["1.12.12.12", "120.53.53.53"]
    # Egern Real IP 模块使用 glob；+.foo 必须展开为 foo 和 *.foo。
    # FCM 专用路由虽已移除，其原有 Real IP 排除项仍保留。
    real_ip: list[str] = []
    for name in ("private", "fakeip_filter", "geolocation-cn", "googlefcm"):
        for domain in entries[name]:
            if domain.startswith("+."):
                real_ip += [domain[2:], "*." + domain[2:]]
            elif domain.startswith("."):
                real_ip.append("*" + domain)
            else:
                real_ip.append(domain)
    profile: dict[str, Any] = {
        "ipv6": False,
        "allow_external_connections": True,
        "vif_only": True,
        "hijack_dns": ["*"],
        "compat_route": True,
        "include_all_networks": True,
        "include_apns": True,
        "proxy_latency_test_url": TEST_URL,
        "direct_latency_test_url": TEST_URL,
        "modules": [
            {
                "name": "MyClash Real IP Domains",
                "url": f"{raw_base}/modules/real-ip-domains.yaml",
                "update_interval": 86400,
                "enabled": True,
            },
            {
                "name": "Dr.COM 校园网流量",
                "url": f"{raw_base}/modules/drcom-egern/drcom.module.yaml",
                "update_interval": 86400,
                "enabled": True,
            },
            {
                "name": "中国移动（Hark 仪表盘版）",
                "url": "https://cdn.jsdmirror.com/gh/zhaohantao1360-hash/Hark@main/china-mobile-hark-dash.yaml",
                "update_interval": 86400,
                "enabled": True,
            },
            {
                "name": "中国电信小组件",
                "url": "https://cdn.jsdmirror.com/gh/IBL3ND/module@main/ChinaTelecom_Widget.yaml",
                "update_interval": 86400,
                "enabled": True,
            },
        ],
        "dns": {
            "bootstrap": ["223.5.5.5", "119.29.29.29"],
            "proxy_nameservers": [
                "https://dns.alidns.com/dns-query",
                "https://doh.pub/dns-query",
            ],
            "upstreams": {
                "china": [
                    "https://dns.alidns.com/dns-query",
                    "https://doh.pub/dns-query",
                ],
                "douyin": ["system", "180.184.1.1", "180.184.2.2"],
                "foreign": [
                    "https://cloudflare-dns.com/dns-query",
                    "https://dns.google/dns-query",
                ],
            },
            "forward": forward,
            "hosts": hosts,
        },
        "proxies": [],
        "policy_groups": groups,
        "default_subscription_group": "全部节点",
        "default_proxy_group": "全部节点",
        "rules": [],
    }
    # Explicit DNS endpoint routing replaces Mihomo's '#policy' annotations.
    dns_rules: list[ConfigEntry] = [
        rule({"domain": {"match": domain}}, "默认代理")
        for domain in ("cloudflare-dns.com", "dns.google")
    ]
    dns_rules += [
        rule({"ip_cidr": {"match": ip + "/32", "no_resolve": True}}, "默认代理")
        for ip in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
    ]
    dns_rules += [
        rule({"domain": {"match": domain}}, "DIRECT")
        for domain in ("doh.pub", "dns.alidns.com")
    ]
    dns_rules += [
        rule({"ip_cidr": {"match": ip + "/32", "no_resolve": True}}, "DIRECT")
        for ip in (
            "114.114.114.114",
            "223.5.5.5",
            "223.6.6.6",
            "119.29.29.29",
            "1.12.12.12",
            "120.53.53.53",
            "180.184.1.1",
            "180.184.2.2",
        )
    ]
    profile["rules"] = dns_rules
    skipped: list[str] = []
    for original in src["rules"]:
        parts = original.split(",")
        kind = parts[0]
        if kind == "PROCESS-NAME":
            skipped.append(original)
            continue
        if kind == "AND":
            # 上游的固定复合规则：拒绝非国内目标的 UDP/443。
            # 在此显式还原结构，避免用逗号拆分解析嵌套逻辑表达式。
            exempt = [
                {"rule_set": reference("cn_additional")},
                {"rule_set": reference("cn_ip-no-resolve")},
            ]
            profile["rules"].append(
                {
                    "and": {
                        "match": [
                            {"protocol": {"match": "udp"}},
                            {"dest_port": {"match": "443"}},
                            {"not": {"match": {"or": {"match": exempt}}}},
                        ],
                        "policy": "REJECT",
                    }
                }
            )
        elif kind == "RULE-SET":
            name, policy = parts[1:3]
            policy = policy_name(policy)
            if name in ("cryptocurrency", "googlefcm", "epicgames"):
                # Crypto is inserted with NSFW; FCM and Epic have no dedicated routes.
                continue
            if name == "apple_cn":
                # Apple CN 包含部分 push 子域，APNs 必须先匹配。
                profile["rules"].append(
                    rule({"domain_suffix": {"match": "push.apple.com"}}, "APNs")
                )
            profile["rules"].append({"rule_set": {**reference(name), "policy": policy}})
            if name == "private":
                profile["rules"].append(
                    {"rule_set": {**reference("douyin"), "policy": "DIRECT"}}
                )
            if name == "category-ads":
                profile["rules"].extend(
                    [
                        {"rule_set": {**reference("nsfw"), "policy": "NSFW"}},
                        {
                            "rule_set": {
                                **reference("cryptocurrency"),
                                "policy": "Crypto",
                            }
                        },
                    ]
                )
        elif kind == "MATCH":
            profile["rules"].append({"default": {"policy": policy_name(parts[1])}})
        else:
            translated = {
                "DOMAIN": "domain",
                "DOMAIN-SUFFIX": "domain_suffix",
                "DOMAIN-KEYWORD": "domain_keyword",
            }[kind]
            profile["rules"].append(rule({translated: {"match": parts[1]}}, parts[2]))

    # Follow the field order used by the reference Egern export.
    def ordered(values: Mapping[str, Value], keys: Sequence[str]) -> dict[str, Value]:
        """按模板键排序，未列出的字段仍按原始顺序追加，绝不丢弃字段。"""
        result = {key: values[key] for key in keys if key in values}
        for key, value in values.items():
            if key not in result:
                result[key] = value
        return result

    profile["dns"] = ordered(
        profile["dns"],
        ("bootstrap", "upstreams", "forward", "hosts", "proxy_nameservers"),
    )
    group_fields = {
        "select": (
            "name",
            "policies",
            "urls",
            "flatten",
            "filter",
            "update_interval",
            "icon",
            "hidden",
        ),
        "auto_test": (
            "name",
            "policies",
            "urls",
            "flatten",
            "filter",
            "interval",
            "tolerance",
            "timeout",
            "icon",
            "hidden",
        ),
        "load_balance": (
            "name",
            "policies",
            "urls",
            "algorithm",
            "flatten",
            "filter",
            "interval",
            "timeout",
            "icon",
            "hidden",
        ),
    }
    profile["policy_groups"] = [
        {kind: ordered(group, group_fields[kind])}
        for wrapped in profile["policy_groups"]
        for kind, group in wrapped.items()
    ]

    def order_rule(wrapped: ConfigEntry) -> ConfigEntry:
        """递归排序规则字段；and/or 含条件列表，not 只含一个条件。"""
        kind, fields = next(iter(wrapped.items()))
        fields = ordered(fields, ("match", "policy", "no_resolve", "update_interval"))
        if kind in ("and", "or"):
            fields["match"] = [order_rule(child) for child in fields["match"]]
        elif kind == "not":
            fields["match"] = order_rule(fields["match"])
        return {kind: fields}

    profile["rules"] = [order_rule(wrapped) for wrapped in profile["rules"]]
    profile = ordered(
        profile,
        (
            "ipv6",
            "allow_external_connections",
            "vif_only",
            "hijack_dns",
            "proxy_latency_test_url",
            "direct_latency_test_url",
            "compat_route",
            "include_all_networks",
            "include_apns",
            "dns",
            "proxies",
            "policy_groups",
            "rules",
            "modules",
            "default_subscription_group",
            "default_proxy_group",
        ),
    )
    text = yaml.dump(
        profile,
        Dumper=NoAliasDumper,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )
    header = """# MyClash mihomo 全量版 → Egern，配置同步日期：2026-10-18（Asia/Taipei）
# 上游配置提交：badd718b81a7c541b574e975ba48d8ca7813759c；规则集快照日期：2026-10-13。
# 原作者：AIsouler；原配置：https://github.com/AIsouler/MyClash
# 在“全部节点”的 urls 中填写订阅地址。必须返回 Egern 原生代理 YAML 或 Egern 可识别的订阅。
# 示例：将 urls: [] 改为 urls: [\"你的订阅地址\"]。
# 地区策略组展平并引用“全部节点”，只需在该组填写一次订阅。
# 分流规则集和 Real IP 模块从 Yoobohl/EgernTest 加载，每 86400 秒更新。
# 尚未在 iOS Egern 内运行验证。
"""
    header += (
        "# 原配置许可：\n"
        + "\n".join(
            "# " + line
            for line in (ROOT / "licenses/MyClash.txt")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        + "\n"
    )
    (ROOT / "Profile.yaml").write_text(header + text, encoding="utf-8")
    (ROOT / "modules").mkdir(exist_ok=True)
    (ROOT / "modules/real-ip-domains.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "MyClash Real IP Domains",
                "description": "原 Fake-IP 排除集合的 Egern 模块版本",
                "author": "AIsouler / Egern conversion",
                "homepage": "https://github.com/Yoobohl/EgernTest",
                "real_ip_domains": list(dict.fromkeys(real_ip)),
            },
            allow_unicode=True,
            sort_keys=False,
            width=120,
        ),
        encoding="utf-8",
    )
    (ROOT / "source" / "manifest.json").write_text(
        json.dumps(
            {
                "snapshot_date": "2026-10-13",
                "config_snapshot_date": "2026-10-18",
                "config_upstream_commit": "badd718b81a7c541b574e975ba48d8ca7813759c",
                "resources": manifest,
                "supplemental_sets": supplemental,
                "skipped_process_rules": skipped,
                "routing_rule_count": len(profile["rules"]),
                "dns_forward_count": len(forward),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        f"Converted {len(manifest)} sets, {len(profile['policy_groups'])} groups, "
        f"{len(profile['rules'])} routing rules, {len(forward)} DNS forward rules."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-base", default=RAW_BASE)
    parser.add_argument("--mihomo", type=Path, default=DEFAULT_MIHOMO)
    args = parser.parse_args()
    build(args.raw_base.rstrip("/"), args.mihomo)
