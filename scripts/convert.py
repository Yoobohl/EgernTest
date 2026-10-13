"""Build an Egern profile and native rule sets from actual MRS snapshots.

Run: uv run --with pyyaml --with zstandard python scripts/convert.py
MRS is exported by the official mihomo v1.19.32 convert-ruleset command.
"""

import argparse
import json
from pathlib import Path
from typing import Any

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


def rule(condition, policy):
    kind, value = next(iter(condition.items()))
    return {kind: {**value, "policy": policy}}


def build(raw_base=RAW_BASE, mihomo=DEFAULT_MIHOMO):
    src = yaml.safe_load((SOURCE / "mihomoConfig.yaml").read_text(encoding="utf-8"))
    version_output = check_version(mihomo)
    downloads = {
        item["name"]: item
        for item in json.loads(
            (SOURCE / "mrs-downloads.json").read_text(encoding="utf-8")
        )
    }
    entries = {}
    manifest = []
    for name, provider in src["rule-providers"].items():
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
    write_native(
        ROOT / "rulesets/cn_ip-no-resolve.yaml", entries["cn_ip"], "ipcidr", True
    )
    supplemental = add_supplemental_sets(ROOT)
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

    def reference(name):
        return {"match": f"{raw_base}/rulesets/{name}.yaml", "update_interval": 86400}

    # Subscription is entered once, then flattened and filtered by consumer groups.
    exclude = src["global_exclude_filter"]["exclude-filter"].removeprefix("(?i)")
    groups = [
        {
            "select": {
                "name": "机场订阅",
                "urls": [],
                "update_interval": 86400,
                "filter": "(?i)^(?!.*" + exclude + ").*$",
                "hidden": True,
            }
        }
    ]
    for original in src["proxy-groups"]:
        if original["name"].endswith("-自动选择"):
            continue
        kind = {"url-test": "auto_test", "load-balance": "load_balance"}.get(
            original["type"], original["type"]
        )
        group: dict[str, Any] = {"name": original["name"]}
        policies = [
            name
            for name in original.get("proxies", [])
            if not name.endswith("-自动选择")
        ]
        if original["name"] == "直连":
            policies = ["DIRECT"]
        elif original["name"] == "AdBlock":
            policies = ["REJECT"]
        # No documented default-selected: preserve intended choice as first item.
        initial = original.get("default-selected")
        if initial in policies:
            policies.remove(initial)
            policies.insert(0, initial)
        if original.get("include-all"):
            # Region manual groups mount nodes directly, without automatic subgroups.
            if kind == "select" and original.get("proxies"):
                filt = original.get("filter")
                neg = original.get("exclude-filter")
                group["urls"] = []
                group["update_interval"] = 86400
                combined = "(?i)^(?!.*" + exclude + ")"
                if filt:
                    combined += "(?=.*" + filt.removeprefix("(?i)") + ")"
                if neg:
                    combined += "(?!.*" + neg.removeprefix("(?i)") + ")"
                group["filter"] = combined + ".*$"
            else:
                policies = ["机场订阅"]
                group["flatten"] = True
                if original.get("filter"):
                    group["filter"] = original["filter"]
                if original.get("exclude-filter"):
                    group["filter"] = (
                        "(?i)^(?!.*"
                        + original["exclude-filter"].removeprefix("(?i)")
                        + ").*$"
                    )
        if policies:
            group["policies"] = policies
        for field in ("icon", "hidden"):
            if field in original:
                group[field] = original[field]
        if group.get("icon", "").endswith(".svg"):
            group["icon"] = f"{raw_base}/icons/{Path(group['icon']).stem}.png"
        if kind in ("auto_test", "load_balance"):
            group["interval"] = original["interval"]
            group["timeout"] = original["timeout"] // 1000
        if kind == "auto_test":
            group["tolerance"] = original["tolerance"]
        if kind == "load_balance":
            group["algorithm"] = "hash"
        groups.append({kind: group})

    groups.append(
        {
            "select": {
                "name": "NSFW",
                "policies": list(src["proxies_common"]["proxies_default"]["proxies"]),
                "icon": f"{raw_base}/icons/nsfw_diamond.png",
            }
        }
    )

    forward = []
    for name, value in (("private", "system"), ("douyin", "douyin"), ("cn", "china")):
        forward.append({"proxy_rule_set": {**reference(name), "value": value}})
    forward.append({"domain_wildcard": {"match": "*", "value": "foreign"}})
    hosts = {}
    for domain, values in src["hosts"].items():
        if domain.startswith("+."):
            hosts[domain[2:]] = values
            hosts["*." + domain[2:]] = values
        else:
            hosts[domain] = values
    real_ip = []
    for name in ("private", "fakeip_filter", "geolocation-cn", "googlefcm"):
        for domain in entries[name]:
            if domain.startswith("+."):
                real_ip += [domain[2:], "*." + domain[2:]]
            elif domain.startswith("."):
                real_ip.append("*" + domain)
            else:
                real_ip.append(domain)
    profile: dict[str, Any] = {
        "ipv6": True,
        "http_port": 7890,
        "socks_port": 7891,
        "allow_external_connections": True,
        "hijack_dns": ["*"],
        "block_quic": False,
        "proxy_latency_test_url": TEST_URL,
        "direct_latency_test_url": TEST_URL,
        "modules": [
            {
                "name": "MyClash Real IP Domains",
                "url": f"{raw_base}/modules/real-ip-domains.yaml",
                "update_interval": 86400,
                "enabled": True,
            }
        ],
        "dns": {
            "bootstrap": ["114.114.114.114"],
            "upstreams": {
                "china": ["223.5.5.5", "119.29.29.29"],
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
        "default_subscription_group": "机场订阅",
        "default_proxy_group": "机场订阅",
        "rules": [],
    }
    # Explicit DNS endpoint routing replaces Mihomo's '#policy' annotations.
    dns_rules = [
        rule({"domain": {"match": domain}}, "默认代理")
        for domain in ("cloudflare-dns.com", "dns.google")
    ]
    dns_rules += [
        rule({"ip_cidr": {"match": ip + "/32", "no_resolve": True}}, "默认代理")
        for ip in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
    ]
    dns_rules += [rule({"domain": {"match": "doh.pub"}}, "DIRECT")]
    dns_rules += [
        rule({"ip_cidr": {"match": ip + "/32", "no_resolve": True}}, "DIRECT")
        for ip in (
            "114.114.114.114",
            "223.5.5.5",
            "119.29.29.29",
            "1.12.12.12",
            "120.53.53.53",
            "180.184.1.1",
            "180.184.2.2",
        )
    ]
    profile["rules"] = dns_rules
    skipped = []
    for original in src["rules"]:
        parts = original.split(",")
        kind = parts[0]
        if kind == "PROCESS-NAME":
            skipped.append(original)
            continue
        if kind == "AND":
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
            if name == "cryptocurrency":
                # Its merged reference is inserted with NSFW before the general
                # proxy service sets, so their domains cannot shadow these lists.
                continue
            profile["rules"].append({"rule_set": {**reference(name), "policy": policy}})
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
            profile["rules"].append({"default": {"policy": parts[1]}})
        else:
            translated = {
                "DOMAIN": "domain",
                "DOMAIN-SUFFIX": "domain_suffix",
                "DOMAIN-KEYWORD": "domain_keyword",
            }[kind]
            profile["rules"].append(rule({translated: {"match": parts[1]}}, parts[2]))

    # Reuse one subscription URL list via a standard YAML anchor. Empty until set.
    shared_urls = groups[0]["select"]["urls"]
    for wrapped in groups:
        group = next(iter(wrapped.values()))
        if "urls" in group:
            group["urls"] = shared_urls
    # Put policies and subscriptions at the start for convenient editing.
    head = {
        key: profile[key] for key in ("policy_groups", "default_subscription_group")
    }
    tail = {key: value for key, value in profile.items() if key not in head}
    text = yaml.safe_dump(
        {**head, **tail}, allow_unicode=True, sort_keys=False, width=120
    )
    text = text.replace("&id001", "&subscriptions").replace("*id001", "*subscriptions")
    header = """# MyClash mihomo 全量版 → Egern，转换日期：2026-10-13（Asia/Taipei）
# 原作者：AIsouler；原配置：https://github.com/AIsouler/MyClash
# 填写下方 urls 的机场订阅。必须返回 Egern 原生代理 YAML 或 Egern 可识别的订阅。
# 示例：将 urls: &subscriptions [] 改为 urls: &subscriptions [\"你的订阅地址\"]。
# 所有地区手动组共用此 URL 列表；请勿删除 &subscriptions / *subscriptions。
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
