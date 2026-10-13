"""Build a self-contained Egern profile from the saved MyClash snapshot.

Run: uv run --with pyyaml --with zstandard python scripts/convert.py
MRS decoding follows MetaCubeX/mihomo's mrs_reader.go and domain_set_bin.go.
"""

import argparse
import ipaddress
import json
import re
import struct
from collections import deque
from pathlib import Path
from typing import Any

import yaml
import zstandard

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "source"
TEST_URL = "https://www.apple.com/library/test/success.html"
RAW_BASE = "https://raw.githubusercontent.com/Yoobohl/EgernTest/main"


def decode_mrs(path):
    with path.open("rb") as stream:
        data = zstandard.ZstdDecompressor().stream_reader(stream).read()
    assert data[:5] == b"MRS\x01\x00", "Expected domain MRS v1"
    count, extra = struct.unpack_from(">qq", data, 5)
    offset = 21 + extra
    assert data[offset] == 1, "Expected domain trie v1"
    offset += 1
    arrays = []
    for _ in range(2):
        length = struct.unpack_from(">q", data, offset)[0]
        offset += 8
        arrays.append(struct.unpack_from(f">{length}Q", data, offset))
        offset += length * 8
    length = struct.unpack_from(">q", data, offset)[0]
    offset += 8
    labels = data[offset : offset + length]
    assert offset + length == len(data)
    leaves, bitmap = arrays
    queue = deque([b""])
    node = bit = edge = 0
    keys = []
    while queue:
        prefix = queue.popleft()
        if (leaves[node // 64] >> (node % 64)) & 1:
            key = prefix.decode("utf-8").removesuffix("+")[::-1]
            keys.append(key)
        while not ((bitmap[bit // 64] >> (bit % 64)) & 1):
            queue.append(prefix + labels[edge : edge + 1])
            edge += 1
            bit += 1
        bit += 1
        node += 1
    assert edge == len(labels)
    # MRS count is insertion count; compact trie can deduplicate/expand entries.
    assert count > 0 and keys
    exact = {key for key in keys if not key.startswith(".")}
    suffix = {key[1:] for key in keys if key.startswith(".")}
    result = ["+." + key for key in sorted(exact & suffix)]
    result += sorted(exact - suffix)
    result += ["." + key for key in sorted(suffix - exact)]
    return result, count


def domain_pattern(domain):
    """Translate Mihomo domain-provider label wildcards, with anchored boundaries."""
    prefix = ""
    if domain.startswith("+."):
        prefix, domain = r"(?:[^.]+\.)*", domain[2:]
    elif domain.startswith("."):
        prefix, domain = r"(?:[^.]+\.)+", domain[1:]
    return prefix + r"\.".join(
        "[^.]+" if label == "*" else re.escape(label) for label in domain.split(".")
    )


def regexes(domains, size=200):
    domains = list(dict.fromkeys(domains))
    for start in range(0, len(domains), size):
        yield (
            "(?i)^(?:"
            + "|".join(domain_pattern(d) for d in domains[start : start + size])
            + ")$"
        )


def conditions(entries, behavior, no_resolve=False):
    if behavior == "domain":
        return [{"domain_regex": {"match": pattern}} for pattern in regexes(entries)]
    result = []
    for entry in entries:
        network = ipaddress.ip_network(entry, strict=False)
        value = {"match": str(network)}
        if no_resolve:
            value["no_resolve"] = True
        result.append({"ip_cidr6" if network.version == 6 else "ip_cidr": value})
    return result


def rule(condition, policy):
    kind, value = next(iter(condition.items()))
    return {kind: {**value, "policy": policy}}


def native_set(entries, behavior):
    result = {}
    for entry in entries:
        if behavior == "ipcidr":
            network = ipaddress.ip_network(entry, strict=False)
            kind, value = (
                ("ip_cidr6_set" if network.version == 6 else "ip_cidr_set"),
                str(network),
            )
        elif entry.startswith("+.") and "*" not in entry:
            kind, value = "domain_suffix_set", entry[2:]
        elif not entry.startswith(".") and "*" not in entry:
            kind, value = "domain_set", entry
        else:
            kind, value = "domain_regex_set", "(?i)^" + domain_pattern(entry) + "$"
        result.setdefault(kind, []).append(value)
    return result


def build(raw_base=RAW_BASE):
    src = yaml.safe_load((SOURCE / "mihomoConfig.yaml").read_text(encoding="utf-8"))
    resources = json.loads((SOURCE / "rule-sources.json").read_text(encoding="utf-8"))
    entries = {}
    manifest = []
    for item in resources:
        if item["name"] == "cn_additional":
            payload, mrs_count = decode_mrs(SOURCE / "cn-additional-list.mrs")
            url = src["rule-providers"]["cn_additional"]["url"]
        else:
            assert item["status"] == 200, item["name"]
            if item["name"] == "emby":
                payload = [
                    line.strip()
                    for line in item["text"].splitlines()
                    if line.strip() and not line.startswith("#")
                ]
            else:
                payload = yaml.safe_load(item["text"])["payload"]
            url, mrs_count = item["url"], None
        entries[item["name"]] = payload
        manifest.append(
            {
                "name": item["name"],
                "source": url,
                "count": len(payload),
                "mrs_insertion_count": mrs_count,
                "behavior": item["behavior"],
            }
        )
        sets = ROOT / "rulesets"
        sets.mkdir(exist_ok=True)
        converted = native_set(payload, item["behavior"])
        if item["behavior"] == "ipcidr" and item["name"] not in {"cn_ip", "private_ip"}:
            converted = {"no_resolve": True, **converted}
        (sets / (item["name"] + ".yaml")).write_text(
            yaml.safe_dump(
                converted,
                allow_unicode=True,
                sort_keys=False,
                width=120,
            ),
            encoding="utf-8",
        )
    (ROOT / "rulesets/cn_ip-no-resolve.yaml").write_text(
        yaml.safe_dump(
            {"no_resolve": True, **native_set(entries["cn_ip"], "ipcidr")},
            sort_keys=False,
            width=120,
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
        kind = {"url-test": "auto_test", "load-balance": "load_balance"}.get(
            original["type"], original["type"]
        )
        group = {"name": original["name"]}
        policies = list(original.get("proxies", []))
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
            # Keep the automatic sub-policy while mounting subscription nodes.
            if kind == "select" and policies:
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
        if kind in ("auto_test", "load_balance"):
            group["interval"] = original["interval"]
            group["timeout"] = original["timeout"] // 1000
        if kind == "auto_test":
            group["tolerance"] = original["tolerance"]
        if kind == "load_balance":
            group["algorithm"] = "hash"
        groups.append({kind: group})

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
            profile["rules"].append({"rule_set": {**reference(name), "policy": policy}})
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
    args = parser.parse_args()
    build(args.raw_base.rstrip("/"))
