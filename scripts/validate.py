"""校验生成物的结构、引用、域名匹配语义和官方 MRS 往返结果。

按顺序执行各阶段断言，任何阶段失败即停止；不联网获取新快照。
末尾的往返转换只写入临时目录，不修改已保存的规则集和来源文件。
"""

import ipaddress
import json
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pcre2
import yaml
from classical_to_egern import DomainSet, parse_classical, suffix_covered
from convert import RAW_BASE, ConfigEntry, ConfigFields
from mrs_to_egern import (
    DEFAULT_MIHOMO,
    check_version,
    domain_pattern,
    dump_mrs,
    native_set,
    sha256,
)
from PIL import Image

# 配置来自 YAML，字段值在下方各阶段检查；包装规则共享构建脚本的类型。
root = Path(__file__).resolve().parent.parent
profile: ConfigFields = yaml.safe_load(
    (root / "Profile.yaml").read_text(encoding="utf-8")
)
assert not any(
    isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken))
    for token in yaml.scan((root / "Profile.yaml").read_text(encoding="utf-8"))
)
groups: dict[str, ConfigFields] = {
    next(iter(g.values()))["name"]: next(iter(g.values()))
    for g in profile["policy_groups"]
}
assert len(groups) == len(profile["policy_groups"])
group_order = list(groups)
assert group_order.index("NSFW") == group_order.index("EHentai") + 1
known = set(groups) | {"DIRECT", "REJECT"}
for name, group in groups.items():
    assert set(group.get("policies", [])) <= known, name
    assert "latency_test_url" not in group
    if "filter" in group:
        pcre2.compile(group["filter"])
    if "urls" in group:
        assert group["urls"] is groups["全部节点"]["urls"]


def visit(name: str, active: set[str]) -> None:
    """沿当前递归路径检查策略引用环；跨不同路径复用同一个组是合法的。"""
    assert name not in active, name
    for child in groups[name].get("policies", []):
        if child in groups:
            visit(child, active | {name})


for name in groups:
    visit(name, set())
assert not any(name.endswith("-自动选择") for name in groups)
assert [
    next(iter(g.values()))["name"] for g in profile["policy_groups"] if "auto_test" in g
] == ["自动选择"]
for name in (
    "香港",
    "日本",
    "美国",
    "新加坡",
    "台湾",
    "英国",
    "低倍率节点",
    "高倍率节点",
    "其他节点",
):
    assert groups[name]["policies"] == ["全部节点"]
    assert groups[name]["flatten"] is True
    assert "urls" not in groups[name]

# 检查规则集字段、重复项、CIDR 和正则；集合顶层还允许 no_resolve。
sets: dict[str, ConfigFields] = {}
count = 0
for path in (root / "rulesets").glob("*.yaml"):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert set(data) <= {
        "domain_set",
        "domain_suffix_set",
        "domain_regex_set",
        "domain_keyword_set",
        "ip_cidr_set",
        "ip_cidr6_set",
        "no_resolve",
    }, path
    for key, entries in data.items():
        if key == "no_resolve":
            assert entries is True
            continue
        assert isinstance(entries, list) and entries
        assert len(entries) == len(set(entries)), (path, key)
        count += len(entries)
        if key in {"ip_cidr_set", "ip_cidr6_set"}:
            for item in entries:
                assert ipaddress.ip_network(item).version == (
                    4 if key == "ip_cidr_set" else 6
                )
        elif key == "domain_regex_set":
            for item in entries:
                pcre2.compile(item)
    sets[path.stem] = data
assert len(sets) == 48
assert "epicgames" not in sets


def resolve(url: str) -> Path:
    """将本站 CDN 地址映射到本地文件，检查引用存在而不依赖网络请求。"""
    assert url.startswith(RAW_BASE + "/"), url
    path = root / url.removeprefix(RAW_BASE + "/")
    assert path.is_file(), path
    return path


# 清单中的原始 SVG 渲染图标有固定尺寸和校验值；手工新增图标只核对引用。
icon_manifest = json.loads(
    (root / "source/icons/manifest.json").read_text(encoding="utf-8")
)
assert len(icon_manifest) == 37
for item in icon_manifest:
    path = root / "icons" / item["name"]
    assert sha256(path) == item["png_sha256"]
    assert (
        sha256(root / "source/icons/svg" / (path.stem + ".svg")) == item["svg_sha256"]
    )
    with Image.open(path) as image:
        assert image.format == "PNG" and image.mode == "RGBA"
        assert image.size == (256, 256)
        assert image.getchannel("A").getextrema() == (0, 255)
for group in groups.values():
    if "icon" in group:
        assert group["icon"].endswith(".png")
        resolve(group["icon"])


refs: list[Path] = []


def validate_condition(wrapped: ConfigEntry) -> None:
    """递归检查路由条件和策略引用，并收集逻辑规则内的远程集合引用。

    no_resolve 属于集合内容，而非远程 rule_set 引用字段。
    """
    assert len(wrapped) == 1
    kind, item = next(iter(wrapped.items()))
    assert kind in {
        "domain",
        "domain_suffix",
        "domain_keyword",
        "ip_cidr",
        "and",
        "or",
        "not",
        "protocol",
        "dest_port",
        "default",
        "rule_set",
    }, kind
    if "policy" in item:
        assert item["policy"] in known
    if kind in {"and", "or"}:
        for condition in item["match"]:
            validate_condition(condition)
    elif kind == "not":
        validate_condition(item["match"])
    elif kind == "rule_set":
        refs.append(resolve(item["match"]))
        assert "no_resolve" not in item
        assert item["update_interval"] == 86400
    elif kind == "ip_cidr":
        ipaddress.ip_network(item["match"])


for item in profile["rules"]:
    validate_condition(item)
assert profile["rules"][-1] == {"default": {"policy": "漏网之鱼"}}
for wrapped in profile["dns"]["forward"]:
    kind, item = next(iter(wrapped.items()))
    assert kind in {"proxy_rule_set", "domain_wildcard"}
    assert item["value"] in set(profile["dns"]["upstreams"]) | {"system"}
    if kind == "proxy_rule_set":
        refs.append(resolve(item["match"]))
module = yaml.safe_load(
    resolve(profile["modules"][0]["url"]).read_text(encoding="utf-8")
)
assert module["real_ip_domains"] and "real_ip_domains" not in profile
assert profile["dns"]["proxy_nameservers"] == [
    "https://dns.alidns.com/dns-query",
    "https://doh.pub/dns-query",
]
host_names = list(profile["dns"]["hosts"])
assert host_names.index("dns.alidns.com") == host_names.index("doh.pub") + 1
assert profile["dns"]["bootstrap"] == ["223.5.5.5", "119.29.29.29"]
assert profile["dns"]["upstreams"]["china"] == [
    "https://dns.alidns.com/dns-query",
    "https://doh.pub/dns-query",
]
assert profile["dns"]["hosts"]["dns.alidns.com"] == ["223.5.5.5", "223.6.6.6"]
assert profile["dns"]["hosts"]["doh.pub"] == ["1.12.12.12", "120.53.53.53"]
for name in ("doh.pub", "dns.alidns.com"):
    assert (
        next(
            r["domain"]["policy"]
            for r in profile["rules"]
            if r.get("domain", {}).get("match") == name
        )
        == "DIRECT"
    )
drcom = yaml.safe_load(
    (root / "modules/drcom-egern/drcom.module.yaml").read_text(encoding="utf-8")
)
script = drcom["scriptings"][0]["generic"]
assert script["script_url"] == RAW_BASE + "/modules/drcom-egern/drcom-widget.js"
resolve(script["script_url"])
assert drcom["widgets"][0]["script_name"] == script["name"]
assert profile["proxy_latency_test_url"] == profile["direct_latency_test_url"]
assert profile["default_proxy_group"] == "全部节点"
assert profile["default_subscription_group"] == "全部节点"
assert "机场订阅" not in groups
for group in groups.values():
    assert "机场订阅" not in group.get("policies", [])
drcom_reference = next(
    m for m in profile["modules"] if m["url"].endswith("/drcom.module.yaml")
)
assert drcom_reference["enabled"] is True
assert drcom_reference["update_interval"] == 86400
resolve(drcom_reference["url"])
external_widgets = {
    "https://cdn.jsdmirror.com/gh/zhaohantao1360-hash/Hark@main/china-mobile-hark-dash.yaml",
    "https://cdn.jsdmirror.com/gh/IBL3ND/module@main/ChinaTelecom_Widget.yaml",
}
for url in external_widgets:
    module_reference = next(m for m in profile["modules"] if m["url"] == url)
    assert module_reference["enabled"] is True
    assert module_reference["update_interval"] == 86400
assert len({m["url"] for m in profile["modules"]}) == len(profile["modules"])
assert profile["vif_only"] is True
assert profile["ipv6"] is False
assert "block_quic" not in profile
assert profile["compat_route"] is True
assert "http_port" not in profile and "socks_port" not in profile
assert groups["NSFW"]["icon"] == RAW_BASE + "/icons/nsfw_diamond.png"

# 固定来源校验值后，逐条证明官方导出项仍被 Egern 集合覆盖。
# 合并可能删除冗余精确域名，因此不能只比较条目数量或字符串相等。
resources: list[dict[str, Any]] = json.loads(
    (root / "source/manifest.json").read_text(encoding="utf-8")
)["resources"]
source_count = 0
for resource in resources:
    name = resource["name"]
    assert resource["format"] == "mrs"
    text_path = root / "source/text" / (name + ".txt")
    mrs_path = root / "source/mrs" / (name + ".mrs")
    assert sha256(mrs_path) == resource["mrs_sha256"]
    assert sha256(text_path) == resource["text_sha256"]
    entries = text_path.read_text(encoding="utf-8").splitlines()
    assert len(entries) == resource["count"]
    lookup = {k: set(v) for k, v in sets[name].items() if k != "no_resolve"}
    for entry in entries:
        if resource["behavior"] == "ipcidr":
            net = ipaddress.ip_network(entry, strict=False)
            kind, value = (
                ("ip_cidr_set" if net.version == 4 else "ip_cidr6_set"),
                str(net),
            )
        elif entry.startswith("+.") and "*" not in entry:
            kind, value = "domain_suffix_set", entry[2:]
        elif not entry.startswith(".") and "*" not in entry:
            kind, value = "domain_set", entry
        else:
            kind, value = "domain_regex_set", "(?i)^" + domain_pattern(entry) + "$"
        covered = value in lookup.get(kind, set())
        if not covered and kind in {"domain_set", "domain_suffix_set"}:
            covered = suffix_covered(value, lookup.get("domain_suffix_set", set()))
        assert covered, (name, entry)
        source_count += 1
    if resource["behavior"] == "ipcidr":
        assert sets[name].get("no_resolve", False) == (
            name not in {"cn_ip", "private_ip"}
        )
assert sets["cn_ip-no-resolve"]["no_resolve"] is True
assert {k: v for k, v in sets["cn_ip-no-resolve"].items() if k != "no_resolve"} == sets[
    "cn_ip"
]

# 覆盖根域、子域、大小写和标签边界，避免通配符转换扩大匹配范围。
samples = {
    "+.example.com": (
        {"example.com", "a.example.com", "a.b.example.com", "EXAMPLE.COM"},
        {"badexample.com", "example.com.bad"},
    ),
    "example.com": (
        {"example.com", "EXAMPLE.COM"},
        {"a.example.com", "example.com.bad"},
    ),
    ".example.com": (
        {"a.example.com", "a.b.example.com"},
        {"example.com", "badexample.com"},
    ),
    "*.example.com": ({"a.example.com"}, {"example.com", "a.b.example.com"}),
}
for domain, (positive, negative) in samples.items():
    regex = pcre2.compile("(?i)^" + domain_pattern(domain) + "$")
    assert all(regex.match(v) for v in positive)
    assert not any(regex.match(v) for v in negative)
assert pcre2.compile(groups["香港"]["filter"]).match("香港 01")
assert not pcre2.compile(groups["香港"]["filter"]).match("日本 01")
assert not (
    pcre2.compile(groups["全部节点"]["filter"]).match("香港 剩余流量")
    and pcre2.compile(groups["香港"]["filter"]).match("香港 剩余流量")
)
assert list(groups).index("台湾") + 1 == list(groups).index("英国")
assert groups["英国"]["icon"] == RAW_BASE + "/icons/United_Kingdom.png"
uk_regex = pcre2.compile(groups["英国"]["filter"])
other_regex = pcre2.compile(groups["其他节点"]["filter"])
for sample in (
    "🇬🇧 01",
    "英国 01",
    "伦敦 01",
    "曼彻斯特 01",
    "UK 01",
    "uk-01",
    "GB 01",
    "GBR 01",
    "United Kingdom 01",
    "Great Britain 01",
    "Britain 01",
):
    assert uk_regex.search(sample), sample
    assert not other_regex.search(sample), sample
for sample in ("香港 01", "美国 01", "德国 01", "Ukraine 01", "Debug 01", "GBRouter"):
    assert not uk_regex.search(sample), sample
assert not pcre2.compile(groups["其他节点"]["filter"]).match("Hong Kong 01")
assert pcre2.compile(groups["其他节点"]["filter"]).match("德国 01")
assert groups["AdBlock"]["policies"] == ["REJECT", "DIRECT"]
assert "FCM" not in groups
assert groups["APNs"]["policies"] == groups["Apple"]["policies"]
assert groups["APNs"]["icon"] == RAW_BASE + "/icons/APNs.png"
assert list(groups).index("APNs") + 1 == list(groups).index("Apple")
apns_rule = {"domain_suffix": {"match": "push.apple.com", "policy": "APNs"}}
assert profile["rules"].count(apns_rule) == 1
assert profile["rules"].index(apns_rule) + 1 == next(
    i
    for i, wrapped in enumerate(profile["rules"])
    if wrapped.get("rule_set", {}).get("match", "").endswith("/apple_cn.yaml")
)
assert not any(
    wrapped.get("rule_set", {}).get("match", "").endswith("/googlefcm.yaml")
    for wrapped in profile["rules"]
)
assert groups["AI"]["policies"][0] == "美国"


# Verify merge semantics against the unmodified union, including boundaries.
def matches(domain: str, sources: Sequence[Mapping[str, list[str]]]) -> bool:
    """按精确域名、标签后缀和关键词模拟纯域名集合的匹配并集。"""
    domain = domain.lower()
    return any(
        domain in data.get("domain_set", [])
        or any(
            domain == suffix or domain.endswith("." + suffix)
            for suffix in data.get("domain_suffix_set", [])
        )
        or any(keyword in domain for keyword in data.get("domain_keyword_set", []))
        for data in sources
    )


supplemental = json.loads((root / "source/manifest.json").read_text(encoding="utf-8"))[
    "supplemental_sets"
]
nsfw, nsfw_info = parse_classical(root / "source/classical/nsfw.list")
web3, web3_info = parse_classical(root / "source/classical/web3.list")
crypto_original: DomainSet = native_set(
    (root / "source/text/cryptocurrency.txt").read_text(encoding="utf-8").splitlines(),
    "domain",
)
for name, inputs in (("nsfw", [nsfw]), ("cryptocurrency", [crypto_original, web3])):
    merge_samples: set[str] = set()
    for data in inputs:
        for entries in data.values():
            for entry in entries:
                merge_samples.update(
                    {
                        entry,
                        entry.upper(),
                        "child." + entry,
                        "bad" + entry,
                        entry + ".invalid",
                    }
                )
    for sample in merge_samples:
        assert matches(sample, inputs) == matches(sample, [sets[name]]), (name, sample)
    assert supplemental[name]["output_count"] == sum(
        len(v) for v in sets[name].values()
    )
assert supplemental["nsfw"]["source_sha256"] == nsfw_info["source_sha256"]
assert supplemental["cryptocurrency"]["source_sha256"] == web3_info["source_sha256"]
assert len(web3_info["skipped"]) == 3
assert groups["NSFW"]["policies"][0] == "默认代理"
positions = {
    wrapped["rule_set"]["match"].rsplit("/", 1)[-1]: index
    for index, wrapped in enumerate(profile["rules"])
    if "rule_set" in wrapped
}
assert (
    positions["category-ads.yaml"]
    < positions["nsfw.yaml"]
    < positions["cryptocurrency.yaml"]
)
assert positions["cryptocurrency.yaml"] < positions["google.yaml"]
assert positions["cryptocurrency.yaml"] < positions["github.yaml"]
assert positions["nsfw.yaml"] < positions["geolocation-!cn.yaml"]
assert (
    sum(
        w.get("rule_set", {}).get("match", "").endswith("/cryptocurrency.yaml")
        for w in profile["rules"]
    )
    == 1
)
# Round-trip all official DumpMrs outputs through the pinned implementation.
check_version(DEFAULT_MIHOMO)
with tempfile.TemporaryDirectory(prefix="mrs-roundtrip-", dir=root / ".cache") as temp:
    temp_root = Path(temp)
    for resource in resources:
        name, behavior = resource["name"], resource["behavior"]
        input_text = root / "source/text" / (name + ".txt")
        mrs_path = temp_root / (name + ".mrs")
        output_text = temp_root / (name + ".txt")
        subprocess.run(
            [
                str(DEFAULT_MIHOMO),
                "convert-ruleset",
                behavior,
                "text",
                str(input_text),
                str(mrs_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        returned, actual_behavior, _ = dump_mrs(mrs_path, output_text)
        assert actual_behavior == behavior
        assert returned == input_text.read_text(encoding="utf-8").splitlines(), name
print(
    f"PASS: {len(groups)} groups, {len(sets)} native sets, {len(refs)} references, "
    f"{source_count} official text entries, {count} output entries; "
    f"{len(resources)} official MRS/text round-trips; no broken references/cycles."
)
