"""Validate native Egern rule sets and references."""

import ipaddress
import json
from pathlib import Path

import pcre2
import yaml
from convert import RAW_BASE, decode_mrs, domain_pattern

root = Path(__file__).resolve().parent.parent
profile = yaml.safe_load((root / "Profile.yaml").read_text(encoding="utf-8"))
groups = {
    next(iter(g.values()))["name"]: next(iter(g.values()))
    for g in profile["policy_groups"]
}
assert len(groups) == len(profile["policy_groups"])
known = set(groups) | {"DIRECT", "REJECT"}
for name, group in groups.items():
    assert set(group.get("policies", [])) <= known, name
    assert "latency_test_url" not in group
    if "filter" in group:
        pcre2.compile(group["filter"])
    if "urls" in group:
        assert group["urls"] is groups["机场订阅"]["urls"]


def visit(name, active):
    assert name not in active, name
    for child in groups[name].get("policies", []):
        if child in groups:
            visit(child, active | {name})


for name in groups:
    visit(name, set())

sets = {}
count = 0
for path in (root / "rulesets").glob("*.yaml"):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert set(data) <= {
        "domain_set",
        "domain_suffix_set",
        "domain_regex_set",
        "ip_cidr_set",
        "ip_cidr6_set",
        "no_resolve",
    }, path
    for key, entries in data.items():
        if key == "no_resolve":
            assert entries is True
            continue
        assert isinstance(entries, list) and entries
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


def resolve(url):
    assert url.startswith(RAW_BASE + "/"), url
    path = root / url.removeprefix(RAW_BASE + "/")
    assert path.is_file(), path
    return path


refs = []


def validate_condition(wrapped):
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
assert "proxy_nameservers" not in profile["dns"]
assert profile["proxy_latency_test_url"] == profile["direct_latency_test_url"]

resources = json.loads((root / "source/rule-sources.json").read_text(encoding="utf-8"))
source_count = 0
for resource in resources:
    name = resource["name"]
    if name == "cn_additional":
        entries, _ = decode_mrs(root / "source/cn-additional-list.mrs")
    elif name == "emby":
        entries = [
            line.strip()
            for line in resource["text"].splitlines()
            if line.strip() and not line.startswith("#")
        ]
    else:
        entries = yaml.safe_load(resource["text"])["payload"]
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
        assert value in lookup[kind], (name, entry)
        source_count += 1
    if resource["behavior"] == "ipcidr":
        assert sets[name].get("no_resolve", False) == (
            name not in {"cn_ip", "private_ip"}
        )
assert sets["cn_ip-no-resolve"]["no_resolve"] is True
assert {k: v for k, v in sets["cn_ip-no-resolve"].items() if k != "no_resolve"} == sets[
    "cn_ip"
]

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
assert not pcre2.compile(groups["香港"]["filter"]).match("香港 剩余流量")
assert not pcre2.compile(groups["其他节点"]["filter"]).match("Hong Kong 01")
assert pcre2.compile(groups["其他节点"]["filter"]).match("德国 01")
assert groups["FCM"]["policies"][0] == "直连"
assert groups["AI"]["policies"][0] == "美国"
print(
    f"PASS: {len(groups)} groups, {len(sets)} native sets, {len(refs)} rule-set references, {source_count} source entries, {count} output entries; no broken references/cycles."
)
