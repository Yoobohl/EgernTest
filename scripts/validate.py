"""Validate native Egern rule sets and references."""

import ipaddress
import json
import subprocess
import tempfile
from pathlib import Path

import pcre2
import yaml
from classical_to_egern import parse_classical, suffix_covered
from convert import RAW_BASE
from mrs_to_egern import (
    DEFAULT_MIHOMO,
    check_version,
    domain_pattern,
    dump_mrs,
    native_set,
    sha256,
)
from PIL import Image

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
        assert group["urls"] is groups["全部节点"]["urls"]


def visit(name, active):
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
    "低倍率节点",
    "高倍率节点",
    "其他节点",
):
    assert groups[name]["policies"] == ["全部节点"]
    assert groups[name]["flatten"] is True
    assert "urls" not in groups[name]

sets = {}
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
assert len(sets) == 49


def resolve(url):
    assert url.startswith(RAW_BASE + "/"), url
    path = root / url.removeprefix(RAW_BASE + "/")
    assert path.is_file(), path
    return path


icon_manifest = json.loads(
    (root / "source/icons/manifest.json").read_text(encoding="utf-8")
)
assert len(icon_manifest) == 36
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
assert profile["default_proxy_group"] == "全部节点"
assert groups["NSFW"]["icon"] == RAW_BASE + "/icons/nsfw_diamond.png"

resources = json.loads((root / "source/manifest.json").read_text(encoding="utf-8"))[
    "resources"
]
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
assert not pcre2.compile(groups["其他节点"]["filter"]).match("Hong Kong 01")
assert pcre2.compile(groups["其他节点"]["filter"]).match("德国 01")
assert groups["FCM"]["policies"][0] == "直连"
assert groups["AI"]["policies"][0] == "美国"


# Verify merge semantics against the unmodified union, including boundaries.
def matches(domain, sources):
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
crypto_original = native_set(
    (root / "source/text/cryptocurrency.txt").read_text(encoding="utf-8").splitlines(),
    "domain",
)
for name, inputs in (("nsfw", [nsfw]), ("cryptocurrency", [crypto_original, web3])):
    samples = set()
    for data in inputs:
        for entries in data.values():
            for entry in entries:
                samples.update(
                    {
                        entry,
                        entry.upper(),
                        "child." + entry,
                        "bad" + entry,
                        entry + ".invalid",
                    }
                )
    for sample in samples:
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
