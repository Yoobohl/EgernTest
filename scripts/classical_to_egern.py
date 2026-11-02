"""Convert the requested classical domain lists and safely merge native sets."""

from collections.abc import Collection, Mapping
from pathlib import Path
from typing import TypedDict

import yaml
from mrs_to_egern import sha256

# 本模块只合并域名集合，不接受带 no_resolve 的 IP 集合。
DomainSet = dict[str, list[str]]


class SkippedRule(TypedDict):
    """未迁移的规则及其在源文件中的位置。"""

    line: int
    rule: str
    reason: str


class SourceInfo(TypedDict):
    """classical 来源与可迁移条目统计。"""

    source: str
    source_sha256: str
    supported_input_count: int
    skipped: list[SkippedRule]


class MergeStats(TypedDict):
    """合并计数；重复项与父后缀覆盖项分别统计。"""

    input_count: int
    duplicate_count: int
    covered_count: int
    output_count: int


class SupplementalInfo(SourceInfo, MergeStats, total=False):
    """写入 manifest 的补充规则来源和最终统计。"""

    original_mrs_text_count: int


FIELDS = {
    "DOMAIN": "domain_set",
    "DOMAIN-SUFFIX": "domain_suffix_set",
    "DOMAIN-KEYWORD": "domain_keyword_set",
}
SOURCES = {
    name: f"https://raw.githubusercontent.com/Yoobohl/proxy-profiles/main/rules/classical/{name}.list"
    for name in ("nsfw", "web3")
}


def parse_classical(path: Path) -> tuple[DomainSet, SourceInfo]:
    """读取 DOMAIN/SUFFIX/KEYWORD，返回原生域名集合及来源信息。

    进程规则单独记录为 skipped；其他未知语法直接报错，避免静默丢规则。
    域名转为小写，但本步骤保留重复项，留给合并阶段统一统计。
    """
    converted: DomainSet = {}
    skipped: list[SkippedRule] = []
    count = 0
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [value.strip() for value in line.split(",")]
        if len(parts) != 2 or not parts[1]:
            raise ValueError(f"Invalid classical rule at {path}:{number}: {raw}")
        kind, value = parts
        if kind == "PROCESS-NAME":
            skipped.append(
                {
                    "line": number,
                    "rule": line,
                    "reason": "No Egern process rule in official documentation",
                }
            )
            continue
        if kind not in FIELDS:
            raise ValueError(f"Unsupported classical type at {path}:{number}: {kind}")
        converted.setdefault(FIELDS[kind], []).append(value.lower())
        count += 1
    return converted, {
        "source": SOURCES[path.stem],
        "source_sha256": sha256(path),
        "supported_input_count": count,
        "skipped": skipped,
    }


def suffix_covered(
    domain: str, suffixes: Collection[str], proper_only: bool = False
) -> bool:
    """按标签边界检查父后缀覆盖；proper_only=True 时不检查域名自身。

    例如 example.com 覆盖 a.example.com，但不覆盖 badexample.com。
    """
    labels = domain.lower().split(".")
    return any(
        ".".join(labels[index:]) in suffixes
        for index in range(1 if proper_only else 0, len(labels))
    )


def merge_native(
    *sources: Mapping[str, list[str]],
) -> tuple[DomainSet, MergeStats]:
    """合并域名匹配并集，删除同字段重复项及已被父后缀覆盖的条目。

    只移除可证明冗余的精确域名/后缀；关键词的包含关系不作推断。
    输出排序固定，确保重复构建产生相同的 YAML 和统计信息。
    """
    values: dict[str, set[str]] = {}
    count = 0
    for source in sources:
        if set(source) - set(FIELDS.values()):
            raise ValueError("Only domain/exact/suffix/keyword sets can be merged here")
        for field, entries in source.items():
            count += len(entries)
            values.setdefault(field, set()).update(entry.lower() for entry in entries)
    unique_count = sum(len(entries) for entries in values.values())
    suffixes = values.get("domain_suffix_set", set())
    # A suffix already includes itself and all subdomains. Removing covered
    # suffixes or exact entries preserves the union of all input matches.
    values["domain_suffix_set"] = {
        domain
        for domain in suffixes
        if not suffix_covered(domain, suffixes, proper_only=True)
    }
    if "domain_set" in values:
        values["domain_set"] = {
            domain
            for domain in values["domain_set"]
            if not suffix_covered(domain, suffixes)
        }
    result = {
        field: sorted(values[field]) for field in FIELDS.values() if values.get(field)
    }
    output_count = sum(len(entries) for entries in result.values())
    return result, {
        "input_count": count,
        "duplicate_count": count - unique_count,
        "covered_count": unique_count - output_count,
        "output_count": output_count,
    }


def write_set(path: Path, data: Mapping[str, list[str]]) -> None:
    """写出纯域名集合；目标目录由构建流程提前创建。"""
    path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=120),
        encoding="utf-8",
        newline="\n",
    )


def add_supplemental_sets(root: Path) -> dict[str, SupplementalInfo]:
    """从保存的 classical 快照生成 NSFW，并将 Web3 合入基础 Crypto。

    调用前必须先从 MRS 重建 cryptocurrency.yaml，避免把上次合并结果
    当作新输入，导致来源计数失真。返回值用于写入 source/manifest.json。
    """
    directory = root / "rulesets"
    nsfw, nsfw_source = parse_classical(root / "source/classical/nsfw.list")
    web3, web3_source = parse_classical(root / "source/classical/web3.list")
    nsfw_set, nsfw_stats = merge_native(nsfw)
    crypto_original = yaml.safe_load(
        (directory / "cryptocurrency.yaml").read_text(encoding="utf-8")
    )
    crypto_set, crypto_stats = merge_native(crypto_original, web3)
    write_set(directory / "nsfw.yaml", nsfw_set)
    write_set(directory / "cryptocurrency.yaml", crypto_set)
    return {
        "nsfw": {**nsfw_source, **nsfw_stats},
        "cryptocurrency": {
            **web3_source,
            **crypto_stats,
            "original_mrs_text_count": sum(len(v) for v in crypto_original.values()),
        },
    }
