"""MRS -> mihomo v1.19.32 DumpMrs text -> native Egern YAML.

The first stage calls the official implementation of mrs_converter.go rather
than interpreting the binary trie or CIDR range layout in Python.
"""

import argparse
import hashlib
import ipaddress
import re
import struct
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

import yaml
import zstandard

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MIHOMO = ROOT / ".cache/mihomo-v1.19.32/mihomo-windows-amd64-v1.exe"
VERSION = "v1.19.32"

# MRS 的头部只区分域名和 IP 两种行为；IP 的版本在读取 CIDR 时判断。
Behavior = Literal["domain", "ipcidr"]
# Egern 原生集合包含字符串列表，以及可选的布尔字段 no_resolve。
# 动态字段名在 native_set 中集中构造，调用方不直接解释 MRS 二进制。
NativeRuleSet = dict[str, Any]


def check_version(mihomo: Path) -> str:
    """检查官方转换器版本，返回完整版本字符串；不匹配时拒绝转换。"""
    result = subprocess.run(
        [str(mihomo), "-v"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    if not re.search(r"\bv1\.19\.32\b", result.stdout):
        raise ValueError(f"Expected mihomo {VERSION}: {result.stdout.strip()}")
    return result.stdout.strip()


def read_header(path: Path) -> tuple[Behavior, int]:
    """读取压缩流头部，返回规则行为和 MRS 插入计数，不解码规则内容。"""
    with (
        path.open("rb") as stream,
        zstandard.ZstdDecompressor().stream_reader(stream) as reader,
    ):
        header = reader.read(21)
    if len(header) != 21 or header[:4] != b"MRS\x01":
        raise ValueError(f"Not an MRS v1 file: {path}")
    # 解压后的固定头为 magic(4) + behavior(1) + count(8) + extra_length(8)。
    # 两个计数字段采用大端、有符号 64 位整数；后续内容交给 mihomo 解释。
    behaviors: dict[int, Behavior] = {0: "domain", 1: "ipcidr"}
    behavior = behaviors.get(header[4])
    if behavior is None:
        raise ValueError(f"Unsupported MRS behavior: {header[4]}")
    count, extra_length = struct.unpack_from(">qq", header, 5)
    if count <= 0 or extra_length < 0:
        raise ValueError(f"Invalid MRS header: {path}")
    return behavior, count


def dump_mrs(
    path: Path,
    target: Path,
    mihomo: Path = DEFAULT_MIHOMO,
    behavior: str | None = None,
) -> tuple[list[str], Behavior, int]:
    """调用官方 DumpMrs，写入文本并返回条目、实际行为和原始插入计数。

    插入计数可以大于导出条目数，因为官方实现会合并重复域名或 IP 范围。
    behavior 只用于核对调用方预期；实际转换类型始终取自文件头。
    """
    actual_behavior, count = read_header(path)
    if behavior is not None and behavior != actual_behavior:
        raise ValueError(
            f"MRS behavior mismatch: expected {behavior}, got {actual_behavior}"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            str(mihomo),
            "convert-ruleset",
            actual_behavior,
            "mrs",
            str(path),
            str(target),
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    entries = target.read_text(encoding="utf-8").splitlines()
    if not entries or any(not entry for entry in entries):
        raise ValueError(f"Invalid or empty DumpMrs output: {target}")
    return entries, actual_behavior, count


def domain_pattern(domain: str) -> str:
    r"""将 mihomo 域名模式转换为不带锚点的正则。

    +.example.com 包含根域及子域，.example.com 仅包含子域；
    单个 * 只匹配一个非空标签，因此不能直接替换为 .*。
    """
    prefix = ""
    if domain.startswith("+."):
        prefix, domain = r"(?:[^.]+\.)*", domain[2:]
    elif domain.startswith("."):
        prefix, domain = r"(?:[^.]+\.)+", domain[1:]
    return prefix + r"\.".join(
        "[^.]+" if label == "*" else re.escape(label) for label in domain.split(".")
    )


def native_set(
    entries: Iterable[str], behavior: str, no_resolve: bool = False
) -> NativeRuleSet:
    """按 Egern 字段分类官方文本条目，保留首次出现顺序并去重。

    精确域名和普通后缀使用原生集合；带通配符的条目使用完整匹配正则。
    no_resolve 只适用于 IP 集合，表示规则匹配时不额外触发 DNS 解析。
    """
    if behavior not in {"domain", "ipcidr"}:
        raise ValueError(f"Unsupported behavior: {behavior}")
    if no_resolve and behavior != "ipcidr":
        raise ValueError("no_resolve only applies to IP rule sets")
    result: NativeRuleSet = {"no_resolve": True} if no_resolve else {}
    seen: set[str] = set()
    for entry in entries:
        if entry in seen:
            continue
        seen.add(entry)
        if behavior == "ipcidr":
            network = ipaddress.ip_network(entry, strict=True)
            kind = "ip_cidr6_set" if network.version == 6 else "ip_cidr_set"
            value = str(network)
        elif entry.startswith("+.") and "*" not in entry:
            kind, value = "domain_suffix_set", entry[2:]
        elif not entry.startswith(".") and "*" not in entry:
            kind, value = "domain_set", entry
        else:
            kind, value = "domain_regex_set", "(?i)^" + domain_pattern(entry) + "$"
        result.setdefault(kind, []).append(value)
    return result


def write_native(
    path: Path,
    entries: Iterable[str],
    behavior: str,
    no_resolve: bool = False,
) -> None:
    """创建目标目录并写出 UTF-8/LF 的 Egern 原生规则集。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            native_set(entries, behavior, no_resolve),
            allow_unicode=True,
            sort_keys=False,
            width=120,
        ),
        encoding="utf-8",
        newline="\n",
    )


def sha256(path: Path) -> str:
    """计算文件字节的 SHA256，用于快照和生成物的完整性核对。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    """解析单文件转换参数，防止输入、文本和 YAML 输出互相覆盖。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--text-output", type=Path)
    parser.add_argument("--mihomo", type=Path, default=DEFAULT_MIHOMO)
    parser.add_argument("--behavior", choices=["domain", "ipcidr"])
    parser.add_argument("--no-resolve", action="store_true")
    args = parser.parse_args()
    version = check_version(args.mihomo)
    text_path = args.text_output or args.output.with_suffix(".txt")
    if args.source.resolve() in {args.output.resolve(), text_path.resolve()}:
        parser.error("Output paths must not overwrite the source MRS")
    if args.output.resolve() == text_path.resolve():
        parser.error("YAML and text output paths must differ")
    entries, behavior, count = dump_mrs(
        args.source, text_path, args.mihomo, args.behavior
    )
    write_native(args.output, entries, behavior, args.no_resolve)
    print(
        f"{version}\n{behavior}: {count} MRS insertions -> {len(entries)} text entries "
        f"-> {args.output}"
    )


if __name__ == "__main__":
    main()
