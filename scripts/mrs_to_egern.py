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
from pathlib import Path
from typing import Any

import yaml
import zstandard

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MIHOMO = ROOT / ".cache/mihomo-v1.19.32/mihomo-windows-amd64-v1.exe"
VERSION = "v1.19.32"


def check_version(mihomo):
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


def read_header(path):
    with (
        path.open("rb") as stream,
        zstandard.ZstdDecompressor().stream_reader(stream) as reader,
    ):
        header = reader.read(21)
    if len(header) != 21 or header[:4] != b"MRS\x01":
        raise ValueError(f"Not an MRS v1 file: {path}")
    behavior = {0: "domain", 1: "ipcidr"}.get(header[4])
    if behavior is None:
        raise ValueError(f"Unsupported MRS behavior: {header[4]}")
    count, extra_length = struct.unpack_from(">qq", header, 5)
    if count <= 0 or extra_length < 0:
        raise ValueError(f"Invalid MRS header: {path}")
    return behavior, count


def dump_mrs(path, target, mihomo=DEFAULT_MIHOMO, behavior=None):
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


def domain_pattern(domain):
    prefix = ""
    if domain.startswith("+."):
        prefix, domain = r"(?:[^.]+\.)*", domain[2:]
    elif domain.startswith("."):
        prefix, domain = r"(?:[^.]+\.)+", domain[1:]
    return prefix + r"\.".join(
        "[^.]+" if label == "*" else re.escape(label) for label in domain.split(".")
    )


def native_set(entries, behavior, no_resolve=False):
    if behavior not in {"domain", "ipcidr"}:
        raise ValueError(f"Unsupported behavior: {behavior}")
    if no_resolve and behavior != "ipcidr":
        raise ValueError("no_resolve only applies to IP rule sets")
    result: dict[str, Any] = {"no_resolve": True} if no_resolve else {}
    seen = set()
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


def write_native(path, entries, behavior, no_resolve=False):
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


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
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
