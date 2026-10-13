"""Convert the requested classical domain lists and safely merge native sets."""

import yaml
from mrs_to_egern import sha256

FIELDS = {
    "DOMAIN": "domain_set",
    "DOMAIN-SUFFIX": "domain_suffix_set",
    "DOMAIN-KEYWORD": "domain_keyword_set",
}
SOURCES = {
    name: f"https://raw.githubusercontent.com/Yoobohl/proxy-profiles/main/rules/classical/{name}.list"
    for name in ("nsfw", "web3")
}


def parse_classical(path):
    converted = {}
    skipped = []
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


def suffix_covered(domain, suffixes, proper_only=False):
    labels = domain.lower().split(".")
    return any(
        ".".join(labels[index:]) in suffixes
        for index in range(1 if proper_only else 0, len(labels))
    )


def merge_native(*sources):
    values = {}
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


def write_set(path, data):
    path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=120),
        encoding="utf-8",
        newline="\n",
    )


def add_supplemental_sets(root):
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
