import json
import re
from pathlib import Path


PLUGIN_CATEGORIES = ("languages", "compilers", "build_systems", "artifacts")


def _read_json(path):
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_rule_pack(path):
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"Rule pack must be a JSON object: {path}")
    return payload


def merge_rule_packs(packs):
    merged = {category: [] for category in PLUGIN_CATEGORIES}
    metadata = []
    for pack in packs:
        if not isinstance(pack, dict):
            continue
        for category in PLUGIN_CATEGORIES:
            entries = pack.get(category, [])
            if isinstance(entries, list):
                merged[category].extend(entries)
        pack_name = pack.get("name") or pack.get("id")
        if pack_name:
            metadata.append(str(pack_name))
    merged["_pack_names"] = metadata
    return merged


def _section_bytes(elf, section_name):
    section = elf.get_section_by_name(section_name)
    if not section:
        return None
    try:
        return section.data().lower()
    except Exception:
        return None


def _collect_haystack(elf, sections):
    if not sections or sections == ["*"] or "*" in sections:
        blobs = []
        for section in elf.iter_sections():
            try:
                blobs.append(section.data().lower())
            except Exception:
                continue
        return b"\n".join(blobs)
    blobs = []
    for name in sections:
        data = _section_bytes(elf, str(name))
        if data:
            blobs.append(data)
    return b"\n".join(blobs)


def _normalize_markers(markers):
    values = []
    for marker in markers or []:
        if marker is None:
            continue
        values.append(str(marker).encode("utf-8", errors="ignore").lower())
    return values


def _rule_match(haystack, rule):
    all_of = _normalize_markers(rule.get("all_of"))
    any_of = _normalize_markers(rule.get("any_of"))
    regex_any = rule.get("regex_any", [])

    if all_of and not all(token in haystack for token in all_of):
        return False
    if any_of and not any(token in haystack for token in any_of):
        return False
    if regex_any:
        matched = False
        for pattern in regex_any:
            try:
                if re.search(pattern, haystack.decode("utf-8", errors="ignore"), flags=re.IGNORECASE):
                    matched = True
                    break
            except re.error:
                continue
        if not matched:
            return False
    return bool(all_of or any_of or regex_any)


def apply_score_rules(elf, scores, rules):
    if not rules:
        return []
    evidence = []
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            continue
        target = rule.get("target")
        if target not in scores:
            continue
        score_delta = int(rule.get("score", 0))
        if score_delta == 0:
            continue

        sections = rule.get("sections", ["*"])
        haystack = _collect_haystack(elf, sections)
        if not haystack:
            continue
        if not _rule_match(haystack, rule):
            continue

        scores[target] = int(scores.get(target, 0)) + score_delta
        evidence.append(
            {
                "rule": rule.get("id", f"rule_{index}"),
                "target": target,
                "score_delta": score_delta,
                "sections": sections,
            }
        )
    return evidence

