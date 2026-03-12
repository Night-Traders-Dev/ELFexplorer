import json
import re
from pathlib import Path


PLUGIN_CATEGORIES = ("languages", "compilers", "build_systems", "artifacts")
RULE_OPERATIONS = {"add", "set_max"}


def _read_json(path):
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_rule_pack(path):
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"Rule pack must be a JSON object: {path}")
    validated, diagnostics = validate_rule_pack_schema(payload, source=str(path))
    validated["_diagnostics"] = diagnostics
    return validated


def merge_rule_packs(packs):
    merged = {category: [] for category in PLUGIN_CATEGORIES}
    metadata = []
    diagnostics = []
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
        diagnostics.extend(pack.get("_diagnostics", []))
    merged["_pack_names"] = metadata
    merged["_diagnostics"] = diagnostics
    return merged


def _normalize_string_list(value, field_name):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"rule field '{field_name}' must be a list of strings")
    normalized = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"rule field '{field_name}' must contain only strings")
        token = item.strip()
        if token:
            normalized.append(token)
    return normalized


def validate_rule_pack_schema(payload, source="pack"):
    if not isinstance(payload, dict):
        raise ValueError(f"{source}: rule pack payload must be an object")

    validated = {
        "name": payload.get("name", Path(str(source)).stem),
        "id": payload.get("id", payload.get("name", Path(str(source)).stem)),
    }
    diagnostics = []

    seen_rule_ids = set()
    matcher_to_targets = {}

    for category in PLUGIN_CATEGORIES:
        rules = payload.get(category, [])
        if rules is None:
            rules = []
        if not isinstance(rules, list):
            raise ValueError(f"{source}: category '{category}' must be a list")

        validated_rules = []
        for index, rule in enumerate(rules, start=1):
            if not isinstance(rule, dict):
                raise ValueError(f"{source}: {category}[{index}] must be an object")
            target = rule.get("target")
            if not isinstance(target, str) or not target.strip():
                raise ValueError(f"{source}: {category}[{index}] missing non-empty 'target'")
            score = int(rule.get("score", 0))
            if score == 0:
                raise ValueError(f"{source}: {category}[{index}] must have non-zero 'score'")

            all_of = _normalize_string_list(rule.get("all_of"), "all_of")
            any_of = _normalize_string_list(rule.get("any_of"), "any_of")
            regex_any = _normalize_string_list(rule.get("regex_any"), "regex_any")
            sections = _normalize_string_list(rule.get("sections", ["*"]), "sections") or ["*"]
            operation = str(rule.get("operation", "add")).strip().lower()
            if operation not in RULE_OPERATIONS:
                raise ValueError(
                    f"{source}: {category}[{index}] invalid operation '{operation}' "
                    f"(allowed: {', '.join(sorted(RULE_OPERATIONS))})"
                )
            for pattern in regex_any:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(
                        f"{source}: {category}[{index}] invalid regex '{pattern}': {exc}"
                    ) from exc

            if not (all_of or any_of or regex_any):
                raise ValueError(
                    f"{source}: {category}[{index}] must define matcher fields "
                    f"(all_of/any_of/regex_any)"
                )

            rule_id = str(rule.get("id", f"{category}_{index}")).strip()
            if rule_id in seen_rule_ids:
                diagnostics.append(f"{source}: duplicate rule id '{rule_id}' in category '{category}'")
            seen_rule_ids.add(rule_id)

            matcher_signature = (
                tuple(sorted(all_of)),
                tuple(sorted(any_of)),
                tuple(sorted(regex_any)),
                tuple(sorted(sections)),
            )
            previous_targets = matcher_to_targets.setdefault(matcher_signature, set())
            if previous_targets and target not in previous_targets:
                diagnostics.append(
                    f"{source}: possible conflict in category '{category}' for matcher "
                    f"{matcher_signature} targeting {sorted(previous_targets | {target})}"
                )
            previous_targets.add(target)

            validated_rules.append(
                {
                    "id": rule_id,
                    "target": target,
                    "score": score,
                    "all_of": all_of,
                    "any_of": any_of,
                    "regex_any": regex_any,
                    "sections": sections,
                    "priority": int(rule.get("priority", 0)),
                    "operation": operation,
                }
            )
        validated[category] = validated_rules
    return validated, diagnostics


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
    ordered_rules = sorted(
        list(rules),
        key=lambda item: (int(item.get("priority", 0)), int(item.get("score", 0))),
        reverse=True,
    )
    for index, rule in enumerate(ordered_rules, start=1):
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

        operation = str(rule.get("operation", "add")).strip().lower()
        if operation == "set_max":
            scores[target] = max(int(scores.get(target, 0)), score_delta)
        else:
            scores[target] = int(scores.get(target, 0)) + score_delta
        evidence.append(
            {
                "rule": rule.get("id", f"rule_{index}"),
                "target": target,
                "score_delta": score_delta,
                "sections": sections,
                "priority": int(rule.get("priority", 0)),
                "operation": operation,
            }
        )
    return evidence
