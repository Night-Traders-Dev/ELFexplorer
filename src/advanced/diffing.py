from datetime import datetime, timezone


def _score_deltas(a, b):
    labels = sorted(set((a or {}).keys()) | set((b or {}).keys()))
    deltas = []
    for label in labels:
        before = int((a or {}).get(label, 0))
        after = int((b or {}).get(label, 0))
        if before == after:
            continue
        deltas.append({"label": label, "before": before, "after": after, "delta": after - before})
    deltas.sort(key=lambda item: abs(item["delta"]), reverse=True)
    return deltas


def compare_reports(report_a, report_b):
    scan_a = report_a.get("scan_result", {})
    scan_b = report_b.get("scan_result", {})
    artifact_a = scan_a.get("artifact_profile", {})
    artifact_b = scan_b.get("artifact_profile", {})

    summary = {
        "language": [scan_a.get("source_language", "Unknown"), scan_b.get("source_language", "Unknown")],
        "compiler": [scan_a.get("compiler", "Unknown"), scan_b.get("compiler", "Unknown")],
        "build_system": [scan_a.get("build_system", "Unknown"), scan_b.get("build_system", "Unknown")],
        "artifact_type": [artifact_a.get("artifact_type", "Unknown"), artifact_b.get("artifact_type", "Unknown")],
        "artifact_confidence": [artifact_a.get("confidence", 0), artifact_b.get("confidence", 0)],
    }

    indicator_a = set(artifact_a.get("indicators", []))
    indicator_b = set(artifact_b.get("indicators", []))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "left_file": report_a.get("file", "unknown"),
        "right_file": report_b.get("file", "unknown"),
        "summary": summary,
        "language_deltas": _score_deltas(scan_a.get("language_scores", {}), scan_b.get("language_scores", {})),
        "compiler_deltas": _score_deltas(scan_a.get("compiler_scores", {}), scan_b.get("compiler_scores", {})),
        "build_deltas": _score_deltas(scan_a.get("build_scores", {}), scan_b.get("build_scores", {})),
        "artifact_deltas": _score_deltas(artifact_a.get("scores", {}), artifact_b.get("scores", {})),
        "indicator_added": sorted(indicator_b - indicator_a),
        "indicator_removed": sorted(indicator_a - indicator_b),
    }


def render_diff_plain(diff):
    lines = [
        "Binary Diff Report",
        f"  left:  {diff.get('left_file')}",
        f"  right: {diff.get('right_file')}",
        "",
        "Summary changes:",
    ]
    summary = diff.get("summary", {})
    for field in ("language", "compiler", "build_system", "artifact_type", "artifact_confidence"):
        before, after = summary.get(field, ["Unknown", "Unknown"])
        marker = "==" if before == after else "->"
        lines.append(f"  {field}: {before} {marker} {after}")

    for title, key in (
        ("Language score deltas", "language_deltas"),
        ("Compiler score deltas", "compiler_deltas"),
        ("Build-system score deltas", "build_deltas"),
        ("Artifact score deltas", "artifact_deltas"),
    ):
        lines.append("")
        lines.append(f"{title}:")
        entries = diff.get(key, [])
        if not entries:
            lines.append("  (no changes)")
            continue
        for item in entries[:12]:
            lines.append(
                f"  {item['label']}: {item['before']} -> {item['after']} (delta {item['delta']:+d})"
            )

    added = diff.get("indicator_added", [])
    removed = diff.get("indicator_removed", [])
    lines.append("")
    lines.append("Artifact indicators added:")
    lines.extend([f"  + {line}" for line in added] or ["  (none)"])
    lines.append("Artifact indicators removed:")
    lines.extend([f"  - {line}" for line in removed] or ["  (none)"])
    return "\n".join(lines)


def diff_to_markdown(diff):
    summary = diff.get("summary", {})
    lines = [
        "# ELFexplorer Binary Diff Report",
        "",
        f"- Generated At: `{diff.get('generated_at', '')}`",
        f"- Left File: `{diff.get('left_file', '')}`",
        f"- Right File: `{diff.get('right_file', '')}`",
        "",
        "## Summary Changes",
        "",
        "| Field | Left | Right |",
        "| --- | --- | --- |",
    ]
    for field in ("language", "compiler", "build_system", "artifact_type", "artifact_confidence"):
        before, after = summary.get(field, ["Unknown", "Unknown"])
        lines.append(f"| {field} | {before} | {after} |")

    def _append_delta_table(title, key):
        lines.extend(["", f"## {title}", "", "| Label | Before | After | Delta |", "| --- | ---: | ---: | ---: |"])
        entries = diff.get(key, [])
        if not entries:
            lines.append("| (none) | 0 | 0 | 0 |")
            return
        for item in entries[:20]:
            lines.append(
                f"| {item['label']} | {item['before']} | {item['after']} | {item['delta']:+d} |"
            )

    _append_delta_table("Language Score Deltas", "language_deltas")
    _append_delta_table("Compiler Score Deltas", "compiler_deltas")
    _append_delta_table("Build-System Score Deltas", "build_deltas")
    _append_delta_table("Artifact Score Deltas", "artifact_deltas")

    lines.extend(["", "## Artifact Indicators Added", ""])
    lines.extend([f"- {line}" for line in diff.get("indicator_added", [])] or ["- (none)"])
    lines.extend(["", "## Artifact Indicators Removed", ""])
    lines.extend([f"- {line}" for line in diff.get("indicator_removed", [])] or ["- (none)"])
    lines.append("")
    return "\n".join(lines)

