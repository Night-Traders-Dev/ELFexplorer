from datetime import datetime, timezone
from pathlib import Path


def _top_scores(scores, limit=8):
    ordered = sorted((scores or {}).items(), key=lambda item: item[1], reverse=True)
    return ordered[:limit]


def report_to_markdown(report):
    scan = report.get("scan_result", {})
    artifact = scan.get("artifact_profile", {})
    generated_at = report.get("generated_at") or datetime.now(timezone.utc).isoformat()

    lines = [
        "# ELFexplorer Scan Report",
        "",
        f"- Generated At: `{generated_at}`",
        f"- Tool Version: `{report.get('version', 'Unknown')}`",
        f"- File: `{report.get('file', 'Unknown')}`",
        f"- Mode: `{report.get('mode', 'general')}`",
        "",
        "## Detection Summary",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Source Language | {scan.get('source_language', 'Unknown')} |",
        f"| Compiler | {scan.get('compiler', 'Unknown')} |",
        f"| Build System | {scan.get('build_system', 'Unknown')} |",
        f"| Artifact Type | {artifact.get('artifact_type', 'Unknown')} |",
        f"| Artifact Confidence | {artifact.get('confidence', 0)} |",
        f"| Target Hint | {artifact.get('target', 'Unknown')} |",
        f"| SDK Hint | {artifact.get('sdk', 'Unknown')} |",
        f"| RTOS Hint | {artifact.get('rtos', 'None detected')} |",
        f"| Runtime Hint | {artifact.get('runtime', 'Unknown')} |",
        f"| Linkage Model | {artifact.get('linkage_model', 'Unknown')} |",
        f"| Loader | {artifact.get('loader', 'None')} |",
        "",
        "## Top Language Scores",
        "",
        "| Label | Score |",
        "| --- | ---: |",
    ]
    for label, value in _top_scores(scan.get("language_scores", {})):
        lines.append(f"| {label} | {value} |")

    lines.extend(
        [
            "",
            "## Top Compiler Scores",
            "",
            "| Label | Score |",
            "| --- | ---: |",
        ]
    )
    for label, value in _top_scores(scan.get("compiler_scores", {})):
        lines.append(f"| {label} | {value} |")

    lines.extend(
        [
            "",
            "## Top Build-System Scores",
            "",
            "| Label | Score |",
            "| --- | ---: |",
        ]
    )
    for label, value in _top_scores(scan.get("build_scores", {})):
        lines.append(f"| {label} | {value} |")

    lines.extend(
        [
            "",
            "## Top Artifact Scores",
            "",
            "| Label | Score |",
            "| --- | ---: |",
        ]
    )
    for label, value in _top_scores(artifact.get("scores", {})):
        lines.append(f"| {label} | {value} |")

    indicators = artifact.get("indicators", [])
    lines.extend(["", "## Artifact Evidence", ""])
    if indicators:
        for indicator in indicators:
            lines.append(f"- {indicator}")
    else:
        lines.append("- No explicit artifact indicators captured.")

    metadata_text = report.get("metadata_text", "").strip()
    lines.extend(["", "## ELF Metadata", ""])
    if metadata_text:
        lines.extend(["```text", metadata_text, "```"])
    else:
        lines.append("_No metadata captured._")

    lines.append("")
    return "\n".join(lines)


def collection_to_markdown(collection_payload):
    reports = collection_payload.get("reports", [])
    generated_at = collection_payload.get("generated_at") or datetime.now(timezone.utc).isoformat()
    lines = [
        "# ELFexplorer Scan Collection",
        "",
        f"- Generated At: `{generated_at}`",
        f"- Report Count: `{len(reports)}`",
        "",
        "## Index",
        "",
        "| # | File | Language | Compiler | Build System | Artifact |",
        "| ---: | --- | --- | --- | --- | --- |",
    ]

    for index, report in enumerate(reports, start=1):
        scan = report.get("scan_result", {})
        artifact = scan.get("artifact_profile", {})
        lines.append(
            "| "
            + f"{index} | {report.get('file', 'Unknown')} | {scan.get('source_language', 'Unknown')} | "
            + f"{scan.get('compiler', 'Unknown')} | {scan.get('build_system', 'Unknown')} | "
            + f"{artifact.get('artifact_type', 'Unknown')} |"
        )

    for index, report in enumerate(reports, start=1):
        lines.extend(["", f"---", "", f"## Report {index}", ""])
        lines.append(report_to_markdown(report))

    lines.append("")
    return "\n".join(lines)


def write_markdown(text, path):
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return out_path


def _write_pdf_from_text(title, text, path):
    try:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer
    except Exception as exc:
        raise RuntimeError(
            "PDF export requires reportlab. Install with: python3 -m pip install reportlab"
        ) from exc

    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    story = [Paragraph(title, styles["Title"]), Spacer(1, 12), Preformatted(text, styles["Code"])]
    doc = SimpleDocTemplate(str(out_path), pagesize=LETTER)
    doc.build(story)
    return out_path


def export_report_markdown(report, path):
    return write_markdown(report_to_markdown(report), path)


def export_collection_markdown(collection_payload, path):
    return write_markdown(collection_to_markdown(collection_payload), path)


def export_report_pdf(report, path):
    return _write_pdf_from_text("ELFexplorer Scan Report", report_to_markdown(report), path)


def export_collection_pdf(collection_payload, path):
    return _write_pdf_from_text(
        "ELFexplorer Scan Collection",
        collection_to_markdown(collection_payload),
        path,
    )

