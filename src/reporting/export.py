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


def _summary_table_rows(report):
    scan = report.get("scan_result", {})
    artifact = scan.get("artifact_profile", {})
    return [
        ("File", report.get("file", "Unknown")),
        ("Mode", report.get("mode", "general")),
        ("Generated At", report.get("generated_at", "Unknown")),
        ("Tool Version", report.get("version", "Unknown")),
        ("Source Language", scan.get("source_language", "Unknown")),
        ("Compiler", scan.get("compiler", "Unknown")),
        ("Build System", scan.get("build_system", "Unknown")),
        ("Artifact Type", artifact.get("artifact_type", "Unknown")),
        ("Artifact Confidence", str(artifact.get("confidence", 0))),
        ("Target Hint", artifact.get("target", "Unknown")),
        ("SDK Hint", artifact.get("sdk", "Unknown")),
        ("RTOS Hint", artifact.get("rtos", "None detected")),
        ("Runtime Hint", artifact.get("runtime", "Unknown")),
        ("Linkage Model", artifact.get("linkage_model", "Unknown")),
        ("Loader", artifact.get("loader", "None")),
    ]


def _render_report_pdf(report, path):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception as exc:
        raise RuntimeError(
            "PDF export requires reportlab. Install with: python3 -m pip install reportlab"
        ) from exc

    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(out_path), pagesize=LETTER)
    scan = report.get("scan_result", {})
    artifact = scan.get("artifact_profile", {})

    story = [Paragraph("ELFexplorer Scan Report", styles["Title"]), Spacer(1, 10)]
    story.append(Paragraph("Detection Summary", styles["Heading2"]))

    summary_rows = [["Field", "Value"]]
    summary_rows.extend(_summary_table_rows(report))
    summary_table = Table(summary_rows, colWidths=[170, 360])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.HexColor("#eef2ff")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    for title, scores in (
        ("Top Language Scores", scan.get("language_scores", {})),
        ("Top Compiler Scores", scan.get("compiler_scores", {})),
        ("Top Build-System Scores", scan.get("build_scores", {})),
        ("Top Artifact Scores", artifact.get("scores", {})),
    ):
        story.append(Paragraph(title, styles["Heading3"]))
        rows = [["Label", "Score"]]
        rows.extend([[label, str(value)] for label, value in _top_scores(scores)])
        score_table = Table(rows, colWidths=[430, 100])
        score_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#99f6e4")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0fdfa")]),
                    ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ]
            )
        )
        story.append(score_table)
        story.append(Spacer(1, 8))

    story.append(Paragraph("Artifact Evidence", styles["Heading3"]))
    indicators = artifact.get("indicators", [])
    if indicators:
        for indicator in indicators:
            story.append(Paragraph(f"• {indicator}", styles["BodyText"]))
    else:
        story.append(Paragraph("No explicit artifact indicators captured.", styles["BodyText"]))
    story.append(Spacer(1, 10))

    metadata = report.get("metadata_text", "").strip()
    story.append(Paragraph("ELF Metadata", styles["Heading3"]))
    story.append(Preformatted(metadata or "No metadata captured.", styles["Code"]))
    doc.build(story)
    return out_path


def _render_collection_pdf(collection_payload, path):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception as exc:
        raise RuntimeError(
            "PDF export requires reportlab. Install with: python3 -m pip install reportlab"
        ) from exc

    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(out_path), pagesize=LETTER)
    reports = collection_payload.get("reports", [])

    story = [
        Paragraph("ELFexplorer Scan Collection", styles["Title"]),
        Spacer(1, 10),
        Paragraph(
            f"Generated At: {collection_payload.get('generated_at', datetime.now(timezone.utc).isoformat())}",
            styles["BodyText"],
        ),
        Paragraph(f"Report Count: {len(reports)}", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Collection Index", styles["Heading2"]),
    ]

    index_rows = [["#", "File", "Language", "Compiler", "Build System", "Artifact"]]
    for index, report in enumerate(reports, start=1):
        scan = report.get("scan_result", {})
        artifact = scan.get("artifact_profile", {})
        index_rows.append(
            [
                str(index),
                report.get("file", "Unknown"),
                scan.get("source_language", "Unknown"),
                scan.get("compiler", "Unknown"),
                scan.get("build_system", "Unknown"),
                artifact.get("artifact_type", "Unknown"),
            ]
        )

    if len(index_rows) == 1:
        index_rows.append(["-", "No reports", "-", "-", "-", "-"])

    index_table = Table(index_rows, colWidths=[30, 210, 70, 70, 90, 70])
    index_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(index_table)

    for index, report in enumerate(reports, start=1):
        scan = report.get("scan_result", {})
        artifact = scan.get("artifact_profile", {})
        story.extend(
            [
                PageBreak(),
                Paragraph(f"Report {index}", styles["Heading1"]),
                Paragraph(report.get("file", "Unknown"), styles["Heading3"]),
                Spacer(1, 8),
            ]
        )
        summary_rows = [["Field", "Value"]]
        summary_rows.extend(_summary_table_rows(report))
        table = Table(summary_rows, colWidths=[170, 360])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 8))

        story.append(Paragraph("Top Language Scores", styles["Heading3"]))
        lang_rows = [["Label", "Score"]]
        lang_rows.extend([[label, str(score)] for label, score in _top_scores(scan.get("language_scores", {}))])
        lang_table = Table(lang_rows, colWidths=[430, 100])
        lang_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0369a1")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bae6fd")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f9ff")]),
                    ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ]
            )
        )
        story.append(lang_table)
        story.append(Spacer(1, 8))

        for title, scores, color_hex, grid_hex, row_hex in (
            ("Top Compiler Scores", scan.get("compiler_scores", {}), "#0f766e", "#99f6e4", "#f0fdfa"),
            ("Top Build-System Scores", scan.get("build_scores", {}), "#7c2d12", "#fdba74", "#fff7ed"),
            ("Top Artifact Scores", artifact.get("scores", {}), "#4c1d95", "#c4b5fd", "#f5f3ff"),
        ):
            story.append(Paragraph(title, styles["Heading3"]))
            rows = [["Label", "Score"]]
            rows.extend([[label, str(score)] for label, score in _top_scores(scores)])
            table = Table(rows, colWidths=[430, 100])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(color_hex)),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(grid_hex)),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(row_hex)]),
                        ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 8))

        story.append(Paragraph("Artifact Evidence", styles["Heading3"]))
        indicators = artifact.get("indicators", [])
        if indicators:
            for indicator in indicators:
                story.append(Paragraph(f"• {indicator}", styles["BodyText"]))
        else:
            story.append(Paragraph("No explicit artifact indicators captured.", styles["BodyText"]))
        story.append(Spacer(1, 8))

        metadata = report.get("metadata_text", "").strip() or "No metadata captured."
        story.append(Paragraph("ELF Metadata", styles["Heading3"]))
        story.append(Preformatted(metadata, styles["Code"]))

    doc.build(story)
    return out_path


def export_report_markdown(report, path):
    return write_markdown(report_to_markdown(report), path)


def export_collection_markdown(collection_payload, path):
    return write_markdown(collection_to_markdown(collection_payload), path)


def export_report_pdf(report, path):
    return _render_report_pdf(report, path)


def export_collection_pdf(collection_payload, path):
    return _render_collection_pdf(collection_payload, path)
