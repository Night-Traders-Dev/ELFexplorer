from __future__ import annotations

import html
import json
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from advanced.diffing import compare_reports, diff_to_markdown
from version import get_version


APP_NAME = "ELFexplorer"


WEB_THEME_OPTIONS = {
    "forge": {
        "label": "Forge",
        "primary": "#ff8a3d",
        "secondary": "#ffb866",
        "accent": "#f4a261",
        "background": "#0f1115",
        "surface": "#171b22",
        "panel": "#202631",
        "text": "#f3efe8",
        "muted": "#b6b9c3",
    },
    "oceanic": {
        "label": "Oceanic",
        "primary": "#38bdf8",
        "secondary": "#67e8f9",
        "accent": "#2dd4bf",
        "background": "#07131d",
        "surface": "#0f1e29",
        "panel": "#162838",
        "text": "#eaf7ff",
        "muted": "#aac3d8",
    },
    "verdant": {
        "label": "Verdant",
        "primary": "#52b788",
        "secondary": "#95d5b2",
        "accent": "#74c69d",
        "background": "#07140f",
        "surface": "#0e1d17",
        "panel": "#152820",
        "text": "#eefbf5",
        "muted": "#b6d1c3",
    },
    "graphite": {
        "label": "Graphite",
        "primary": "#cba6f7",
        "secondary": "#89b4fa",
        "accent": "#f9e2af",
        "background": "#0b0c10",
        "surface": "#151821",
        "panel": "#1d2230",
        "text": "#edf2f7",
        "muted": "#adb7c6",
    },
}


class DashboardRuntime:
    def __init__(self, callbacks=None, initial_reports=None):
        self.callbacks = callbacks or {}
        self.reports = list(initial_reports or [])
        self.message = "Dashboard ready."
        self.active_diff = None

    def _callback(self, name):
        value = self.callbacks.get(name)
        return value if callable(value) else None

    def _collection_payload(self):
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(self.reports),
            "reports": list(self.reports),
        }

    def capabilities(self):
        return {
            "scan": bool(self._callback("scan")),
            "crawl": bool(self._callback("crawl")),
            "load_scan": bool(self._callback("load_scan")),
            "load_collection": bool(self._callback("load_collection")),
            "list_saved": bool(self._callback("list_saved")),
            "export_md": bool(self._callback("export_report_md")),
            "export_pdf": bool(self._callback("export_report_pdf")),
            "save_scan": bool(self._callback("save_scan")),
            "save_collection": bool(self._callback("save_collection")),
            "export_collection_md": bool(self._callback("export_collection_md")),
            "export_collection_pdf": bool(self._callback("export_collection_pdf")),
            "tool_plugins": bool(self._callback("list_tool_plugins"))
            and bool(self._callback("export_tool_plugin")),
            "tooling": bool(self._callback("tooling_snapshot")),
            "tool_runner": bool(self._callback("tool_recommendations"))
            and bool(self._callback("tool_execute")),
            "diff": bool(self._callback("scan")),
        }

    def _list_saved(self):
        callback = self._callback("list_saved")
        if not callback:
            return []
        return [str(item) for item in callback()]

    def state(self, message=None):
        reports = list(self.reports)
        summaries = [_report_summary(report, index) for index, report in enumerate(reports)]
        return {
            "app_name": APP_NAME,
            "version": get_version(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "message": message if message is not None else self.message,
            "report_count": len(reports),
            "selected_index": 0 if reports else None,
            "reports": reports,
            "summaries": summaries,
            "saved_reports": self._list_saved(),
            "capabilities": self.capabilities(),
            "web_themes": WEB_THEME_OPTIONS,
            "tool_plugin_formats": self._tool_plugin_formats(),
            "active_diff": self.active_diff,
        }

    def replace_reports(self, reports, message):
        self.reports = list(reports)
        self.message = message
        self.active_diff = None
        return self.state()

    def scan(self, path, mode):
        callback = self._callback("scan")
        if not callback:
            raise RuntimeError("Scan action is unavailable in this dashboard context.")
        report = callback(path, mode)
        return self.replace_reports([report], f"Scanned {path} using mode '{mode}'.")

    def crawl(self, path, mode, recursive=True, max_files=None):
        callback = self._callback("crawl")
        if not callback:
            raise RuntimeError("Crawl action is unavailable in this dashboard context.")
        reports = callback(path, mode, recursive=recursive, max_files=max_files)
        return self.replace_reports(reports, f"Scanned {len(reports)} supported file(s) under {path}.")

    def load_scan(self, path):
        callback = self._callback("load_scan")
        if not callback:
            raise RuntimeError("Load-scan action is unavailable in this dashboard context.")
        report = callback(path)
        return self.replace_reports([report], f"Loaded saved scan {path}.")

    def load_collection(self, path):
        callback = self._callback("load_collection")
        if not callback:
            raise RuntimeError("Load-collection action is unavailable in this dashboard context.")
        payload = callback(path)
        reports = payload.get("reports", [])
        return self.replace_reports(reports, f"Loaded collection {path} with {len(reports)} report(s).")

    def save_report(self, index, path=None):
        callback = self._callback("save_scan")
        if not callback:
            raise RuntimeError("Save-scan action is unavailable in this dashboard context.")
        report = self.get_report(index)
        saved = callback(report, path=path)
        self.message = f"Saved report JSON: {saved}"
        return {"ok": True, "path": str(saved), "message": self.message}

    def save_collection(self, path=None):
        callback = self._callback("save_collection")
        if not callback:
            raise RuntimeError("Save-collection action is unavailable in this dashboard context.")
        saved = callback(self.reports, path=path)
        self.message = f"Saved collection JSON: {saved}"
        return {"ok": True, "path": str(saved), "message": self.message}

    def export_report(self, index, export_format, path=None):
        report = self.get_report(index)
        if export_format == "markdown":
            callback = self._callback("export_report_md")
            extension = ".md"
        elif export_format == "pdf":
            callback = self._callback("export_report_pdf")
            extension = ".pdf"
        else:
            raise RuntimeError(f"Unsupported export format '{export_format}'.")
        if not callback:
            raise RuntimeError(f"Export action '{export_format}' is unavailable in this dashboard context.")
        target = Path(path).expanduser() if path else _default_export_path(report, extension)
        exported = callback(report, target)
        self.message = f"Exported {export_format.upper()} report: {exported}"
        return {"ok": True, "path": str(exported), "message": self.message}

    def export_collection(self, export_format, path):
        payload = self._collection_payload()
        if export_format == "markdown":
            callback = self._callback("export_collection_md")
        elif export_format == "pdf":
            callback = self._callback("export_collection_pdf")
        else:
            raise RuntimeError(f"Unsupported collection export format '{export_format}'.")
        if not callback:
            raise RuntimeError(
                f"Collection export action '{export_format}' is unavailable in this dashboard context."
            )
        exported = callback(payload, Path(path).expanduser())
        self.message = f"Exported collection {export_format.upper()}: {exported}"
        return {"ok": True, "path": str(exported), "message": self.message}

    def _tool_plugin_formats(self):
        callback = self._callback("list_tool_plugins")
        return callback() if callback else {}

    def export_tool_plugin(self, index, tool_format, path=None):
        report = self.get_report(index)
        default_path_callback = self._callback("default_tool_plugin_path")
        export_callback = self._callback("export_tool_plugin")
        if not export_callback:
            raise RuntimeError("Tool-plugin export is unavailable in this dashboard context.")
        target = Path(path).expanduser() if path else default_path_callback(report, tool_format)
        exported = export_callback(report, target, tool_format)
        self.message = f"Exported {tool_format} integration artifact: {exported}"
        return {"ok": True, "path": str(exported), "message": self.message}

    def tooling_status(self):
        callback = self._callback("tooling_snapshot")
        if not callback:
            raise RuntimeError("Tooling status is unavailable in this dashboard context.")
        return callback()

    def tooling_detail(self, tool_key):
        callback = self._callback("tooling_detail")
        if not callback:
            raise RuntimeError("Tooling detail is unavailable in this dashboard context.")
        return callback(tool_key)

    def tool_recommendations(self, index):
        callback = self._callback("tool_recommendations")
        if not callback:
            raise RuntimeError("Tool recommendations are unavailable in this dashboard context.")
        report = self.get_report(index)
        return callback(report)

    def tool_execute(self, index, tool_key, action="run", preset_key=None, args=None, dry_run=False):
        callback = self._callback("tool_execute")
        if not callback:
            raise RuntimeError("Tool execution is unavailable in this dashboard context.")
        report = self.get_report(index)
        result = callback(
            report,
            tool_key,
            action=action,
            preset_key=preset_key,
            args=args,
            dry_run=dry_run,
        )
        message = result.get("message")
        if message:
            self.message = message
        return result

    def compare_with(self, index, other_path, mode="general"):
        report = self.get_report(index)
        scan_callback = self._callback("scan")
        if not scan_callback:
            raise RuntimeError("Diff action is unavailable in this dashboard context.")
        other_report = scan_callback(other_path, mode)
        self.active_diff = compare_reports(report, other_report)
        self.message = f"Compared {report.get('file')} against {other_path}."
        return {"ok": True, "diff": self.active_diff, "message": self.message}

    def export_diff_markdown(self, path):
        if not self.active_diff:
            raise RuntimeError("No active diff is available to export.")
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(diff_to_markdown(self.active_diff), encoding="utf-8")
        self.message = f"Exported diff Markdown: {target}"
        return {"ok": True, "path": str(target), "message": self.message}

    def get_report(self, index):
        if index is None:
            raise RuntimeError("No report is selected.")
        try:
            numeric_index = int(index)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Invalid report index.") from exc
        if numeric_index < 0 or numeric_index >= len(self.reports):
            raise RuntimeError("Selected report index is out of range.")
        return self.reports[numeric_index]


def _report_summary(report, index):
    scan = report.get("scan_result", {})
    artifact = scan.get("artifact_profile", {})
    return {
        "index": index,
        "file": str(report.get("file", "Unknown")),
        "mode": str(report.get("mode", "general")),
        "language": str(scan.get("source_language", "Unknown")),
        "compiler": str(scan.get("compiler", "Unknown")),
        "build_system": str(scan.get("build_system", "Unknown")),
        "artifact_type": str(artifact.get("artifact_type", "Unknown")),
        "confidence": artifact.get("confidence", 0),
    }


def _default_export_path(report, extension):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    source = Path(str(report.get("file", "scan")))
    stem = source.stem or "scan"
    safe_stem = "".join(ch if (ch.isalnum() or ch in {"-", "_"}) else "_" for ch in stem)
    output_dir = Path.cwd() / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"{safe_stem}-web-{timestamp}{extension}"


def _json_text(payload):
    return json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")


def build_dashboard_html(initial_state):
    payload = _json_text(initial_state)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{APP_NAME} Web Dashboard</title>
  <style>
    :root {{
      color-scheme: dark;
      --primary: #ff8a3d;
      --secondary: #ffb866;
      --accent: #f4a261;
      --bg: #0f1115;
      --surface: #171b22;
      --panel: #202631;
      --text: #f3efe8;
      --muted: #b6b9c3;
      --border: rgba(255,255,255,0.08);
      --success: #5bd09d;
      --shadow: 0 14px 36px rgba(0,0,0,0.24);
      --radius: 18px;
    }}
    [data-theme="oceanic"] {{
      --primary: #38bdf8; --secondary: #67e8f9; --accent: #2dd4bf; --bg: #07131d; --surface: #0f1e29; --panel: #162838; --text: #eaf7ff; --muted: #aac3d8;
    }}
    [data-theme="verdant"] {{
      --primary: #52b788; --secondary: #95d5b2; --accent: #74c69d; --bg: #07140f; --surface: #0e1d17; --panel: #152820; --text: #eefbf5; --muted: #b6d1c3;
    }}
    [data-theme="graphite"] {{
      --primary: #cba6f7; --secondary: #89b4fa; --accent: #f9e2af; --bg: #0b0c10; --surface: #151821; --panel: #1d2230; --text: #edf2f7; --muted: #adb7c6;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "IBM Plex Sans", "Fira Sans", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, color-mix(in srgb, var(--primary) 16%, transparent), transparent 30%),
        radial-gradient(circle at top right, color-mix(in srgb, var(--accent) 14%, transparent), transparent 24%),
        linear-gradient(180deg, color-mix(in srgb, var(--bg) 92%, #000), var(--bg));
    }}
    .shell {{
      display: grid;
      grid-template-columns: 360px minmax(0, 1fr);
      min-height: 100vh;
      gap: 24px;
      padding: 24px;
    }}
    .sidebar, .main {{ display: flex; flex-direction: column; gap: 18px; }}
    .card {{
      background: linear-gradient(180deg, color-mix(in srgb, var(--surface) 92%, #fff 3%), var(--panel));
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
      contain: layout paint style;
    }}
    .render-card {{ content-visibility: auto; }}
    .hero {{ padding: 24px; position: relative; }}
    .hero::after {{
      content: "";
      position: absolute;
      inset: auto -20% -50% auto;
      width: 220px;
      height: 220px;
      background: radial-gradient(circle, color-mix(in srgb, var(--primary) 18%, transparent), transparent 70%);
      pointer-events: none;
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 6px 12px;
      border-radius: 999px;
      background: color-mix(in srgb, var(--panel) 80%, #fff 3%);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}
    .hero h1 {{
      font-family: "Space Grotesk", "Avenir Next", "Segoe UI", sans-serif;
      font-size: clamp(2rem, 3vw, 3rem);
      line-height: 1.05;
      margin: 16px 0 10px;
    }}
    .hero p {{ margin: 0; color: var(--muted); max-width: 60ch; line-height: 1.6; }}
    .hero-actions {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 18px; align-items: center; }}
    .theme-select, input, select, button, textarea {{
      font: inherit;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: color-mix(in srgb, var(--surface) 92%, #fff 2%);
      color: var(--text);
    }}
    .theme-select, input, select {{ width: 100%; padding: 11px 13px; }}
    textarea {{ width: 100%; min-height: 120px; padding: 11px 13px; resize: vertical; }}
    button {{
      padding: 11px 14px;
      cursor: pointer;
      transition: transform 120ms ease, background 120ms ease, border-color 120ms ease;
      background: linear-gradient(180deg, color-mix(in srgb, var(--surface) 70%, var(--primary) 15%), color-mix(in srgb, var(--panel) 85%, #000));
    }}
    button:hover {{ transform: translateY(-1px); border-color: color-mix(in srgb, var(--primary) 40%, var(--border)); }}
    button.primary {{ background: linear-gradient(180deg, color-mix(in srgb, var(--primary) 88%, #fff 5%), color-mix(in srgb, var(--primary) 72%, #000 12%)); color: #fff; border-color: transparent; }}
    button.ghost {{ background: transparent; }}
    button:disabled {{ opacity: 0.45; cursor: not-allowed; transform: none; }}
    .section {{ padding: 18px 18px 20px; }}
    .section h2, .section h3 {{ margin: 0 0 12px; font-family: "Space Grotesk", "Avenir Next", sans-serif; }}
    .section h2 {{ font-size: 1rem; letter-spacing: 0.03em; }}
    .form-grid {{ display: grid; gap: 10px; }}
    .inline-grid {{ display: grid; gap: 10px; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }}
    .muted {{ color: var(--muted); }}
    .status-bar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 14px 18px;
      background: color-mix(in srgb, var(--panel) 82%, #fff 3%);
      border-top: 1px solid var(--border);
      color: var(--muted);
      font-size: 0.95rem;
    }}
    .pill-grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }}
    .pill {{ padding: 16px; border-radius: 16px; background: color-mix(in srgb, var(--panel) 84%, #fff 3%); border: 1px solid var(--border); min-height: 116px; }}
    .pill strong {{ display: block; font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 12px; }}
    .pill span {{ display: block; font-size: 1.15rem; line-height: 1.4; }}
    .report-list {{ display: grid; gap: 10px; max-height: 340px; overflow: auto; overscroll-behavior: contain; }}
    .report-item {{ padding: 14px; border-radius: 14px; border: 1px solid var(--border); background: color-mix(in srgb, var(--surface) 90%, #fff 2%); cursor: pointer; }}
    .report-item.active {{ border-color: color-mix(in srgb, var(--primary) 50%, var(--border)); box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--primary) 24%, transparent); }}
    .report-item .top {{ display: flex; justify-content: space-between; gap: 12px; margin-bottom: 6px; font-size: 0.88rem; color: var(--muted); }}
    .report-item .file {{ font-weight: 600; word-break: break-word; }}
    .tag-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }}
    .tag {{ font-size: 0.78rem; padding: 5px 9px; border-radius: 999px; background: color-mix(in srgb, var(--panel) 84%, #fff 3%); border: 1px solid var(--border); color: var(--muted); }}
    .tabs {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .tab {{ padding: 9px 13px; border-radius: 999px; border: 1px solid var(--border); background: transparent; color: var(--muted); }}
    .tab.active {{ background: color-mix(in srgb, var(--primary) 18%, var(--panel)); color: var(--text); border-color: color-mix(in srgb, var(--primary) 35%, var(--border)); }}
    .panel {{ display: none; }}
    .panel.active {{ display: block; }}
    .details-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }}
    .detail-card {{ padding: 16px; border-radius: 16px; border: 1px solid var(--border); background: color-mix(in srgb, var(--panel) 86%, #fff 3%); }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 14px; border: 1px solid var(--border); }}
    th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-size: 0.84rem; text-transform: uppercase; letter-spacing: 0.06em; background: color-mix(in srgb, var(--panel) 88%, #fff 3%); }}
    tr:last-child td {{ border-bottom: none; }}
    pre {{ margin: 0; padding: 16px; border-radius: 16px; overflow: auto; overscroll-behavior: contain; background: color-mix(in srgb, var(--bg) 82%, #000); border: 1px solid var(--border); color: var(--text); font: 0.88rem/1.6 "Iosevka Term", "JetBrains Mono", monospace; }}
    .split-grid {{ display: grid; gap: 14px; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }}
    .saved-list {{ display: grid; gap: 8px; max-height: 220px; overflow: auto; overscroll-behavior: contain; }}
    .saved-item {{ padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border); background: color-mix(in srgb, var(--surface) 90%, #fff 2%); font-size: 0.9rem; word-break: break-word; cursor: pointer; }}
    .empty {{ padding: 28px; text-align: center; color: var(--muted); border: 1px dashed var(--border); border-radius: 18px; background: color-mix(in srgb, var(--panel) 64%, transparent); }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .info-list {{ display: grid; gap: 10px; }}
    .info-row {{ padding: 12px 14px; border-radius: 14px; border: 1px solid var(--border); background: color-mix(in srgb, var(--panel) 84%, #fff 3%); }}
    .toolbar-row {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
    .sticky-top {{ position: sticky; top: 0; z-index: 5; background: color-mix(in srgb, var(--panel) 94%, #000 4%); }}
    .hidden {{ display: none !important; }}
    .runner-grid {{ display: grid; gap: 14px; grid-template-columns: minmax(280px, 360px) minmax(0, 1fr); }}
    .runner-list {{ display: grid; gap: 10px; max-height: 780px; overflow: auto; overscroll-behavior: contain; }}
    .tool-card {{
      padding: 14px;
      border-radius: 16px;
      border: 1px solid var(--border);
      background: color-mix(in srgb, var(--surface) 90%, #fff 2%);
      cursor: pointer;
    }}
    .tool-card.selected {{
      border-color: color-mix(in srgb, var(--primary) 48%, var(--border));
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--primary) 22%, transparent);
    }}
    .tool-card.recommended {{
      background: linear-gradient(180deg, color-mix(in srgb, var(--primary) 8%, var(--surface)), color-mix(in srgb, var(--surface) 90%, #fff 2%));
    }}
    .tool-card .title-row {{ display: flex; justify-content: space-between; gap: 10px; align-items: center; }}
    .runner-status {{
      font-size: 0.78rem;
      padding: 4px 8px;
      border-radius: 999px;
      border: 1px solid var(--border);
      color: var(--muted);
      white-space: nowrap;
    }}
    .runner-status.good {{
      color: var(--success);
      border-color: color-mix(in srgb, var(--success) 36%, var(--border));
    }}
    .runner-status.bad {{
      color: var(--danger);
      border-color: color-mix(in srgb, var(--danger) 36%, var(--border));
    }}
    .tool-card .reason {{ margin-top: 10px; color: var(--muted); line-height: 1.5; }}
    .tool-card .meta {{ margin-top: 10px; font-size: 0.82rem; color: var(--muted); }}
    .action-grid {{ display: grid; gap: 12px; }}
    .output-log {{ min-height: 220px; max-height: 420px; overflow: auto; overscroll-behavior: contain; }}
    @media (max-width: 1180px) {{
      .shell {{ grid-template-columns: 1fr; }}
      .runner-grid {{ grid-template-columns: 1fr; }}
      .pill-grid, .details-grid, .split-grid, .inline-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body data-theme="forge">
  <div class="shell">
    <aside class="sidebar">
      <section class="card hero">
        <div class="eyebrow">Web Dashboard <span id="hero-version"></span></div>
        <h1>Elegant binary analysis, now browser-native.</h1>
        <p>Scan binaries, crawl corpora, inspect reports, and export artifacts from a responsive dashboard without leaving the existing ELFexplorer workflow.</p>
        <div class="hero-actions">
          <select id="theme-select" class="theme-select" aria-label="Dashboard theme"></select>
          <button id="refresh-state" class="ghost">Refresh State</button>
        </div>
      </section>

      <section class="card section">
        <h2>Scan File</h2>
        <form id="scan-form" class="form-grid">
          <input id="scan-path" placeholder="/path/to/binary.elf or firmware.uf2" required>
          <select id="scan-mode">
            <option value="general">general</option>
            <option value="important">important</option>
            <option value="detailed">detailed</option>
          </select>
          <button id="scan-submit" class="primary" type="submit">Run Scan</button>
        </form>
      </section>

      <section class="card section">
        <h2>Crawl Directory</h2>
        <form id="crawl-form" class="form-grid">
          <input id="crawl-path" placeholder="/path/to/corpus" required>
          <select id="crawl-mode">
            <option value="general">general</option>
            <option value="important">important</option>
            <option value="detailed">detailed</option>
          </select>
          <input id="crawl-max-files" placeholder="Max files (optional)" inputmode="numeric">
          <label class="muted"><input id="crawl-recursive" type="checkbox" checked> recursive</label>
          <button id="crawl-submit" class="primary" type="submit">Run Crawl</button>
        </form>
      </section>

      <section class="card section">
        <h2>Load Saved JSON</h2>
        <form id="load-scan-form" class="form-grid">
          <input id="load-scan-path" placeholder="/path/to/report.json" required>
          <button class="ghost" type="submit">Load Scan</button>
        </form>
        <form id="load-collection-form" class="form-grid" style="margin-top:12px;">
          <input id="load-collection-path" placeholder="/path/to/collection.json" required>
          <button class="ghost" type="submit">Load Collection</button>
        </form>
        <div style="margin-top:14px;">
          <div class="muted" style="margin-bottom:10px;">Saved scans</div>
          <div id="saved-list" class="saved-list"></div>
        </div>
      </section>

      <section class="card section">
        <h2>Compare / Diff</h2>
        <form id="compare-form" class="form-grid">
          <input id="compare-path" placeholder="/path/to/other/binary" required>
          <select id="compare-mode">
            <option value="general">general</option>
            <option value="important">important</option>
            <option value="detailed">detailed</option>
          </select>
          <button id="compare-submit" class="ghost" type="submit">Compare With Active Report</button>
          <button id="export-diff" class="ghost" type="button">Export Diff Markdown</button>
        </form>
      </section>
    </aside>

    <main class="main">
      <section class="card sticky-top">
        <div class="status-bar">
          <div id="status-message">Booting dashboard…</div>
          <div id="status-meta"></div>
        </div>
      </section>

      <section class="card section render-card">
        <div class="actions">
          <button id="download-json">Download JSON</button>
          <button id="save-report">Save Report JSON</button>
          <button id="save-collection">Save Collection JSON</button>
          <button id="export-markdown">Export Markdown</button>
          <button id="export-pdf">Export PDF</button>
          <button id="export-collection-markdown">Export Collection MD</button>
          <button id="export-collection-pdf">Export Collection PDF</button>
          <select id="plugin-format" style="max-width:240px;"></select>
          <button id="export-plugin">Export Tool Plugin</button>
        </div>
        <div id="metric-grid" class="pill-grid"></div>
      </section>

      <section class="card section render-card">
        <h2>Reports</h2>
        <div id="report-list" class="report-list"></div>
      </section>

      <section class="card section render-card">
        <div class="tabs">
          <button class="tab active" data-tab="overview">Overview</button>
          <button class="tab" data-tab="scores">Scores</button>
          <button class="tab" data-tab="evidence">Evidence</button>
          <button class="tab" data-tab="explain">Explain</button>
          <button class="tab" data-tab="hardening">Hardening</button>
          <button class="tab" data-tab="firmware">Firmware</button>
          <button class="tab" data-tab="plugins">Plugins</button>
          <button class="tab" data-tab="diff">Diff</button>
          <button class="tab" data-tab="tool-runner">Tool Runner</button>
          <button class="tab" data-tab="integrations">Integrations</button>
          <button class="tab" data-tab="metadata">Metadata</button>
          <button class="tab" data-tab="json">JSON</button>
        </div>
        <div id="panel-overview" class="panel active"></div>
        <div id="panel-scores" class="panel"></div>
        <div id="panel-evidence" class="panel"></div>
        <div id="panel-explain" class="panel"></div>
        <div id="panel-hardening" class="panel"></div>
        <div id="panel-firmware" class="panel"></div>
        <div id="panel-plugins" class="panel"></div>
        <div id="panel-diff" class="panel"></div>
        <div id="panel-tool-runner" class="panel"></div>
        <div id="panel-integrations" class="panel"></div>
        <div id="panel-metadata" class="panel"></div>
        <div id="panel-json" class="panel"></div>
      </section>
    </main>
  </div>

  <script id="initial-state" type="application/json">{payload}</script>
  <script>
    const initialState = JSON.parse(document.getElementById('initial-state').textContent);
    let appState = initialState;
    let selectedIndex = initialState.selected_index;
    let activeTab = 'overview';
    let toolingSnapshot = null;
    let activeToolKey = null;
    let toolRecommendations = null;
    let activeRunnerToolKey = null;
    let toolRunnerAction = 'run';
    let toolRunnerPresetKey = '';
    let toolRunnerArgsText = '';
    let toolRunnerResult = null;
    let renderFrame = null;
    const themeSelect = document.getElementById('theme-select');
    const themeKey = 'elfexplorer.web.theme';

    function escapeHtml(value) {{
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }}

    function humanFile(value) {{
      if (!value) return 'Unknown';
      const parts = String(value).split(/[\\/]/);
      return parts[parts.length - 1] || value;
    }}

    function activeReport() {{
      if (selectedIndex === null || selectedIndex === undefined) return null;
      return appState.reports?.[selectedIndex] ?? null;
    }}

    function resetToolRunnerState() {{
      toolRecommendations = null;
      activeRunnerToolKey = null;
      toolRunnerAction = 'run';
      toolRunnerPresetKey = '';
      toolRunnerArgsText = '';
      toolRunnerResult = null;
    }}

    function shellQuote(value) {{
      const text = String(value ?? '');
      if (!text.length) return "''";
      if (/^[A-Za-z0-9_./:=+%-]+$/.test(text)) return text;
      return JSON.stringify(text);
    }}

    function formatArgs(args) {{
      return (args || []).map((item) => shellQuote(item)).join(' ');
    }}

    function currentToolRecommendation() {{
      return (toolRecommendations?.tools || []).find((item) => item.tool_key === activeRunnerToolKey) || null;
    }}

    function applyToolRunnerDefaults(tool) {{
      if (!tool) return;
      activeRunnerToolKey = tool.tool_key;
      toolRunnerAction = tool.default_action || (tool.cli_friendly ? 'run' : 'launch');
      toolRunnerPresetKey = tool.default_preset_key || '';
      toolRunnerArgsText = formatArgs(tool.default_args || []);
      toolRunnerResult = null;
    }}

    function syncToolRunnerSelection() {{
      const tools = toolRecommendations?.tools || [];
      if (!tools.length) {{
        activeRunnerToolKey = null;
        return;
      }}
      const current = currentToolRecommendation();
      applyToolRunnerDefaults(current || tools[0]);
    }}

    function resolveRunnerPreview(tool) {{
      if (!tool) return '';
      const file = tool.target_path || activeReport()?.file || '';
      const executable = tool.status?.path || tool.executable_override || tool.tool_key;
      const argText = (toolRunnerArgsText || '').trim() || formatArgs(tool.default_args || []);
      const resolved = argText.replaceAll('{{file}}', file);
      return `${{executable}}${{resolved ? ` ${{resolved}}` : ''}}`;
    }}

    function metric(label, value) {{
      return `<div class="pill"><strong>${{label}}</strong><span>${{value}}</span></div>`;
    }}

    function codeBlock(value) {{
      return `<pre>${{escapeHtml(value || 'No data available.')}}</pre>`;
    }}

    function setStatus(message) {{
      document.getElementById('status-message').textContent = message || 'Ready.';
      document.getElementById('status-meta').textContent = `Reports: ${{appState.report_count}} | Generated: ${{new Date(appState.generated_at).toLocaleString()}}`;
    }}

    async function apiGet(path) {{
      const response = await fetch(path);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Request failed.');
      return payload;
    }}

    async function apiPost(path, body) {{
      const response = await fetch(path, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body),
      }});
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Request failed.');
      return payload;
    }}

    function renderThemeOptions() {{
      const themes = appState.web_themes || {{}};
      themeSelect.innerHTML = Object.entries(themes)
        .map(([key, meta]) => `<option value="${{key}}">${{meta.label}}</option>`)
        .join('');
      const savedTheme = localStorage.getItem(themeKey) || 'forge';
      themeSelect.value = themes[savedTheme] ? savedTheme : 'forge';
      document.body.dataset.theme = themeSelect.value;
    }}

    function renderPluginFormats() {{
      const formats = appState.tool_plugin_formats || {{}};
      const select = document.getElementById('plugin-format');
      const currentValue = select.value;
      select.innerHTML = Object.entries(formats)
        .map(([key, meta]) => `<option value="${{key}}">${{escapeHtml(meta.label || key)}}</option>`)
        .join('');
      if (formats[currentValue]) {{
        select.value = currentValue;
      }} else if (Object.keys(formats).length) {{
        select.value = Object.keys(formats)[0];
      }}
    }}

    function renderMetrics() {{
      const report = activeReport();
      if (!report) {{
        document.getElementById('metric-grid').innerHTML = [
          metric('Report Count', appState.report_count || 0),
          metric('Active File', 'None selected'),
          metric('UI Mode', 'Web dashboard'),
          metric('State', 'Ready for scan or load')
        ].join('');
        return;
      }}
      const scan = report.scan_result || {{}};
      const artifact = scan.artifact_profile || {{}};
      document.getElementById('metric-grid').innerHTML = [
        metric('Active File', humanFile(report.file)),
        metric('Language', scan.source_language || 'Unknown'),
        metric('Compiler', scan.compiler || 'Unknown'),
        metric('Artifact', artifact.artifact_type || 'Unknown'),
        metric('Board / Target', artifact.board || artifact.target || 'Unknown'),
        metric('SDK / Build', `${{artifact.sdk || 'Unknown'}} / ${{scan.build_system || 'Unknown'}}`),
        metric('Family', artifact.family || 'Unknown'),
        metric('Confidence', artifact.confidence ?? 0),
      ].join('');
    }}

    function renderReportList() {{
      const container = document.getElementById('report-list');
      if (!appState.reports || appState.reports.length === 0) {{
        container.innerHTML = '<div class="empty">No reports loaded yet. Scan a binary, crawl a corpus, or load a saved report JSON.</div>';
        return;
      }}
      container.innerHTML = appState.summaries.map((summary) => `
        <div class="report-item ${{summary.index === selectedIndex ? 'active' : ''}}" data-index="${{summary.index}}">
          <div class="top"><span>${{summary.mode}}</span><span>confidence=${{summary.confidence}}</span></div>
          <div class="file">${{summary.file}}</div>
          <div class="tag-row">
            <span class="tag">${{summary.language}}</span>
            <span class="tag">${{summary.compiler}}</span>
            <span class="tag">${{summary.build_system}}</span>
            <span class="tag">${{summary.artifact_type}}</span>
          </div>
        </div>
      `).join('');
    }}

    function renderSavedReports() {{
      const container = document.getElementById('saved-list');
      const items = appState.saved_reports || [];
      if (items.length === 0) {{
        container.innerHTML = '<div class="muted">No saved scans found.</div>';
        return;
      }}
      container.innerHTML = items.map((item) => `<div class="saved-item" data-path="${{item}}">${{item}}</div>`).join('');
    }}

    function scoreTable(scores) {{
      const rows = Object.entries(scores || {{}}).sort((a, b) => b[1] - a[1]);
      if (!rows.length) return '<div class="empty">No score data available.</div>';
      return `
        <table>
          <thead><tr><th>Label</th><th>Score</th></tr></thead>
          <tbody>${{rows.map(([label, value]) => `<tr><td>${{label}}</td><td>${{value}}</td></tr>`).join('')}}</tbody>
        </table>
      `;
    }}

    function evidenceList(report) {{
      const scan = report.scan_result || {{}};
      const artifact = scan.artifact_profile || {{}};
      const lines = [];
      for (const item of artifact.indicators || []) lines.push(`Artifact: ${{item}}`);
      const hardening = scan.hardening_profile || {{}};
      for (const item of hardening.signals || []) lines.push(`Hardening: ${{item}}`);
      const firmware = scan.firmware_fingerprint || {{}};
      for (const item of firmware.signals || []) lines.push(`Firmware: ${{item}}`);
      const pluginEvidence = scan.plugin_evidence || {{}};
      for (const item of pluginEvidence.diagnostics || []) lines.push(`Plugin: ${{item}}`);
      return lines;
    }}

    function renderOverview() {{
      const report = activeReport();
      if (!report) {{
        return '<div class="empty">No active report. Start with a scan, crawl, or saved report load.</div>';
      }}
      const scan = report.scan_result || {{}};
      const artifact = scan.artifact_profile || {{}};
      return `
        <div class="details-grid">
          <div class="detail-card"><strong class="muted">File</strong><div>${{escapeHtml(report.file || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">Mode</strong><div>${{escapeHtml(report.mode || 'general')}}</div></div>
          <div class="detail-card"><strong class="muted">Source Language</strong><div>${{escapeHtml(scan.source_language || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">Compiler</strong><div>${{escapeHtml(scan.compiler || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">Build System</strong><div>${{escapeHtml(scan.build_system || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">Artifact Type</strong><div>${{escapeHtml(artifact.artifact_type || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">Confidence</strong><div>${{artifact.confidence ?? 0}}</div></div>
          <div class="detail-card"><strong class="muted">Target / SDK</strong><div>${{escapeHtml(artifact.target || 'Unknown')}} / ${{escapeHtml(artifact.sdk || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">Board / Family</strong><div>${{escapeHtml(artifact.board || 'Unknown')}} / ${{escapeHtml(artifact.family || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">RTOS / Runtime</strong><div>${{escapeHtml(artifact.rtos || 'None detected')}} / ${{escapeHtml(artifact.runtime || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">Linkage / Loader</strong><div>${{escapeHtml(artifact.linkage_model || 'Unknown')}} / ${{escapeHtml(artifact.loader || 'None')}}</div></div>
          <div class="detail-card"><strong class="muted">Device Description</strong><div>${{escapeHtml(artifact.device_description || 'Unknown')}}</div></div>
        </div>
      `;
    }}

    function renderScores() {{
      const report = activeReport();
      if (!report) {{
        return '<div class="empty">No score tables available without an active report.</div>';
      }}
      const scan = report.scan_result || {{}};
      const artifact = scan.artifact_profile || {{}};
      return `
        <div class="split-grid">
          <div><h3>Artifact Scores</h3>${{scoreTable(artifact.scores)}}</div>
          <div><h3>Language Scores</h3>${{scoreTable(scan.language_scores)}}</div>
          <div><h3>Compiler Scores</h3>${{scoreTable(scan.compiler_scores)}}</div>
          <div><h3>Build System Scores</h3>${{scoreTable(scan.build_scores)}}</div>
        </div>
      `;
    }}

    function renderEvidence() {{
      const report = activeReport();
      if (!report) {{
        return '<div class="empty">Evidence appears here when a report is selected.</div>';
      }}
      const lines = evidenceList(report);
      return lines.length
        ? `<pre>${{lines.join('\\n')}}</pre>`
        : '<div class="empty">No explicit evidence lines were emitted for this report.</div>';
    }}

    function renderMetadata() {{
      const report = activeReport();
      if (!report) {{
        return '<div class="empty">Metadata appears here when a report is selected.</div>';
      }}
      return codeBlock(report.metadata_text || 'No metadata text available.');
    }}

    function renderJson() {{
      const report = activeReport();
      if (!report) {{
        return '<div class="empty">JSON payload appears here when a report is selected.</div>';
      }}
      return codeBlock(JSON.stringify(report, null, 2));
    }}

    function renderExplain() {{
      const report = activeReport();
      if (!report) {{
        return '<div class="empty">Explainability appears here when a report is selected.</div>';
      }}
      const explanations = report.scan_result?.explanations || {{}};
      const blocks = Object.entries(explanations).map(([key, value]) => `
        <div class="detail-card">
          <strong class="muted">${{escapeHtml(key)}}</strong>
          <div>Predicted: ${{escapeHtml(value.predicted || 'Unknown')}}</div>
          <div>Confidence Note: ${{escapeHtml(value.confidence_note || 'n/a')}}</div>
          <div>Margin: ${{value.score_margin ?? 0}}</div>
          <div style="margin-top:10px;">Top Positive: ${{(value.top_positive || []).map((item) => `${{escapeHtml(item.label)}} (${{item.score}})`).join(', ') || 'None'}}</div>
          <div style="margin-top:6px;">Competitors: ${{(value.top_competitors || []).map((item) => `${{escapeHtml(item.label)}} (${{item.score}})`).join(', ') || 'None'}}</div>
        </div>
      `);
      return blocks.length ? `<div class="details-grid">${{blocks.join('')}}</div>` : '<div class="empty">No explainability data available.</div>';
    }}

    function renderHardening() {{
      const report = activeReport();
      if (!report) {{
        return '<div class="empty">Hardening data appears here when a report is selected.</div>';
      }}
      const hardening = report.scan_result?.hardening_profile;
      if (!hardening) {{
        return '<div class="empty">This scan does not include a hardening profile.</div>';
      }}
      return `
        <div class="details-grid">
          <div class="detail-card"><strong class="muted">Risk Level</strong><div>${{escapeHtml(hardening.risk_level || 'unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">Stripped</strong><div>${{String(hardening.stripped ?? false)}}</div></div>
          <div class="detail-card"><strong class="muted">Likely Packed</strong><div>${{String(hardening.likely_packed ?? false)}}</div></div>
          <div class="detail-card"><strong class="muted">Likely Obfuscated</strong><div>${{String(hardening.likely_obfuscated ?? false)}}</div></div>
          <div class="detail-card"><strong class="muted">Text Entropy</strong><div>${{hardening.text_entropy ?? 0}}</div></div>
        </div>
        ${{codeBlock((hardening.signals || []).join('\\n') || 'No hardening signals available.')}}
      `;
    }}

    function renderFirmware() {{
      const report = activeReport();
      if (!report) {{
        return '<div class="empty">Firmware fingerprinting appears here when a report is selected.</div>';
      }}
      const firmware = report.scan_result?.firmware_fingerprint;
      if (!firmware) {{
        return '<div class="empty">This scan does not include a firmware fingerprint.</div>';
      }}
      return `
        <div class="details-grid">
          <div class="detail-card"><strong class="muted">Firmware Candidate</strong><div>${{String(firmware.is_firmware_candidate ?? false)}}</div></div>
          <div class="detail-card"><strong class="muted">Confidence</strong><div>${{firmware.firmware_confidence ?? 0}}</div></div>
          <div class="detail-card"><strong class="muted">Likely MCU</strong><div>${{escapeHtml(firmware.likely_mcu || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">Likely Vendor</strong><div>${{escapeHtml(firmware.likely_vendor || 'Unknown')}}</div></div>
          <div class="detail-card"><strong class="muted">SDK Candidates</strong><div>${{escapeHtml((firmware.sdk_candidates || []).join(', ') || 'None')}}</div></div>
          <div class="detail-card"><strong class="muted">RTOS Candidates</strong><div>${{escapeHtml((firmware.rtos_candidates || []).join(', ') || 'None')}}</div></div>
          <div class="detail-card"><strong class="muted">Board Candidates</strong><div>${{escapeHtml((firmware.board_candidates || []).join(', ') || 'None')}}</div></div>
        </div>
        ${{codeBlock((firmware.signals || []).join('\\n') || 'No firmware fingerprint signals available.')}}
      `;
    }}

    function renderPlugins() {{
      const report = activeReport();
      if (!report) {{
        return '<div class="empty">Plugin and signature evidence appears here when a report is selected.</div>';
      }}
      const pluginEvidence = report.scan_result?.plugin_evidence;
      if (!pluginEvidence) {{
        return '<div class="empty">No plugin or signature evidence is attached to this report.</div>';
      }}
      const diagnostics = (pluginEvidence.diagnostics || []).join('\\n') || 'No diagnostics.';
      const categories = ['languages', 'compilers', 'build_systems', 'artifacts']
        .map((key) => {{
          const items = pluginEvidence[key] || [];
          if (!items.length) return '';
          return `<div class="detail-card"><strong class="muted">${{escapeHtml(key)}}</strong><div>${{items.map((item) => `${{escapeHtml(item.rule)}} -> ${{escapeHtml(item.target)}} (${{item.score_delta ?? 0}})`).join('<br>')}}</div></div>`;
        }})
        .filter(Boolean)
        .join('');
      return `
        <div class="details-grid">
          <div class="detail-card"><strong class="muted">Packs</strong><div>${{escapeHtml((pluginEvidence.pack_names || []).join(', ') || 'None')}}</div></div>
          ${{categories}}
        </div>
        ${{codeBlock(diagnostics)}}
      `;
    }}

    function renderDiff() {{
      const diff = appState.active_diff;
      if (!diff) {{
        return '<div class="empty">Run a compare operation to populate a binary diff view.</div>';
      }}
      const summary = diff.summary || {{}};
      const rows = ['language', 'compiler', 'build_system', 'artifact_type', 'artifact_confidence']
        .map((key) => {{
          const values = summary[key] || ['Unknown', 'Unknown'];
          return `<tr><td>${{escapeHtml(key)}}</td><td>${{escapeHtml(values[0])}}</td><td>${{escapeHtml(values[1])}}</td></tr>`;
        }})
        .join('');
      const deltaTable = (entries) => {{
        if (!entries?.length) return '<div class="muted">No deltas.</div>';
        return `<table><thead><tr><th>Label</th><th>Before</th><th>After</th><th>Delta</th></tr></thead><tbody>${{entries.slice(0, 12).map((item) => `<tr><td>${{escapeHtml(item.label)}}</td><td>${{item.before}}</td><td>${{item.after}}</td><td>${{item.delta}}</td></tr>`).join('')}}</tbody></table>`;
      }};
      return `
        <div class="info-list">
          <div class="info-row"><strong class="muted">Left</strong><div>${{escapeHtml(diff.left_file || '')}}</div></div>
          <div class="info-row"><strong class="muted">Right</strong><div>${{escapeHtml(diff.right_file || '')}}</div></div>
        </div>
        <div style="margin-top:14px;"> <table><thead><tr><th>Field</th><th>Left</th><th>Right</th></tr></thead><tbody>${{rows}}</tbody></table></div>
        <div class="split-grid" style="margin-top:14px;">
          <div><h3>Language Deltas</h3>${{deltaTable(diff.language_deltas)}}</div>
          <div><h3>Compiler Deltas</h3>${{deltaTable(diff.compiler_deltas)}}</div>
          <div><h3>Build Deltas</h3>${{deltaTable(diff.build_deltas)}}</div>
          <div><h3>Artifact Deltas</h3>${{deltaTable(diff.artifact_deltas)}}</div>
        </div>
        <div class="split-grid" style="margin-top:14px;">
          <div>${{codeBlock((diff.indicator_added || []).map((line) => `+ ${{line}}`).join('\\n') || '(none)')}}</div>
          <div>${{codeBlock((diff.indicator_removed || []).map((line) => `- ${{line}}`).join('\\n') || '(none)')}}</div>
        </div>
      `;
    }}

    function renderToolRunner() {{
      const report = activeReport();
      const caps = appState.capabilities || {{}};
      if (!report) {{
        return '<div class="empty">Select or scan a binary to build recommended third-party tool actions.</div>';
      }}
      if (!caps.tool_runner) {{
        return '<div class="empty">Tool execution callbacks are unavailable in this dashboard context.</div>';
      }}
      if (!toolRecommendations) {{
        return '<div class="empty">Loading tool recommendations for the active binary…</div>';
      }}
      const tools = toolRecommendations.tools || [];
      if (!tools.length) {{
        return '<div class="empty">No tool workflows are available for this report.</div>';
      }}
      const current = currentToolRecommendation() || tools[0];
      const presets = current.presets || [];
      const supportsRun = Boolean(current.cli_friendly || presets.length);
      const actionOptions = [
        supportsRun ? `<option value="run"${{toolRunnerAction === 'run' ? ' selected' : ''}}>Run and capture output</option>` : '',
        `<option value="launch"${{toolRunnerAction === 'launch' ? ' selected' : ''}}>Launch external tool</option>`,
      ].filter(Boolean).join('');
      const presetOptions = [`<option value="">Manual / default</option>`]
        .concat(
          presets.map((preset) => `<option value="${{preset.key}}"${{toolRunnerPresetKey === preset.key ? ' selected' : ''}}>${{escapeHtml(preset.label)}}</option>`)
        )
        .join('');
      const resultBlock = toolRunnerResult
        ? codeBlock(
            [
              toolRunnerResult.message || '',
              toolRunnerResult.command ? `command: ${{toolRunnerResult.command.join(' ')}}` : '',
              toolRunnerResult.pid ? `pid: ${{toolRunnerResult.pid}}` : '',
              toolRunnerResult.returncode !== undefined ? `returncode: ${{toolRunnerResult.returncode}}` : '',
              toolRunnerResult.output || '',
            ].filter(Boolean).join('\\n')
          )
        : '<div class="muted">Preview, run, or launch a tool to see the resolved command and execution result here.</div>';

      return `
        <div class="runner-grid">
          <div class="runner-list">
            ${{
              tools.map((tool) => `
                <div class="tool-card ${{tool.tool_key === current.tool_key ? 'selected' : ''}} ${{tool.recommended ? 'recommended' : ''}}" data-tool-runner-select="${{tool.tool_key}}">
                  <div class="title-row">
                    <strong>${{escapeHtml(tool.status?.label || tool.tool_key)}}</strong>
                    <span class="runner-status ${{tool.status?.installed ? 'good' : 'bad'}}">${{tool.status?.installed ? 'Installed' : 'Missing'}}</span>
                  </div>
                  <div class="meta">priority=${{tool.priority || 0}} • action=${{tool.default_action || 'launch'}} • container=${{escapeHtml(toolRecommendations.container_kind || 'unknown')}}</div>
                  <div class="reason">${{escapeHtml(tool.reason || 'Available for this report.')}}</div>
                </div>
              `).join('')
            }}
          </div>
          <div class="action-grid">
            <div class="details-grid">
              <div class="detail-card"><strong class="muted">Selected Tool</strong><div>${{escapeHtml(current.status?.label || current.tool_key)}}</div></div>
              <div class="detail-card"><strong class="muted">Binary Type</strong><div>${{escapeHtml(toolRecommendations.artifact_type || toolRecommendations.container_kind || 'Unknown')}}</div></div>
              <div class="detail-card"><strong class="muted">Resolved Binary</strong><div>${{escapeHtml(current.target_path || report.file || 'Unknown')}}</div></div>
              <div class="detail-card"><strong class="muted">Executable</strong><div>${{escapeHtml(current.status?.path || current.executable_override || 'Not detected')}}</div></div>
            </div>
            <div class="detail-card">
              <strong class="muted">Recommendation</strong>
              <div style="margin-top:8px;">${{escapeHtml(current.reason || 'Available for manual use.')}}</div>
              <div class="form-grid" style="margin-top:14px;">
                <div class="inline-grid">
                  <label>
                    <div class="muted" style="margin-bottom:6px;">Action</div>
                    <select id="tool-runner-action">${{actionOptions}}</select>
                  </label>
                  <label>
                    <div class="muted" style="margin-bottom:6px;">Preset</div>
                    <select id="tool-runner-preset">${{presetOptions}}</select>
                  </label>
                </div>
                <label>
                  <div class="muted" style="margin-bottom:6px;">Arguments</div>
                  <textarea id="tool-runner-args" placeholder="Enter CLI arguments or keep the recommended preset args">${{escapeHtml(toolRunnerArgsText || '')}}</textarea>
                </label>
                <div class="toolbar-row">
                  <button type="button" id="tool-runner-refresh">Refresh Recommendations</button>
                  <button type="button" id="tool-runner-preview">Preview Command</button>
                  <button type="button" id="tool-runner-execute" class="primary">${{toolRunnerAction === 'launch' ? 'Launch Tool' : 'Run Tool'}}</button>
                </div>
              </div>
            </div>
            <div class="detail-card">
              <strong class="muted">Command Preview</strong>
              <div style="margin-top:10px;">${{escapeHtml(resolveRunnerPreview(current) || 'Unavailable')}}</div>
            </div>
            <div class="detail-card">
              <strong class="muted">Execution Result</strong>
              <div class="output-log" style="margin-top:12px;">${{resultBlock}}</div>
            </div>
          </div>
        </div>
      `;
    }}

    function renderIntegrations() {{
      const caps = appState.capabilities || {{}};
      if (!caps.tooling) {{
        return '<div class="empty">Tooling integration callbacks are unavailable in this dashboard context.</div>';
      }}
      if (!toolingSnapshot) {{
        return '<div class="empty">Loading tooling status…</div>';
      }}
      const tools = toolingSnapshot.tools || [];
      const rows = tools.map((tool) => `
        <tr>
          <td>${{escapeHtml(tool.label || tool.key)}}</td>
          <td>${{tool.installed ? 'Installed' : 'Missing'}}</td>
          <td>${{escapeHtml(tool.version || tool.path || tool.install_manager_label || 'n/a')}}</td>
          <td><button type="button" class="ghost" data-tool-detail="${{tool.key}}">Details</button></td>
        </tr>
      `).join('');
      const detail = activeToolKey && toolingSnapshot.details?.[activeToolKey]
        ? codeBlock(
            Array.isArray(toolingSnapshot.details[activeToolKey])
              ? toolingSnapshot.details[activeToolKey].join('\\n')
              : JSON.stringify(toolingSnapshot.details[activeToolKey], null, 2)
          )
        : '<div class="muted">Select a tool for detailed install and path information.</div>';
      return `
        <div class="toolbar-row" style="margin-bottom:14px;">
          <button type="button" id="refresh-tooling-inline">Refresh Tooling Status</button>
        </div>
        <table>
          <thead><tr><th>Tool</th><th>Status</th><th>Path / Version</th><th>Detail</th></tr></thead>
          <tbody>${{rows}}</tbody>
        </table>
        <div style="margin-top:14px;">${{detail}}</div>
      `;
    }}

    function applyCapabilities() {{
      const caps = appState.capabilities || {{}};
      document.getElementById('scan-submit').disabled = !caps.scan;
      document.getElementById('crawl-submit').disabled = !caps.crawl;
      document.getElementById('export-markdown').disabled = !caps.export_md || !activeReport();
      document.getElementById('export-pdf').disabled = !caps.export_pdf || !activeReport();
      document.getElementById('save-report').disabled = !caps.save_scan || !activeReport();
      document.getElementById('save-collection').disabled = !caps.save_collection || !appState.report_count;
      document.getElementById('export-collection-markdown').disabled = !caps.export_collection_md || !appState.report_count;
      document.getElementById('export-collection-pdf').disabled = !caps.export_collection_pdf || !appState.report_count;
      document.getElementById('export-plugin').disabled = !caps.tool_plugins || !activeReport();
      document.getElementById('compare-submit').disabled = !caps.diff || !activeReport();
      document.getElementById('export-diff').disabled = !appState.active_diff;
      document.getElementById('download-json').disabled = !activeReport();
    }}

    function renderCurrentPanel() {{
      const panel = document.getElementById(`panel-${{activeTab}}`);
      document.querySelectorAll('.panel').forEach((item) => item.classList.remove('active'));
      panel.classList.add('active');
      const renderers = {{
        overview: renderOverview,
        scores: renderScores,
        evidence: renderEvidence,
        explain: renderExplain,
        hardening: renderHardening,
        firmware: renderFirmware,
        plugins: renderPlugins,
        diff: renderDiff,
        'tool-runner': renderToolRunner,
        integrations: renderIntegrations,
        metadata: renderMetadata,
        json: renderJson,
      }};
      panel.innerHTML = (renderers[activeTab] || (() => '<div class="empty">Unknown tab.</div>'))();
    }}

    function renderAll() {{
      document.getElementById('hero-version').textContent = `v${{appState.version}}`;
      renderThemeOptions();
      renderPluginFormats();
      renderMetrics();
      renderReportList();
      renderSavedReports();
      renderCurrentPanel();
      applyCapabilities();
      setStatus(appState.message || 'Ready.');
    }}

    function scheduleRender() {{
      if (renderFrame !== null) return;
      renderFrame = requestAnimationFrame(() => {{
        renderFrame = null;
        renderAll();
      }});
    }}

    async function refreshState() {{
      appState = await apiGet('/api/state');
      if (appState.report_count && (selectedIndex === null || selectedIndex >= appState.report_count)) {{
        selectedIndex = 0;
      }}
      scheduleRender();
    }}

    async function runScan(path, mode) {{
      appState = await apiPost('/api/scan', {{ path, mode }});
      selectedIndex = appState.selected_index;
      activeToolKey = null;
      resetToolRunnerState();
      scheduleRender();
    }}

    async function runCrawl(path, mode, recursive, maxFiles) {{
      appState = await apiPost('/api/crawl', {{ path, mode, recursive, max_files: maxFiles }});
      selectedIndex = appState.selected_index;
      activeToolKey = null;
      resetToolRunnerState();
      scheduleRender();
    }}

    async function runLoadScan(path) {{
      appState = await apiPost('/api/load-scan', {{ path }});
      selectedIndex = appState.selected_index;
      activeToolKey = null;
      resetToolRunnerState();
      scheduleRender();
    }}

    async function runLoadCollection(path) {{
      appState = await apiPost('/api/load-collection', {{ path }});
      selectedIndex = appState.selected_index;
      activeToolKey = null;
      resetToolRunnerState();
      scheduleRender();
    }}

    async function runExport(format) {{
      if (selectedIndex === null || selectedIndex === undefined) return;
      const payload = await apiPost('/api/export/report', {{ index: selectedIndex, format }});
      setStatus(payload.message || `Exported ${{format}}.`);
    }}

    async function runSaveReport() {{
      if (selectedIndex === null || selectedIndex === undefined) return;
      const payload = await apiPost('/api/save/report', {{ index: selectedIndex }});
      setStatus(payload.message);
      await refreshState();
    }}

    async function runSaveCollection() {{
      const payload = await apiPost('/api/save/collection', {{}});
      setStatus(payload.message);
      await refreshState();
    }}

    async function runExportCollection(format) {{
      const suffix = format === 'markdown' ? '.md' : '.pdf';
      const stem = activeReport() ? humanFile(activeReport().file).replace(/\\.[^.]+$/, '') : 'collection';
      const path = `reports/${{stem}}-collection-web${{suffix}}`;
      const payload = await apiPost('/api/export/collection', {{ format, path }});
      setStatus(payload.message);
    }}

    async function runExportPlugin() {{
      if (selectedIndex === null || selectedIndex === undefined) return;
      const format = document.getElementById('plugin-format').value;
      const payload = await apiPost('/api/tool-plugin/export', {{ index: selectedIndex, format }});
      setStatus(payload.message);
    }}

    async function ensureToolingSnapshot(force = false) {{
      if (!force && toolingSnapshot) return;
      const snapshot = await apiGet('/api/tooling/status');
      toolingSnapshot = {{
        ...snapshot,
        details: toolingSnapshot?.details || {{}},
      }};
    }}

    async function ensureToolRecommendations(force = false) {{
      const report = activeReport();
      if (!report) {{
        resetToolRunnerState();
        return;
      }}
      if (!force && toolRecommendations && toolRecommendations.target_path === String(report.file || '')) return;
      toolRecommendations = await apiPost('/api/tooling/recommendations', {{ index: selectedIndex }});
      syncToolRunnerSelection();
    }}

    async function showToolDetail(toolKey) {{
      await ensureToolingSnapshot();
      if (!toolingSnapshot.details[toolKey]) {{
        toolingSnapshot.details[toolKey] = await apiGet(`/api/tooling/${{toolKey}}/detail`);
      }}
      activeToolKey = toolKey;
      scheduleRender();
    }}

    async function runToolExecute(dryRun = false) {{
      const tool = currentToolRecommendation();
      if (!tool) return;
      const payload = await apiPost('/api/tooling/execute', {{
        index: selectedIndex,
        tool_key: tool.tool_key,
        action: toolRunnerAction,
        preset_key: toolRunnerPresetKey || null,
        args: toolRunnerArgsText.trim(),
        dry_run: dryRun,
      }});
      toolRunnerResult = payload;
      setStatus(payload.message || (dryRun ? 'Generated tool command preview.' : 'Executed tool action.'));
      scheduleRender();
    }}

    async function runCompare(otherPath, mode) {{
      if (selectedIndex === null || selectedIndex === undefined) return;
      const payload = await apiPost('/api/diff', {{ index: selectedIndex, path: otherPath, mode }});
      appState.active_diff = payload.diff;
      activeTab = 'diff';
      scheduleRender();
      setStatus(payload.message);
    }}

    async function runExportDiff() {{
      const report = activeReport();
      const stem = report ? humanFile(report.file).replace(/\\.[^.]+$/, '') : 'diff';
      const payload = await apiPost('/api/export/diff', {{ path: `reports/${{stem}}-diff-web.md` }});
      setStatus(payload.message);
    }}

    function activateTab(tab) {{
      activeTab = tab;
      document.querySelectorAll('.tab').forEach((item) => item.classList.toggle('active', item.dataset.tab === tab));
      if (tab === 'tool-runner') {{
        ensureToolRecommendations().then(() => scheduleRender()).catch((error) => setStatus(error.message));
      }}
      if (tab === 'integrations') {{
        ensureToolingSnapshot().then(() => scheduleRender()).catch((error) => setStatus(error.message));
      }}
      scheduleRender();
    }}

    document.getElementById('scan-form').addEventListener('submit', async (event) => {{
      event.preventDefault();
      try {{
        await runScan(document.getElementById('scan-path').value, document.getElementById('scan-mode').value);
      }} catch (error) {{
        setStatus(error.message);
      }}
    }});

    document.getElementById('crawl-form').addEventListener('submit', async (event) => {{
      event.preventDefault();
      try {{
        const rawMax = document.getElementById('crawl-max-files').value.trim();
        await runCrawl(
          document.getElementById('crawl-path').value,
          document.getElementById('crawl-mode').value,
          document.getElementById('crawl-recursive').checked,
          rawMax ? Number(rawMax) : null,
        );
      }} catch (error) {{
        setStatus(error.message);
      }}
    }});

    document.getElementById('load-scan-form').addEventListener('submit', async (event) => {{
      event.preventDefault();
      try {{
        await runLoadScan(document.getElementById('load-scan-path').value);
      }} catch (error) {{
        setStatus(error.message);
      }}
    }});

    document.getElementById('load-collection-form').addEventListener('submit', async (event) => {{
      event.preventDefault();
      try {{
        await runLoadCollection(document.getElementById('load-collection-path').value);
      }} catch (error) {{
        setStatus(error.message);
      }}
    }});

    document.getElementById('compare-form').addEventListener('submit', async (event) => {{
      event.preventDefault();
      try {{
        await runCompare(
          document.getElementById('compare-path').value,
          document.getElementById('compare-mode').value,
        );
      }} catch (error) {{
        setStatus(error.message);
      }}
    }});

    document.getElementById('refresh-state').addEventListener('click', async () => {{
      try {{
        await refreshState();
      }} catch (error) {{
        setStatus(error.message);
      }}
    }});

    document.getElementById('download-json').addEventListener('click', () => {{
      if (selectedIndex === null || selectedIndex === undefined) return;
      window.open(`/api/report/${{selectedIndex}}/json`, '_blank');
    }});

    document.getElementById('export-markdown').addEventListener('click', async () => {{
      try {{ await runExport('markdown'); }} catch (error) {{ setStatus(error.message); }}
    }});
    document.getElementById('export-pdf').addEventListener('click', async () => {{
      try {{ await runExport('pdf'); }} catch (error) {{ setStatus(error.message); }}
    }});
    document.getElementById('save-report').addEventListener('click', async () => {{
      try {{ await runSaveReport(); }} catch (error) {{ setStatus(error.message); }}
    }});
    document.getElementById('save-collection').addEventListener('click', async () => {{
      try {{ await runSaveCollection(); }} catch (error) {{ setStatus(error.message); }}
    }});
    document.getElementById('export-collection-markdown').addEventListener('click', async () => {{
      try {{ await runExportCollection('markdown'); }} catch (error) {{ setStatus(error.message); }}
    }});
    document.getElementById('export-collection-pdf').addEventListener('click', async () => {{
      try {{ await runExportCollection('pdf'); }} catch (error) {{ setStatus(error.message); }}
    }});
    document.getElementById('export-plugin').addEventListener('click', async () => {{
      try {{ await runExportPlugin(); }} catch (error) {{ setStatus(error.message); }}
    }});
    document.getElementById('export-diff').addEventListener('click', async () => {{
      try {{ await runExportDiff(); }} catch (error) {{ setStatus(error.message); }}
    }});

    document.getElementById('report-list').addEventListener('click', (event) => {{
      const item = event.target.closest('.report-item');
      if (!item) return;
      selectedIndex = Number(item.dataset.index);
      resetToolRunnerState();
      if (activeTab === 'tool-runner') {{
        ensureToolRecommendations().then(() => scheduleRender()).catch((error) => setStatus(error.message));
        return;
      }}
      scheduleRender();
    }});

    document.getElementById('saved-list').addEventListener('click', async (event) => {{
      const item = event.target.closest('.saved-item');
      if (!item) return;
      try {{
        document.getElementById('load-scan-path').value = item.dataset.path;
        await runLoadScan(item.dataset.path);
      }} catch (error) {{
        setStatus(error.message);
      }}
    }});

    document.querySelectorAll('.tab').forEach((button) => {{
      button.addEventListener('click', () => activateTab(button.dataset.tab));
    }});

    document.addEventListener('click', async (event) => {{
      const toolButton = event.target.closest('[data-tool-detail]');
      if (!toolButton) return;
      try {{
        await showToolDetail(toolButton.dataset.toolDetail);
      }} catch (error) {{
        setStatus(error.message);
      }}
    }});

    document.addEventListener('click', async (event) => {{
      if (event.target.id !== 'refresh-tooling-inline') return;
      try {{
        await ensureToolingSnapshot(true);
        scheduleRender();
      }} catch (error) {{
        setStatus(error.message);
      }}
    }});

    document.addEventListener('click', async (event) => {{
      const item = event.target.closest('[data-tool-runner-select]');
      if (!item) return;
      const tool = (toolRecommendations?.tools || []).find((entry) => entry.tool_key === item.dataset.toolRunnerSelect);
      if (!tool) return;
      applyToolRunnerDefaults(tool);
      scheduleRender();
    }});

    document.addEventListener('change', (event) => {{
      if (event.target.id === 'tool-runner-action') {{
        toolRunnerAction = event.target.value;
        const tool = currentToolRecommendation();
        if (tool && !toolRunnerPresetKey) {{
          toolRunnerArgsText = formatArgs(
            toolRunnerAction === 'launch' ? (tool.launch_args || []) : (tool.default_args || [])
          );
        }}
        toolRunnerResult = null;
        scheduleRender();
        return;
      }}
      if (event.target.id === 'tool-runner-preset') {{
        toolRunnerPresetKey = event.target.value;
        const tool = currentToolRecommendation();
        const preset = (tool?.presets || []).find((entry) => entry.key === toolRunnerPresetKey);
        if (preset) {{
          toolRunnerArgsText = formatArgs(preset.args || []);
        }} else if (tool) {{
          toolRunnerArgsText = formatArgs(
            toolRunnerAction === 'launch' ? (tool.launch_args || []) : (tool.default_args || [])
          );
        }}
        toolRunnerResult = null;
        scheduleRender();
      }}
    }});

    document.addEventListener('input', (event) => {{
      if (event.target.id !== 'tool-runner-args') return;
      toolRunnerArgsText = event.target.value;
    }});

    document.addEventListener('click', async (event) => {{
      if (event.target.id === 'tool-runner-refresh') {{
        try {{
          await ensureToolRecommendations(true);
          scheduleRender();
        }} catch (error) {{
          setStatus(error.message);
        }}
        return;
      }}
      if (event.target.id === 'tool-runner-preview') {{
        try {{
          await runToolExecute(true);
        }} catch (error) {{
          setStatus(error.message);
        }}
        return;
      }}
      if (event.target.id === 'tool-runner-execute') {{
        try {{
          await runToolExecute(false);
        }} catch (error) {{
          setStatus(error.message);
        }}
      }}
    }});

    themeSelect.addEventListener('change', () => {{
      document.body.dataset.theme = themeSelect.value;
      localStorage.setItem(themeKey, themeSelect.value);
    }});

    renderAll();
  </script>
</body>
</html>
"""


def _load_request_body(handler):
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Request body must be valid JSON.") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Request body must be a JSON object.")
    return payload


def _send_json(handler, status_code, payload):
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _send_html(handler, html_text):
    body = html_text.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _send_report_json(handler, report):
    body = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    filename = human_filename(report.get("file", "report")) + ".json"
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def human_filename(value):
    return Path(str(value)).name or "report"


def create_dashboard_server(
    callbacks=None,
    initial_reports=None,
    host="127.0.0.1",
    port=8765,
):
    runtime = DashboardRuntime(callbacks=callbacks, initial_reports=initial_reports)

    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                if path == "/":
                    _send_html(self, build_dashboard_html(runtime.state()))
                    return
                if path == "/api/state":
                    _send_json(self, 200, runtime.state())
                    return
                if path == "/api/tooling/status":
                    _send_json(self, 200, runtime.tooling_status())
                    return
                if path.startswith("/api/tooling/") and path.endswith("/detail"):
                    fragment = path[len("/api/tooling/") : -len("/detail")].strip("/")
                    _send_json(self, 200, runtime.tooling_detail(fragment))
                    return
                if path.startswith("/api/report/") and path.endswith("/json"):
                    fragment = path[len("/api/report/") : -len("/json")].strip("/")
                    report = runtime.get_report(fragment)
                    _send_report_json(self, report)
                    return
                _send_json(self, 404, {"error": f"Unknown route: {html.escape(path)}"})
            except Exception as exc:
                _send_json(self, 400, {"error": str(exc)})

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                payload = _load_request_body(self)
                if path == "/api/scan":
                    state = runtime.scan(payload.get("path"), payload.get("mode", "general"))
                    _send_json(self, 200, state)
                    return
                if path == "/api/crawl":
                    state = runtime.crawl(
                        payload.get("path"),
                        payload.get("mode", "general"),
                        recursive=bool(payload.get("recursive", True)),
                        max_files=payload.get("max_files"),
                    )
                    _send_json(self, 200, state)
                    return
                if path == "/api/load-scan":
                    state = runtime.load_scan(payload.get("path"))
                    _send_json(self, 200, state)
                    return
                if path == "/api/load-collection":
                    state = runtime.load_collection(payload.get("path"))
                    _send_json(self, 200, state)
                    return
                if path == "/api/export/report":
                    result = runtime.export_report(
                        payload.get("index"),
                        payload.get("format"),
                        path=payload.get("path"),
                    )
                    _send_json(self, 200, result)
                    return
                if path == "/api/save/report":
                    result = runtime.save_report(payload.get("index"), path=payload.get("path"))
                    _send_json(self, 200, result)
                    return
                if path == "/api/save/collection":
                    result = runtime.save_collection(path=payload.get("path"))
                    _send_json(self, 200, result)
                    return
                if path == "/api/export/collection":
                    result = runtime.export_collection(
                        payload.get("format"),
                        payload.get("path"),
                    )
                    _send_json(self, 200, result)
                    return
                if path == "/api/tool-plugin/export":
                    result = runtime.export_tool_plugin(
                        payload.get("index"),
                        payload.get("format"),
                        path=payload.get("path"),
                    )
                    _send_json(self, 200, result)
                    return
                if path == "/api/tooling/recommendations":
                    _send_json(self, 200, runtime.tool_recommendations(payload.get("index")))
                    return
                if path == "/api/tooling/execute":
                    result = runtime.tool_execute(
                        payload.get("index"),
                        payload.get("tool_key"),
                        action=payload.get("action", "run"),
                        preset_key=payload.get("preset_key"),
                        args=payload.get("args"),
                        dry_run=bool(payload.get("dry_run", False)),
                    )
                    _send_json(self, 200, result)
                    return
                if path == "/api/diff":
                    result = runtime.compare_with(
                        payload.get("index"),
                        payload.get("path"),
                        mode=payload.get("mode", "general"),
                    )
                    _send_json(self, 200, result)
                    return
                if path == "/api/export/diff":
                    result = runtime.export_diff_markdown(payload.get("path"))
                    _send_json(self, 200, result)
                    return
                _send_json(self, 404, {"error": f"Unknown route: {html.escape(path)}"})
            except Exception as exc:
                _send_json(self, 400, {"error": str(exc)})

    server = ThreadingHTTPServer((host, int(port)), DashboardHandler)
    display_host = "127.0.0.1" if host in {"0.0.0.0", ""} else host
    url = f"http://{display_host}:{server.server_port}"
    return server, url, runtime


def run_web_dashboard(
    callbacks=None,
    initial_reports=None,
    host="127.0.0.1",
    port=8765,
    open_browser=False,
):
    server, url, _runtime = create_dashboard_server(
        callbacks=callbacks,
        initial_reports=initial_reports,
        host=host,
        port=port,
    )
    print(f"Starting {APP_NAME} web dashboard at {url}")
    print("Press Ctrl+C to stop the dashboard.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception as exc:
            print(f"Browser auto-open failed: {exc}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping web dashboard.")
    finally:
        server.shutdown()
        server.server_close()
