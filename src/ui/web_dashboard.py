from __future__ import annotations

import html
import json
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

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

    def _callback(self, name):
        value = self.callbacks.get(name)
        return value if callable(value) else None

    def capabilities(self):
        return {
            "scan": bool(self._callback("scan")),
            "crawl": bool(self._callback("crawl")),
            "load_scan": bool(self._callback("load_scan")),
            "load_collection": bool(self._callback("load_collection")),
            "list_saved": bool(self._callback("list_saved")),
            "export_md": bool(self._callback("export_report_md")),
            "export_pdf": bool(self._callback("export_report_pdf")),
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
        }

    def replace_reports(self, reports, message):
        self.reports = list(reports)
        self.message = message
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
      --shadow: 0 24px 80px rgba(0,0,0,0.28);
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
    }}
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
    .report-list {{ display: grid; gap: 10px; max-height: 340px; overflow: auto; }}
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
    pre {{ margin: 0; padding: 16px; border-radius: 16px; overflow: auto; background: color-mix(in srgb, var(--bg) 82%, #000); border: 1px solid var(--border); color: var(--text); font: 0.88rem/1.6 "Iosevka Term", "JetBrains Mono", monospace; }}
    .split-grid {{ display: grid; gap: 14px; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }}
    .saved-list {{ display: grid; gap: 8px; max-height: 220px; overflow: auto; }}
    .saved-item {{ padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border); background: color-mix(in srgb, var(--surface) 90%, #fff 2%); font-size: 0.9rem; word-break: break-word; cursor: pointer; }}
    .empty {{ padding: 28px; text-align: center; color: var(--muted); border: 1px dashed var(--border); border-radius: 18px; background: color-mix(in srgb, var(--panel) 64%, transparent); }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .sticky-top {{ position: sticky; top: 0; z-index: 5; backdrop-filter: blur(18px); }}
    .hidden {{ display: none !important; }}
    @media (max-width: 1180px) {{
      .shell {{ grid-template-columns: 1fr; }}
      .pill-grid, .details-grid, .split-grid {{ grid-template-columns: 1fr; }}
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
    </aside>

    <main class="main">
      <section class="card sticky-top">
        <div class="status-bar">
          <div id="status-message">Booting dashboard…</div>
          <div id="status-meta"></div>
        </div>
      </section>

      <section class="card section">
        <div class="actions">
          <button id="download-json">Download JSON</button>
          <button id="export-markdown">Export Markdown</button>
          <button id="export-pdf">Export PDF</button>
        </div>
        <div id="metric-grid" class="pill-grid"></div>
      </section>

      <section class="card section">
        <h2>Reports</h2>
        <div id="report-list" class="report-list"></div>
      </section>

      <section class="card section">
        <div class="tabs">
          <button class="tab active" data-tab="overview">Overview</button>
          <button class="tab" data-tab="scores">Scores</button>
          <button class="tab" data-tab="evidence">Evidence</button>
          <button class="tab" data-tab="metadata">Metadata</button>
          <button class="tab" data-tab="json">JSON</button>
        </div>
        <div id="panel-overview" class="panel active"></div>
        <div id="panel-scores" class="panel"></div>
        <div id="panel-evidence" class="panel"></div>
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
    const themeSelect = document.getElementById('theme-select');
    const themeKey = 'elfexplorer.web.theme';

    function humanFile(value) {{
      if (!value) return 'Unknown';
      const parts = String(value).split(/[\\/]/);
      return parts[parts.length - 1] || value;
    }}

    function activeReport() {{
      if (selectedIndex === null || selectedIndex === undefined) return null;
      return appState.reports?.[selectedIndex] ?? null;
    }}

    function metric(label, value) {{
      return `<div class="pill"><strong>${{label}}</strong><span>${{value}}</span></div>`;
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
        metric('Artifact', artifact.artifact_type || 'Unknown')
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
      container.querySelectorAll('.report-item').forEach((item) => {{
        item.addEventListener('click', () => {{
          selectedIndex = Number(item.dataset.index);
          renderAll();
        }});
      }});
    }}

    function renderSavedReports() {{
      const container = document.getElementById('saved-list');
      const items = appState.saved_reports || [];
      if (items.length === 0) {{
        container.innerHTML = '<div class="muted">No saved scans found.</div>';
        return;
      }}
      container.innerHTML = items.map((item) => `<div class="saved-item" data-path="${{item}}">${{item}}</div>`).join('');
      container.querySelectorAll('.saved-item').forEach((item) => {{
        item.addEventListener('click', async () => {{
          document.getElementById('load-scan-path').value = item.dataset.path;
          await runLoadScan(item.dataset.path);
        }});
      }});
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
      const panel = document.getElementById('panel-overview');
      if (!report) {{
        panel.innerHTML = '<div class="empty">No active report. Start with a scan, crawl, or saved report load.</div>';
        return;
      }}
      const scan = report.scan_result || {{}};
      const artifact = scan.artifact_profile || {{}};
      panel.innerHTML = `
        <div class="details-grid">
          <div class="detail-card"><strong class="muted">File</strong><div>${{report.file || 'Unknown'}}</div></div>
          <div class="detail-card"><strong class="muted">Mode</strong><div>${{report.mode || 'general'}}</div></div>
          <div class="detail-card"><strong class="muted">Source Language</strong><div>${{scan.source_language || 'Unknown'}}</div></div>
          <div class="detail-card"><strong class="muted">Compiler</strong><div>${{scan.compiler || 'Unknown'}}</div></div>
          <div class="detail-card"><strong class="muted">Build System</strong><div>${{scan.build_system || 'Unknown'}}</div></div>
          <div class="detail-card"><strong class="muted">Artifact Type</strong><div>${{artifact.artifact_type || 'Unknown'}}</div></div>
          <div class="detail-card"><strong class="muted">Confidence</strong><div>${{artifact.confidence ?? 0}}</div></div>
          <div class="detail-card"><strong class="muted">Target / SDK</strong><div>${{artifact.target || 'Unknown'}} / ${{artifact.sdk || 'Unknown'}}</div></div>
        </div>
      `;
    }}

    function renderScores() {{
      const report = activeReport();
      const panel = document.getElementById('panel-scores');
      if (!report) {{
        panel.innerHTML = '<div class="empty">No score tables available without an active report.</div>';
        return;
      }}
      const scan = report.scan_result || {{}};
      const artifact = scan.artifact_profile || {{}};
      panel.innerHTML = `
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
      const panel = document.getElementById('panel-evidence');
      if (!report) {{
        panel.innerHTML = '<div class="empty">Evidence appears here when a report is selected.</div>';
        return;
      }}
      const lines = evidenceList(report);
      panel.innerHTML = lines.length
        ? `<pre>${{lines.join('\\n')}}</pre>`
        : '<div class="empty">No explicit evidence lines were emitted for this report.</div>';
    }}

    function renderMetadata() {{
      const report = activeReport();
      const panel = document.getElementById('panel-metadata');
      if (!report) {{
        panel.innerHTML = '<div class="empty">Metadata appears here when a report is selected.</div>';
        return;
      }}
      panel.innerHTML = `<pre>${{report.metadata_text || 'No metadata text available.'}}</pre>`;
    }}

    function renderJson() {{
      const report = activeReport();
      const panel = document.getElementById('panel-json');
      if (!report) {{
        panel.innerHTML = '<div class="empty">JSON payload appears here when a report is selected.</div>';
        return;
      }}
      panel.innerHTML = `<pre>${{JSON.stringify(report, null, 2)}}</pre>`;
    }}

    function applyCapabilities() {{
      const caps = appState.capabilities || {{}};
      document.getElementById('scan-submit').disabled = !caps.scan;
      document.getElementById('crawl-submit').disabled = !caps.crawl;
      document.getElementById('export-markdown').disabled = !caps.export_md || !activeReport();
      document.getElementById('export-pdf').disabled = !caps.export_pdf || !activeReport();
      document.getElementById('download-json').disabled = !activeReport();
    }}

    function renderAll() {{
      document.getElementById('hero-version').textContent = `v${{appState.version}}`;
      renderThemeOptions();
      renderMetrics();
      renderReportList();
      renderSavedReports();
      renderOverview();
      renderScores();
      renderEvidence();
      renderMetadata();
      renderJson();
      applyCapabilities();
      setStatus(appState.message || 'Ready.');
    }}

    async function refreshState() {{
      appState = await apiGet('/api/state');
      if (appState.report_count && (selectedIndex === null || selectedIndex >= appState.report_count)) {{
        selectedIndex = 0;
      }}
      renderAll();
    }}

    async function runScan(path, mode) {{
      appState = await apiPost('/api/scan', {{ path, mode }});
      selectedIndex = appState.selected_index;
      renderAll();
    }}

    async function runCrawl(path, mode, recursive, maxFiles) {{
      appState = await apiPost('/api/crawl', {{ path, mode, recursive, max_files: maxFiles }});
      selectedIndex = appState.selected_index;
      renderAll();
    }}

    async function runLoadScan(path) {{
      appState = await apiPost('/api/load-scan', {{ path }});
      selectedIndex = appState.selected_index;
      renderAll();
    }}

    async function runLoadCollection(path) {{
      appState = await apiPost('/api/load-collection', {{ path }});
      selectedIndex = appState.selected_index;
      renderAll();
    }}

    async function runExport(format) {{
      if (selectedIndex === null || selectedIndex === undefined) return;
      const payload = await apiPost('/api/export/report', {{ index: selectedIndex, format }});
      setStatus(payload.message || `Exported ${{format}}.`);
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

    document.querySelectorAll('.tab').forEach((button) => {{
      button.addEventListener('click', () => {{
        document.querySelectorAll('.tab').forEach((item) => item.classList.remove('active'));
        document.querySelectorAll('.panel').forEach((item) => item.classList.remove('active'));
        button.classList.add('active');
        document.getElementById(`panel-${{button.dataset.tab}}`).classList.add('active');
      }});
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
