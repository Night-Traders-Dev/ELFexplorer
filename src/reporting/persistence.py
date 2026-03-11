import json
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_STORE_DIR = Path.home() / ".elfexplorer" / "scans"


def ensure_store_dir(store_dir=None):
    directory = Path(store_dir) if store_dir else DEFAULT_STORE_DIR
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _sanitize_filename(text):
    allowed = []
    for ch in text:
        if ch.isalnum() or ch in ("-", "_", "."):
            allowed.append(ch)
        else:
            allowed.append("_")
    cleaned = "".join(allowed).strip("._")
    return cleaned or "scan"


def _timestamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def default_report_path(report, store_dir=None):
    directory = ensure_store_dir(store_dir)
    source = Path(report.get("file", "scan")).name
    stem = _sanitize_filename(Path(source).stem)
    filename = f"{stem}-{_timestamp()}.json"
    return directory / filename


def save_report(report, path=None, store_dir=None):
    out_path = Path(path) if path else default_report_path(report, store_dir=store_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    return out_path


def load_report(path):
    in_path = Path(path)
    with in_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_collection(reports, path=None, store_dir=None):
    directory = ensure_store_dir(store_dir)
    if path:
        out_path = Path(path)
    else:
        out_path = directory / f"collection-{_timestamp()}.json"

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(reports),
        "reports": reports,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return out_path


def load_collection(path):
    in_path = Path(path)
    with in_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict) and "reports" in payload:
        return payload
    if isinstance(payload, list):
        return {"generated_at": None, "count": len(payload), "reports": payload}
    raise ValueError(f"Invalid collection file format: {in_path}")


def list_saved_reports(store_dir=None):
    directory = ensure_store_dir(store_dir)
    return sorted(directory.glob("*.json"))

