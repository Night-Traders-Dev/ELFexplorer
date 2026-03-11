import json
import shutil
import urllib.request
from pathlib import Path


DEFAULT_SIGNATURE_DIR = Path.home() / ".elfexplorer" / "signatures"
ACTIVE_SIGNATURE_FILENAME = "active-signatures.json"


def ensure_signature_dir(signature_dir=None):
    directory = Path(signature_dir).expanduser() if signature_dir else DEFAULT_SIGNATURE_DIR
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def active_signature_path(signature_dir=None):
    return ensure_signature_dir(signature_dir) / ACTIVE_SIGNATURE_FILENAME


def list_signature_packs(signature_dir=None):
    directory = ensure_signature_dir(signature_dir)
    return sorted(directory.glob("*.json"))


def load_signature_pack(path):
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Signature pack must be a JSON object: {path}")
    return payload


def load_active_signature_pack(signature_dir=None):
    path = active_signature_path(signature_dir)
    if not path.exists():
        return None
    return load_signature_pack(path)


def install_signature_pack(source_path, signature_dir=None, active_name=None):
    source = Path(source_path).expanduser()
    if not source.exists():
        raise FileNotFoundError(f"Signature pack not found: {source}")
    directory = ensure_signature_dir(signature_dir)
    target_name = active_name or source.name
    installed = directory / target_name
    if source.resolve() != installed.resolve():
        shutil.copy2(source, installed)
    active_path = active_signature_path(signature_dir)
    if installed.resolve() != active_path.resolve():
        shutil.copy2(installed, active_path)
    return installed, active_path


def update_signature_pack(url, signature_dir=None, timeout=15):
    directory = ensure_signature_dir(signature_dir)
    downloaded = directory / "downloaded-signatures.json"
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = response.read()
    downloaded.write_bytes(payload)
    # Validate JSON shape before activating.
    load_signature_pack(downloaded)
    active_path = active_signature_path(signature_dir)
    shutil.copy2(downloaded, active_path)
    return downloaded, active_path
