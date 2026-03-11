import json
from pathlib import Path


DEFAULT_SETTINGS = {
    "theme": "textual-dark",
}


def settings_path() -> Path:
    return Path(__file__).resolve().parents[1] / "settings.conf"


def load_settings() -> dict:
    path = settings_path()
    if not path.exists():
        save_settings(dict(DEFAULT_SETTINGS))
        return dict(DEFAULT_SETTINGS)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        data = {}

    if not isinstance(data, dict):
        data = {}

    merged = dict(DEFAULT_SETTINGS)
    merged.update({key: value for key, value in data.items() if value is not None})
    return merged


def save_settings(settings: dict) -> Path:
    merged = dict(DEFAULT_SETTINGS)
    if isinstance(settings, dict):
        merged.update(settings)
    path = settings_path()
    path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_theme_preference() -> str:
    settings = load_settings()
    return str(settings.get("theme", DEFAULT_SETTINGS["theme"]))


def save_theme_preference(theme: str) -> Path:
    settings = load_settings()
    settings["theme"] = str(theme)
    return save_settings(settings)

