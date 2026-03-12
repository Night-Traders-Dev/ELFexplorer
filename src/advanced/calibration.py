import json
from pathlib import Path


def build_calibration_model(benchmark_result):
    reliability = benchmark_result.get("reliability_curve", {})
    bins = []
    for bucket, entry in sorted(reliability.items()):
        try:
            left, right = bucket.split("-", 1)
            lower = int(left)
            upper = int(right)
        except Exception:
            continue
        bins.append(
            {
                "range": [lower, upper],
                "empirical_accuracy": float(entry.get("empirical_accuracy", 0.0)),
                "sample_count": int(entry.get("total", 0)),
            }
        )
    return {"version": 1, "bins": bins}


def save_calibration_model(model, path):
    out_path = Path(path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(model, handle, indent=2, sort_keys=True)
    return out_path


def load_calibration_model(path):
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("Calibration model must be a JSON object.")
    bins = payload.get("bins")
    if not isinstance(bins, list):
        raise ValueError("Calibration model must include a 'bins' array.")
    return payload


def calibrate_confidence(raw_confidence, model):
    value = max(0, min(99, int(raw_confidence)))
    for item in model.get("bins", []):
        rng = item.get("range", [])
        if not isinstance(rng, list) or len(rng) != 2:
            continue
        lower, upper = int(rng[0]), int(rng[1])
        if lower <= value < upper:
            return int(round(float(item.get("empirical_accuracy", 0.0)) * 100))
    return value

