import json
from pathlib import Path


def run_task_file(task_file, scan_binary_func, crawl_directory_func, default_mode="general"):
    task_path = Path(task_file)
    payload = json.loads(task_path.read_text(encoding="utf-8"))
    tasks = payload.get("tasks", [])

    reports = []
    for task in tasks:
        task_type = str(task.get("type", "")).strip().lower()
        mode = task.get("mode", default_mode)

        if task_type == "scan":
            path = task.get("path")
            if not path:
                continue
            reports.append(scan_binary_func(path, mode=mode))
            continue

        if task_type == "crawl":
            path = task.get("path")
            if not path:
                continue
            recursive = bool(task.get("recursive", True))
            max_files = int(task.get("max_files", 0)) or None
            reports.extend(
                crawl_directory_func(
                    path,
                    mode=mode,
                    recursive=recursive,
                    max_files=max_files,
                )
            )
            continue

    return reports

