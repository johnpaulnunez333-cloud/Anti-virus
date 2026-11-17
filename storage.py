"""Thread-safe JSON storage for scan history."""
import json
import os
import threading

import config

_lock = threading.Lock()


def load_history():
    with _lock:
        return _read()


def add_history_entry(entry):
    """Insert a new entry at the top and keep only the latest N."""
    with _lock:
        history = _read()
        history.insert(0, entry)
        _write(history[: config.HISTORY_LIMIT])


def _read():
    try:
        with open(config.HISTORY_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _write(data):
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = config.HISTORY_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, config.HISTORY_FILE)  # atomic: no half-written file
