"""Central configuration for NovaScan."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Where scan history is stored. Override with NOVASCAN_DATA_DIR.
# Note: on hosts like Render's free tier the disk is ephemeral,
# so history resets whenever the service restarts.
DATA_DIR = Path(os.environ.get("NOVASCAN_DATA_DIR", BASE_DIR / "data"))
HISTORY_FILE = DATA_DIR / "scan_history.json"
HISTORY_LIMIT = 20

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_SESSIONS_IN_MEMORY = 50

# Never hardcode debug=True. Enable locally with: FLASK_DEBUG=1 python app.py
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
PORT = int(os.environ.get("PORT", 5000))
