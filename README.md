# NovaScan — Educational Antivirus Demo

A Flask + vanilla JavaScript web app that shows how a simple antivirus works.

> **Educational project.** It is not real antivirus software.

## Features
- **Scan Now** — a *simulated* system scan with made-up files (shows progress, results, history).
- **File upload scan** — a *real* check on files you upload (max 10 MB):
  - MD5 / SHA-256 signature lookup (detects the harmless EICAR test file)
  - suspicious file extensions (`.exe`, `.bat`, `.ps1`, ...)
  - suspicious code patterns (`eval(`, `rm -rf`, `powershell -enc`, ...)
- Scan history, stats, and a threat log.

## Project structure
```
novascan/
├── app.py            # Flask routes (API)
├── scanner.py        # real file analysis
├── demo_scan.py      # simulated system scan data
├── storage.py        # thread-safe history storage
├── config.py         # settings (env vars)
├── static/
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
├── data/             # scan_history.json is created here
├── requirements.txt
├── render.yaml / Procfile
└── README.md
```

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                    # http://localhost:5000
```
Debug mode (local only): `FLASK_DEBUG=1 python app.py`

## Deploy on Render
1. Push this folder to GitHub.
2. Render → **New → Web Service** → pick the repo (or use **Blueprint** with `render.yaml`).
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT`

Note: Render's free tier has an ephemeral disk, so scan history resets on restart.

## Test it
Save this single line as `eicar.txt` and upload it — it should be flagged as a threat:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

## Screenshots
_Add screenshots here._
