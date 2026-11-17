"""Simulated 'full system scan'.

Nothing here touches the real file system. The file list is made up so the
UI can show a full scan flow. Results are labelled simulated=True.
"""
import hashlib
from pathlib import Path

# (path, size in bytes, status, threat name or None)
DEMO_FILES = [
    ("system32/kernel.dll", 204800, "clean", None),
    ("system32/ntdll.dll", 512000, "clean", None),
    ("AppData/temp/setup.exe", 98304, "warning", None),
    ("Downloads/movie.mp4", 734003200, "clean", None),
    ("Documents/report.docx", 45056, "clean", None),
    ("Temp/update.bat", 2048, "warning", None),
    ("Program Files/app/main.exe", 1048576, "clean", None),
    ("AppData/Roaming/cache.tmp", 8192, "clean", None),
    ("Desktop/invoice.pdf", 156672, "clean", None),
    ("Downloads/crack_tool.exe", 32768, "threat", "Trojan.Demo.Generic"),
    ("System/drivers/net.sys", 65536, "clean", None),
    ("Windows/Temp/~tmp001.tmp", 4096, "clean", None),
    ("Users/Public/share.vbs", 1024, "warning", None),
    ("ProgramData/logs/error.log", 20480, "clean", None),
    ("AppData/Local/Temp/inst.msi", 5242880, "warning", None),
    ("System32/config/SAM", 262144, "clean", None),
    ("Windows/System32/cmd.exe", 294912, "clean", None),
    ("Downloads/keygen.exe", 16384, "threat", "Backdoor.Demo.Agent"),
    ("Temp/script.ps1", 3072, "warning", None),
    ("Documents/backup.zip", 20971520, "clean", None),
]


def build_result(path, size, status, threat):
    ext = Path(path).suffix.lower()
    if status == "threat":
        risk = "critical"
        details = ["Simulated malware signature", "Executable with suspicious behavior"]
    elif status == "warning":
        risk = "high" if ext in {".exe", ".bat", ".ps1"} else "medium"
        details = [f"Suspicious file type: {ext}", "Requires manual review"]
    else:
        risk = "low"
        details = ["No threats detected"]

    return {
        "filename": path,
        "size": size,
        "status": status,
        "threat": threat,
        "risk_level": risk,
        "md5": hashlib.md5(f"{path}{size}".encode()).hexdigest(),
        "sha256": hashlib.sha256(path.encode()).hexdigest(),
        "details": details,
        "simulated": True,
    }
