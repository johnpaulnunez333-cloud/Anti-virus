"""Real (but simple) file analysis: hash lookup, extension check, pattern check.

This is an educational scanner. It is NOT a replacement for a real antivirus.
"""
import hashlib
from pathlib import Path

# Each hash type is compared only against its own table.
# EICAR is the harmless industry-standard antivirus test file.
MD5_SIGNATURES = {
    "44d88612fea8a8f36de82e1278abb02f": "Eicar.Test.File",
}
SHA256_SIGNATURES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Eicar.Test.File",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".scr", ".pif",
    ".com", ".jar", ".ps1", ".sh", ".msi",
}

DANGEROUS_PATTERNS = [
    ("eval(", "Obfuscated code execution"),
    ("exec(", "Dynamic code execution"),
    ("subprocess", "System process spawning"),
    ("os.system", "OS command execution"),
    ("shell=true", "Shell injection risk"),
    ("base64.decode", "Encoded payload"),
    ("wget ", "Remote file download"),
    ("curl ", "Remote file download"),
    ("/etc/passwd", "Sensitive file access"),
    ("regedit", "Registry modification"),
    ("format c:", "Disk format command"),
    ("rm -rf", "Destructive deletion"),
    ("powershell -enc", "Encoded PowerShell"),
    ("invoke-expression", "PowerShell injection"),
    ("eicar-standard-antivirus-test-file", "EICAR test string"),
]

RISK_ORDER = ["low", "medium", "high", "critical"]


def _raise_risk(result, level):
    if RISK_ORDER.index(level) > RISK_ORDER.index(result["risk_level"]):
        result["risk_level"] = level


def analyze_file(filename, content_bytes):
    safe_name = Path(filename or "unnamed").name  # strip any path parts
    md5_hash = hashlib.md5(content_bytes).hexdigest()
    sha256_hash = hashlib.sha256(content_bytes).hexdigest()

    result = {
        "filename": safe_name,
        "size": len(content_bytes),
        "status": "clean",
        "threat": None,
        "risk_level": "low",
        "md5": md5_hash,
        "sha256": sha256_hash,
        "details": [],
    }

    # 1. Signature check (MD5 vs MD5 table, SHA-256 vs SHA-256 table)
    threat = MD5_SIGNATURES.get(md5_hash) or SHA256_SIGNATURES.get(sha256_hash)
    if threat:
        result.update(status="threat", threat=threat)
        _raise_risk(result, "critical")
        result["details"].append("Known malware signature detected")

    # 2. Extension check
    ext = Path(safe_name).suffix.lower()
    if ext in SUSPICIOUS_EXTENSIONS:
        result["details"].append(f"Suspicious file extension: {ext}")
        if result["status"] == "clean":
            result["status"] = "warning"
        _raise_risk(result, "medium")

    # 3. Pattern check on the file's text content
    text = content_bytes.decode("utf-8", errors="ignore").lower()
    matches = [desc for pattern, desc in DANGEROUS_PATTERNS if pattern in text]
    for desc in matches:
        result["details"].append(f"Suspicious pattern: {desc}")
    if matches:
        if result["status"] == "clean":
            result["status"] = "warning"
        _raise_risk(result, "high" if len(matches) > 1 or ext in SUSPICIOUS_EXTENSIONS else "medium")

    # 4. Empty files are odd but not malware
    if not content_bytes:
        result["details"].append("File is empty")

    if not result["details"]:
        result["details"].append("No threats detected")

    return result
