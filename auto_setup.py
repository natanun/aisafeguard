#!/usr/bin/env python3
"""
Safe deployment and verification script for AISafeGuard.
Includes directory guardrails, backup/rollback, dry-run tests, and confirmation prompt.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

# ใช้ Raw String (r'''...''') เพื่อป้องกันปัญหา Backslash / Quote Escaping 100%
CLEAN_AISAFEGUARD_CODE = r'''#!/usr/bin/env python3
"""
AISafeGuard - Lightweight Security & Secret Scanner for AI-Generated Code.
License: MIT
"""
import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from typing import List


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    cwe: str
    severity: str
    description: str
    snippet: str
    remediation: str


SECURITY_RULES = [
    {
        "id": "ASG001",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "description": "Hardcoded API Key or Secret token detected",
        "pattern": re.compile(r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})"),
        "remediation": "Move secrets to environment variables (os.environ) or a secrets manager.",
    },
    {
        "id": "ASG002",
        "cwe": "CWE-94",
        "severity": "HIGH",
        "description": "Arbitrary code execution via eval() or exec()",
        "pattern": re.compile(r"\b(eval|exec)\s*\("),
        "remediation": "Avoid eval()/exec() on untrusted input; use ast.literal_eval() or safe parsers.",
    },
    {
        "id": "ASG003",
        "cwe": "CWE-78",
        "severity": "HIGH",
        "description": "OS Command Injection risk via shell=True or os.system",
        "pattern": re.compile(r"(subprocess\.(Popen|run|call)\s*\([^)]*shell\s*=\s*True|os\.system\s*\()"),
        "remediation": "Use subprocess.run() with a list of arguments and shell=False.",
    },
    {
        "id": "ASG004",
        "cwe": "CWE-89",
        "severity": "HIGH",
        "description": "Potential SQL Injection via string interpolation in SQL query",
        "pattern": re.compile(r"(execute|cursor\.execute)\s*\([^)]*(SELECT|INSERT|UPDATE|DELETE)", re.IGNORECASE),
        "remediation": "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))).",
    },
    {
        "id": "ASG005",
        "cwe": "CWE-502",
        "severity": "HIGH",
        "description": "Insecure deserialization using pickle or unsafe yaml.load",
        "pattern": re.compile(r"(pickle\.(loads|load)\s*\(|yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader))"),
        "remediation": "Use json or yaml.safe_load() instead of untrusted pickle/yaml.load.",
    },
    {
        "id": "ASG006",
        "cwe": "CWE-327",
        "severity": "MEDIUM",
        "description": "Use of weak cryptographic hash function (MD5/SHA1)",
        "pattern": re.compile(r"hashlib\.(md5|sha1)\s*\("),
        "remediation": "Use strong cryptographic hashes such as hashlib.sha256() or bcrypt/argon2.",
    },
]

EXCLUDED_FILES = {"aisafeguard.py", "test_aisafeguard.py", "auto_setup.py"}
EXCLUDED_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules"}


def scan_file(filepath: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                for rule in SECURITY_RULES:
                    if rule["pattern"].search(line):
                        findings.append(
                            Finding(
                                file=filepath,
                                line=idx,
                                rule_id=rule["id"],
                                cwe=rule["cwe"],
                                severity=rule["severity"],
                                description=rule["description"],
                                snippet=line.strip()[:120],
                                remediation=rule["remediation"],
                            )
                        )
    except OSError:
        pass
    return findings


def scan_path(target_path: str) -> List[Finding]:
    if os.path.isfile(target_path):
        return scan_file(target_path)
    all_findings: List[Finding] = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file in files:
            if file.endswith((".py", ".js", ".ts", ".sh", ".env", ".yml", ".yaml")) and file not in EXCLUDED_FILES:
                all_findings.extend(scan_file(os.path.join(root, file)))
    return all_findings


def main() -> None:
    parser = argparse.ArgumentParser(description="AISafeGuard: Static Security Scanner for AI-Generated Code")
    parser.add_argument("target", nargs="?", default=".", help="File or directory path to scan")
    parser.add_argument("--json", action="store_true", help="Output findings in JSON format")
    args = parser.parse_args()

    findings = scan_path(args.target)
    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("AISafeGuard: No security issues found.")
        else:
            print(f"AISafeGuard detected {len(findings)} security issue(s):")
            for f in findings:
                print(f"[{f.severity}] {f.rule_id} ({f.cwe}) in {f.file}:{f.line}")
                print(f"  Issue: {f.description}")
                print(f"  Code : {f.snippet}")
                print(f"  Fix  : {f.remediation}")
            sys.exit(1)


if __name__ == "__main__":
    main()
'''


def main() -> None:
    cwd = Path.cwd()
    # 1. Pre-condition Folder Guardrail
    if cwd.name.lower() != "aisafeguard" or not (cwd / ".git").exists():
        print(f"[BLOCKED] Current directory is '{cwd}'.")
        print("Please run this script inside 'C:\\Users\\nts\\.gemini\\aisafeguard' only.")
        sys.exit(1)

    target_file = cwd / "aisafeguard.py"
    backup_file = cwd / "aisafeguard.py.bak"

    # 2. Backup existing file (Rollback preparation)
    if target_file.exists():
        shutil.copy2(target_file, backup_file)
        print("[1/4] Backed up existing aisafeguard.py -> aisafeguard.py.bak")

    try:
        # 3. Write clean code and run dry-run verification
        target_file.write_text(CLEAN_AISAFEGUARD_CODE.lstrip(), encoding="utf-8")
        print("[2/4] Wrote clean aisafeguard.py. Running verification checks...")

        # Check 1: Unit tests
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-v"], check=True)
        # Check 2: Self security scan (exact command used by GitHub Actions)
        subprocess.run([sys.executable, "aisafeguard.py", "."], check=True)
        print("[3/4] All unit tests and self-scan passed 100%!")

    except subprocess.CalledProcessError:
        print("[ERROR] Verification failed! Rolling back to backup...")
        if backup_file.exists():
            shutil.move(str(backup_file), str(target_file))
        sys.exit(1)

    # Remove backup after successful verification
    if backup_file.exists():
        backup_file.unlink()

    # 4. Confirmation Prompt before Git Push
    ans = input("\n[4/4] Ready to commit and push to GitHub (origin/main)? [y/N]: ").strip().lower()
    if ans == "y":
        subprocess.run(["git", "add", "aisafeguard.py", "auto_setup.py"], check=True)
        subprocess.run(["git", "commit", "-m", "fix: resolve regex syntax and exclude setup script from self-scan"], check=True)
        subprocess.run(["git", "push", "origin", "main"], check=True)
        print("\n[SUCCESS] Pushed to GitHub successfully!")
    else:
        print("\n[SKIPPED] File updated locally, but git push was cancelled by user.")


if __name__ == "__main__":
    main()
