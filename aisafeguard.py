#!/usr/bin/env python3
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
