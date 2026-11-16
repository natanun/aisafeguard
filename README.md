# 🛡️ AISafeGuard: Safety Scanner for AI-Generated Code

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security CI](https://github.com/natanun/aisafeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/natanun/aisafeguard/actions/workflows/ci.yml)

**AISafeGuard** is a fast, zero-dependency Static Application Security Testing (SAST) CLI tool designed to catch security vulnerabilities, unsafe execution patterns, and hardcoded secrets commonly introduced by AI coding assistants before they reach production.

## 🚀 Key Features
- **Secret Leak Prevention (CWE-798):** Detects exposed API keys (OpenAI, AWS, GitHub tokens) in source files.
- **Injection Guardrails (CWE-78 / CWE-89 / CWE-94):** Flags dangerous `eval()`, `exec()`, `shell=True`, and raw SQL string formatting.
- **Safe Serialization & Crypto Checks (CWE-502 / CWE-327):** Identifies unsafe `pickle` usage and weak hashing algorithms (`md5`, `sha1`).
- **CI/CD & Agent Ready:** Outputs structured JSON or human-readable remediation guidance for automated PR reviews.

## 📦 Quick Start
```bash
# Scan current repository
python3 aisafeguard.py .

# Output findings as JSON for CI/CD pipelines
python3 aisafeguard.py . --json

# Run unit tests
python3 -m unittest test_aisafeguard.py
```

## 🗺️ Roadmap
- [x] Core static regex engine mapped to CWE & OWASP Top 10
- [x] Automated unit test suite and GitHub Actions workflow
- [ ] AST-based deep taint analysis for Python and TypeScript
- [ ] LLM-assisted automated patch generation for detected vulnerabilities

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.
