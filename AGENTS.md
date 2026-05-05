# AGENTS.md

## Cursor Cloud specific instructions

This is a **bash shell script repository** (no Node.js, Python, or other runtimes). The codebase consists of deployment/management scripts for Sing-Box proxy with ShadowTLS and DNS unlocking services.

### Key scripts

| Script | Purpose |
|--------|---------|
| `sb.sh` | Main Sing-Box & ShadowTLS management script (~5000 lines) |
| `install_sniproxy.sh` | SNI Proxy + SmartDNS installer for the unlock server |
| `test_improvements.sh` | Unit-level test script for validating functions in `sb.sh` |

### Lint

```bash
shellcheck --severity=error sb.sh install_sniproxy.sh
```

Note: `--severity=warning` produces ~300+ warnings (pre-existing style issues in this large script). Use `--severity=error` for CI-like checks.

### Tests

```bash
bash test_improvements.sh
```

24/25 tests pass. Test 22 ("配置生成步骤化检查") fails due to a pre-existing code issue (step markers `[1/4]...[4/4]` not all present in `sb.sh`). This is not a regression.

### Syntax check

```bash
bash -n sb.sh
bash -n install_sniproxy.sh
```

### Important notes

- The scripts are designed to run on Linux VPS servers with `systemd`. They install system packages, download binaries, and configure services. They require root/sudo and network access.
- **Do NOT run `sb.sh` or `install_sniproxy.sh` directly in the development environment** — they will attempt to install Sing-Box, configure systemd services, and modify system files. Use the test script or `bash -n` for validation.
- The `docs/` directory contains MkDocs-style documentation for the Sing-Box project (markdown files with YAML frontmatter).
