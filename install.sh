#!/bin/bash
set -e
cd "$(dirname "$0")"
echo "[*] Installing linuxharden (no external deps required)"
chmod +x "$0" 2>/dev/null || true
echo "[*] Done. Run with:"
echo "    sudo python3 -m linuxharden audit --html report.html"
