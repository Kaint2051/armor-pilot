#!/bin/bash
set -e

if command -v systemctl &>/dev/null 2>&1; then
    systemctl stop  armor-pilot 2>/dev/null || true
    systemctl disable armor-pilot 2>/dev/null || true
fi
