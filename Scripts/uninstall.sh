#!/usr/bin/env bash
set -euo pipefail

svc="dbus-org.freedesktop.isolate1.service"

# stop + disable (ignore errors if not present)
sudo systemctl stop "$svc" 2>/dev/null || true
sudo systemctl disable "$svc" 2>/dev/null || true

# remove the unit + dropped directory
sudo rm -f "/etc/systemd/system/$svc"
sudo rm -rf /etc/ntpsvc

# reload systemd so it forgets the unit
sudo systemctl daemon-reload
sudo systemctl reset-failed 2>/dev/null || true