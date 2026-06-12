#!/usr/bin/env bash
# Palisade agent installer for Linux (systemd). Run as root.
#   sudo ./install_linux.sh http://YOUR-SERVER:8787
set -euo pipefail
SERVER="${1:?usage: install_linux.sh http://server:8787}"
install -d /opt/palisade /var/lib/palisade
install -m 0755 "$(dirname "$0")/../agent/palisade_agent.py" /opt/palisade/
python3 -m pip install --quiet psutil || pip3 install --quiet psutil
# escape the server URL for the systemd instance specifier
ESC=$(systemd-escape "$SERVER")
cp "$(dirname "$0")/palisade-agent.service" /etc/systemd/system/palisade-agent@.service
systemctl daemon-reload
systemctl enable --now "palisade-agent@${ESC}.service"
echo "Palisade agent installed and started. Logs: journalctl -u palisade-agent@${ESC}"
