#!/usr/bin/env bash
# Palisade agent installer for macOS (launchd). Run with sudo.
#   sudo ./install_macos.sh http://YOUR-SERVER:8787
set -euo pipefail
SERVER="${1:?usage: install_macos.sh http://server:8787}"
mkdir -p /opt/palisade /var/db/palisade
cp "$(dirname "$0")/../agent/palisade_agent.py" /opt/palisade/
/usr/bin/python3 -m pip install --quiet psutil || true
PLIST=/Library/LaunchDaemons/com.palisade.agent.plist
sed "s#http://CHANGE-ME:8787#${SERVER}#" "$(dirname "$0")/com.palisade.agent.plist" > "$PLIST"
chown root:wheel "$PLIST"; chmod 644 "$PLIST"
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"
echo "Palisade agent installed. Logs: /var/log/palisade-agent.log"
