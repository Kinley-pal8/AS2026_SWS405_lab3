#!/bin/bash
# Lets Apache's PHP see the independently-running dema process, so Xplico's
# web UI health check (ps -p <dema_pid>) stops reporting "not running" when
# it actually is. See conversation for root cause (ProtectProc=invisible).
set -euo pipefail

mkdir -p /etc/systemd/system/apache2.service.d
cat > /etc/systemd/system/apache2.service.d/override.conf << 'EOF'
[Service]
ProtectProc=default
EOF

systemctl daemon-reload
systemctl restart apache2

echo "Done. Reload http://localhost:9876 and log in again."
