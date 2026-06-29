#!/bin/sh
# spot-server — Instalación mínima en Alpine Linux
# Solo backend binario, paquetes esenciales, OpenRC service

set -e

SPOT_USER="${SPOT_USER:-spot}"
SPOT_DIR="/opt/spot"
SPOT_PORT="${SPOT_PORT:-1801}"
WG_PORT="${WG_PORT:-51820}"

echo "=== spot-server Alpine ==="

# 1. Paquetes mínimos
apk add --no-cache python3 wireguard-tools openrc iptables

# 2. Usuario
adduser -D -s /sbin/nologin "$SPOT_USER" 2>/dev/null || true

# 3. Directorio
mkdir -p "$SPOT_DIR"/data
cp spot-server.py "$SPOT_DIR/"
chmod +x "$SPOT_DIR/spot-server.py"
chown -R "$SPOT_USER:$SPOT_USER" "$SPOT_DIR"

# 4. Servicio OpenRC
cat > /etc/init.d/spot-server << 'EOF'
#!/sbin/openrc-run
description="spot-server — Protocolo binario SP"
SPOT_DIR="/opt/spot"
SPOT_PORT="1801"
SPOT_BIND="0.0.0.0"

depend() { need net; }

start() {
    checkpath -d -m 0755 -o spot:spot "$SPOT_DIR/data"
    start-stop-daemon --start --background \
        --make-pidfile --pidfile /run/spot-server.pid \
        --user spot --group spot \
        --exec /usr/bin/python3 -- "$SPOT_DIR/spot-server.py" \
        --port "$SPOT_PORT" --bind "$SPOT_BIND"
}

stop() {
    start-stop-daemon --stop --pidfile /run/spot-server.pid
}
EOF
chmod +x /etc/init.d/spot-server

# 5. Firewall mínimo
cat > /etc/init.d/spot-firewall << 'EOF'
#!/sbin/openrc-run
description="spot-firewall"
depend() { need net; }
start() {
    iptables -A INPUT -p tcp --dport 1801 -j ACCEPT
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT
}
stop() {
    iptables -D INPUT -p tcp --dport 1801 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null || true
}
EOF
chmod +x /etc/init.d/spot-firewall

# 6. Iniciar
rc-service spot-firewall start 2>/dev/null || true
rc-service spot-server start 2>/dev/null || true

echo "=== spot-server listo en :$SPOT_PORT ==="
echo "   Servicio: rc-service spot-server {start|stop|restart}"
echo "   Logs: tail -f /var/log/messages"
echo "   Puerto: $SPOT_PORT TCP"
echo "   WireGuard: $WG_PORT UDP (configurar peers aparte)"
