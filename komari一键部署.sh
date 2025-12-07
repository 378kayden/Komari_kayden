#!/bin/bash
set -uo pipefail
trap 'echo "Error: $BASH_COMMAND"; exit 1' ERR

KOMARI_PORT="25774"
SSL_DIR="/etc/nginx/ssl"
ACME_DIR="$HOME/.acme.sh"
ACME_EXEC="${ACME_DIR}/acme.sh"
DOMAIN=""
EMAIL=""
KOMARI_USER="admin"
KOMARI_PWD=""
LOG_FILE="/tmp/komari_deploy.log"
RETRY_TIMES=3
TIMEOUT=30

log() { echo "[`date +%F_%T`] $1" | tee -a "$LOG_FILE"; }

retry_download() {
    local URL="$1"; local OUTPUT="$2"; local COUNT=0
    rm -f "$OUTPUT"
    while [ $COUNT -lt $RETRY_TIMES ]; do
        if wget -q --timeout="$TIMEOUT" --no-check-certificate "$URL" -O "$OUTPUT"; then
            if [[ "$OUTPUT" == *.tar.gz ]] && ! tar -tzf "$OUTPUT" >/dev/null 2>&1; then rm -f "$OUTPUT"
            else log "download ok: $URL"; return 0; fi
        fi
        COUNT=$((COUNT+1)); sleep 3
    done
    log "download failed"; exit 1
}

check_port_used() {
    if ss -tulpn | grep -q ":$KOMARI_PORT "; then
        read -p "port used, change? y/n: " C
        if [ "$C" = "y" ]; then
            for P in {25775..25800}; do
                if ! ss -tulpn | grep -q ":$P "; then KOMARI_PORT="$P"; log "use $P"; return; fi
            done
            exit 1
        else systemctl stop komari 2>/dev/null; pkill -f komari 2>/dev/null; fi
    fi
}

backup_file() {
    [ -f "$1" ] && cp -f "$1" "$1.bak_$(date +%F_%T)"
}

fix_env() {
    rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock
    dpkg --configure -a
    apt update -y
}

fix_ssl_time() {
    apt install -y ca-certificates ntpdate
    update-ca-certificates
    ntpdate pool.ntp.org || true
}

install_acme() {
    mkdir -p "$ACME_DIR"; chmod 700 "$ACME_DIR"
    retry_download "https://cdn.jsdelivr.net/gh/acmesh-official/acme.sh@3.0.7/acme.sh" "$ACME_EXEC"
    chmod +x "$ACME_EXEC"
    "$ACME_EXEC" --set-default-ca --server zerossl
    "$ACME_EXEC" --register-account -m "$EMAIL" --force
    crontab -l 2>/dev/null | grep -q "$ACME_EXEC --cron" || \
        (crontab -l 2>/dev/null; echo "0 0 * * * $ACME_EXEC --cron") | crontab -
}

verify_ssl_cert() {
    openssl x509 -in "$SSL_DIR/$DOMAIN.crt" -noout -checkend 86400 || exit 1
}

clear
log "Start Komari deploy"
[ "$(id -u)" -ne 0 ] && log "Need root" && exit 1
check_port_used

read -p "domain: " DOMAIN
while ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; do read -p "domain: " DOMAIN; done

read -p "email: " EMAIL
while ! echo "$EMAIL" | grep -qE '^[^@]+@[^@]+\.[^@]+$'; do read -p "email: " EMAIL; done

fix_env
fix_ssl_time
apt install -y curl wget nginx-full socat cron openssl

[ ! -f "$ACME_EXEC" ] && install_acme

ACME_CERT_PATH="${ACME_DIR}/${DOMAIN}_ecc"
if [ ! -d "$ACME_CERT_PATH" ]; then
    systemctl stop nginx 2>/dev/null
    "$ACME_EXEC" --issue -d "$DOMAIN" --standalone -k ec-256 --force
    systemctl start nginx 2>/dev/null
fi

mkdir -p "$SSL_DIR"
cp -f "$ACME_CERT_PATH/$DOMAIN.key" "$SSL_DIR/"
cp -f "$ACME_CERT_PATH/fullchain.cer" "$SSL_DIR/$DOMAIN.crt"
chmod 600 "$SSL_DIR/$DOMAIN.key"
verify_ssl_cert
read -p "continue install? y/n: " X
[ "$X" != "y" ] && exit 0

if [ -f "/opt/komari/komari" ]; then
    read -p "found komari, overwrite? y/n: " C
    if [ "$C" = "y" ]; then
        systemctl stop komari; pkill -f komari
        retry_download "https://raw.githubusercontent.com/komari-monitor/komari/main/install-komari.sh" "install-komari.sh"
        chmod +x install-komari.sh; ./install-komari.sh -q 2>&1 | tee komari_install.log
    fi
else
    retry_download "https://raw.githubusercontent.com/komari-monitor/komari/main/install-komari.sh" "install-komari.sh"
    chmod +x install-komari.sh; ./install-komari.sh -q 2>&1 | tee komari_install.log
fi

KOMARI_PWD=$(grep -E "Password: [A-Za-z0-9]+" komari_install.log | awk '{print $2}')
[ -z "$KOMARI_PWD" ] && KOMARI_PWD="copy_from_log"

backup_file "/etc/systemd/system/komari.service"
cat > /etc/systemd/system/komari.service << EOF
[Unit]
Description=Komari Monitor
After=network.target nginx.service

[Service]
Type=simple
ExecStart=/opt/komari/komari server -l 0.0.0.0:${KOMARI_PORT}
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl restart komari
systemctl enable komari

backup_file "/etc/nginx/nginx.conf"
backup_file "/etc/nginx/conf.d/komari.conf"

cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 4096; }
http {
    sendfile on;
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
}
EOF

cat > /etc/nginx/conf.d/komari.conf << EOF
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;
    server_name ${DOMAIN};
    ssl_certificate ${SSL_DIR}/${DOMAIN}.crt;
    ssl_certificate_key ${SSL_DIR}/${DOMAIN}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:${KOMARI_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

nginx -t && systemctl restart nginx
rm -rf "$ACME_DIR/tmp" 2>/dev/null
chmod -R 600 "$SSL_DIR"
systemctl reload nginx

log "done"
echo "url: https://${DOMAIN}/admin"
echo "user: ${KOMARI_USER}"
echo "pwd: ${KOMARI_PWD}"
