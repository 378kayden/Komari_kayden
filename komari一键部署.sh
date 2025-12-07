#!/bin/bash
set -uo pipefail
trap 'echo "脚本执行出错：$BASH_COMMAND 失败"; exit 1' ERR

# 核心配置
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

# 基础日志函数
log() {
    local MSG="$1"
    local DATE=$(date +%Y-%m-%d_%H:%M:%S)
    echo "[$DATE] $MSG" | tee -a "${LOG_FILE}"
}

# 新增：展示证书时间+自动续约状态（Komari前强制核对）
show_cert_info() {
    log "==================== 证书信息核对 ===================="
    # 服务器IP
    local SERVER_IP=$(curl -s icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
    echo "服务器公网IP：${SERVER_IP}"
    echo "部署域名：${DOMAIN}"
    echo "证书绑定邮箱：${EMAIL}"
    
    # 证书时间检测
    if [ -f "${SSL_DIR}/${DOMAIN}.crt" ]; then
        local CERT_START=$(openssl x509 -in "${SSL_DIR}/${DOMAIN}.crt" -noout -startdate | cut -d= -f2)
        local CERT_END=$(openssl x509 -in "${SSL_DIR}/${DOMAIN}.crt" -noout -enddate | cut -d= -f2)
        local END_TIMESTAMP=$(date -d "${CERT_END}" +%s 2>/dev/null)
        local NOW_TIMESTAMP=$(date +%s)
        if [ -n "${END_TIMESTAMP}" ] && [ "${END_TIMESTAMP}" -gt "${NOW_TIMESTAMP}" ]; then
            local CERT_DAYS=$(( (END_TIMESTAMP - NOW_TIMESTAMP) / 86400 ))
            echo "证书生效时间：${CERT_START}"
            echo "证书过期时间：${CERT_END}"
            echo "证书剩余有效期：${CERT_DAYS} 天"
        else
            echo "证书状态：已存在，但有效期解析失败（请手动验证）"
        fi
    else
        echo "证书状态：未生成（将在后续步骤申请）"
    fi

    # 新增：检测acme.sh自动续约定时任务（核心）
    echo -e "\n==== 自动续约检测 ===="
    if crontab -l 2>/dev/null | grep -q "${ACME_EXEC} --cron"; then
        echo "✅ 自动续约定时任务已生效（每天0点执行续约）"
    else
        echo "❌ 自动续约定时任务未配置！"
    fi

    # 强制确认：必须输入y才继续
    read -p $'\n以上证书信息已核对，是否继续部署？(y/n)：' CHOICE
    case "${CHOICE}" in
        y|Y) log "确认继续部署";;
        n|N) log "用户取消部署，脚本退出"; exit 0;;
        *) log "输入无效，脚本退出"; exit 1;;
    esac
    log "======================================================"
}

# 下载重试
retry_download() {
    local URL="$1"
    local OUTPUT="$2"
    local COUNT=0
    rm -f "${OUTPUT}"
    while [ ${COUNT} -lt ${RETRY_TIMES} ]; do
        if wget -q --timeout="${TIMEOUT}" --no-check-certificate "${URL}" -O "${OUTPUT}"; then
            if [[ "${OUTPUT}" == *.tar.gz ]] && ! tar -tzf "${OUTPUT}" >/dev/null 2>&1; then
                log "压缩包损坏：${OUTPUT}"; rm -f "${OUTPUT}"
            else
                log "下载成功：${URL}"; return 0
            fi
        fi
        COUNT=$((COUNT+1))
        log "下载失败，3秒后重试（${COUNT}/${RETRY_TIMES}）"
        sleep 3
    done
    log "下载失败（重试${RETRY_TIMES}次）"; exit 1
}

# 端口检查
check_port_used() {
    if ss -tulpn | grep -q ":${KOMARI_PORT} "; then
        log "端口${KOMARI_PORT}已被占用"
        read -p "选择：1=换端口 2=停旧服务 (1/2)：" CHOICE
        case "${CHOICE}" in
            1) for NEW_PORT in {25775..25800}; do
                if ! ss -tulpn | grep -q ":${NEW_PORT} "; then
                    KOMARI_PORT="${NEW_PORT}"; log "已换端口：${NEW_PORT}"; return 0
                fi
            done; log "无可用端口"; exit 1;;
            2) systemctl stop komari 2>/dev/null; pkill -f komari 2>/dev/null; log "已停旧服务";;
            *) log "输入无效"; exit 1;;
        esac
    fi
    log "端口${KOMARI_PORT}未被占用"
}

# 文件备份
backup_file() {
    local FILE="$1"
    if [ -f "${FILE}" ]; then
        local BACKUP_FILE="${FILE}.bak_$(date +%Y%m%d_%H%M%S)"
        cp -f "${FILE}" "${BACKUP_FILE}"
        log "已备份配置：${BACKUP_FILE}"
    fi
}

# 修复apt环境
fix_apt_env() {
    log "修复apt环境"
    rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null
    dpkg --configure -a 2>/dev/null
    if [ -f "/etc/apt/sources.list" ]; then
        backup_file "/etc/apt/sources.list"
        cat > /etc/apt/sources.list << EOF
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF
    fi
    apt update -y 2>/dev/null
    log "apt环境修复完成"
}

# 修复CA证书和时间
fix_ssl_ca_and_time() {
    log "修复CA证书/时间"
    apt install -y ca-certificates ntpdate 2>/dev/null
    update-ca-certificates --fresh 2>/dev/null
    ntpdate pool.ntp.org 2>/dev/null || log "时间同步失败（继续执行）"
    log "CA证书/时间修复完成"
}

# 安装acme.sh（确保自动续约任务被配置）
install_acme_sh_manual() {
    log "安装acme.sh"
    mkdir -p "${ACME_DIR}"; chmod 700 "${ACME_DIR}"
    local DOWNLOAD_SOURCES=("https://cdn.jsdelivr.net/gh/acmesh-official/acme.sh@3.0.7/acme.sh")
    retry_download "${DOWNLOAD_SOURCES[0]}" "${ACME_EXEC}"
    chmod +x "${ACME_EXEC}"
    "${ACME_EXEC}" --set-default-ca --server zerossl 2>/dev/null
    "${ACME_EXEC}" --register-account -m "${EMAIL}" --force 2>/dev/null
    # 强制配置自动续约定时任务（避免漏配）
    if ! crontab -l 2>/dev/null | grep -q "${ACME_EXEC} --cron"; then
        (crontab -l 2>/dev/null; echo "0 0 * * * ${ACME_EXEC} --cron --log ${LOG_FILE} > /dev/null") | crontab -
        log "已配置自动续约定时任务（每天0点执行）"
    fi
    log "acme.sh安装完成"
}

# 提取Komari密码
extract_komari_password() {
    log "提取Komari密码"
    KOMARI_PWD=$(grep "初始登录信息" -A1 komari_install.log | grep -o "Password: [^, ]*" | awk '{print $2}')
    if [ -z "${KOMARI_PWD}" ]; then
        KOMARI_PWD=$(grep -E "Password: [A-Za-z0-9]+" komari_install.log | awk '{print $2}')
    fi
    if [ -z "${KOMARI_PWD}" ]; then
        log "自动提取失败！请从安装日志复制密码"
        KOMARI_PWD="请手动复制"
    else
        log "密码提取成功：${KOMARI_PWD}"
    fi
}

# 检查Gzip模块
check_nginx_gzip_module() {
    log "检查Gzip模块"
    NGINX_V_OUTPUT=$(nginx -V 2>&1)
    if echo "${NGINX_V_OUTPUT}" | grep -q -- "--with-http_gzip"; then
        log "Gzip模块已加载"
    else
        log "Debian nginx-full默认包含Gzip功能"
    fi
}

# 配置Nginx
config_nginx() {
    log "配置Nginx"
    backup_file "/etc/nginx/nginx.conf"
    backup_file "/etc/nginx/conf.d/komari.conf"
    cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 10240;
    use epoll;
}

http {
    gzip on;
    gzip_vary on;
    gzip_comp_level 9;
    gzip_min_length 1;
    gzip_types *;
    gzip_static on;

    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    server_tokens off;

    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" "\$http_user_agent"';
    access_log /var/log/nginx/access.log main;
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
        gzip on;
        proxy_pass http://127.0.0.1:${KOMARI_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    if [ -f "/etc/nginx/sites-enabled/default" ]; then
        rm -f "/etc/nginx/sites-enabled/default"; log "已删默认配置"
    fi
    if ! grep -q "X-XSS-Protection" /etc/nginx/conf.d/komari.conf; then
        sed -i '/listen \[::\]:443 ssl http2;/a \    add_header X-XSS-Protection "1; mode=block" always;' /etc/nginx/conf.d/komari.conf
        log "已加安全响应头"
    fi
    if nginx -t 2>/dev/null; then
        systemctl restart nginx 2>/dev/null; log "Nginx已重启（Gzip压缩已生效）"
    else
        log "Nginx配置错误！执行nginx -t查看"
    fi
}

# 验证SSL证书
verify_ssl_cert() {
    log "验证SSL证书"
    if openssl x509 -in "${SSL_DIR}/${DOMAIN}.crt" -noout -checkend 86400 2>/dev/null; then
        log "证书有效（剩余>24小时）"
    else
        log "证书无效！"; exit 1
    fi
}

# 清理冗余
clean_redundant() {
    log "清理冗余文件"
    rm -rf "${ACME_DIR}/tmp" komari_install.log 2>/dev/null
    chmod -R 600 "${SSL_DIR}"
    systemctl reload nginx 2>/dev/null
    log "清理完成"
}

# ===================== 主流程 =====================
clear
log "Komari 一键部署脚本"

# 权限检查
if [ "$(id -u)" -ne 0 ]; then
    log "请用root权限运行（sudo ./脚本名.sh）"; exit 1
fi

# 端口检查
check_port_used

# 输入域名
log "请先解析域名到本服务器公网IP"
read -p "请输入你的域名：" DOMAIN
while [ -z "${DOMAIN}" ] || ! echo "${DOMAIN}" | grep -qE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; do
    log "域名格式错误！请输入如tz.2z99.com"
    read -p "请输入你的域名：" DOMAIN
done
log "域名确认：${DOMAIN}"

# 输入邮箱
read -p "请输入你的邮箱：" EMAIL
while [ -z "${EMAIL}" ] || ! echo "${EMAIL}" | grep -qE '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; do
    log "邮箱格式错误！请输入如xxx@xxx.com"
    read -p "请输入你的邮箱：" EMAIL
done
log "邮箱确认：${EMAIL}"

# 基础环境修复
fix_apt_env
fix_ssl_ca_and_time

# 安装基础工具
log "安装基础工具"
apt install -y curl wget nano nginx-full socat cron openssl 2>/dev/null
log "基础工具安装完成"

# 检查Gzip模块
check_nginx_gzip_module() {
    log "检查Gzip模块"
    NGINX_V_OUTPUT=$(nginx -V 2>&1)
    if echo "${NGINX_V_OUTPUT}" | grep -q -- "--with-http_gzip"; then
        log "Gzip模块已加载"
    else
        log "Debian nginx-full默认包含Gzip功能"
    fi
}

# 安装acme.sh
if [ ! -f "${ACME_EXEC}" ]; then
    install_acme_sh_manual
else
    log "acme.sh已安装"
    # 检查已安装的acme.sh是否配置了自动续约
    if ! crontab -l 2>/dev/null | grep -q "${ACME_EXEC} --cron"; then
        (crontab -l 2>/dev/null; echo "0 0 * * * ${ACME_EXEC} --cron --log ${LOG_FILE} > /dev/null") | crontab -
        log "补全自动续约定时任务"
    fi
fi

# 申请SSL证书
log "申请SSL证书"
ACME_CERT_PATH="${ACME_DIR}/${DOMAIN}_ecc"
if [ ! -d "${ACME_CERT_PATH}" ]; then
    systemctl stop nginx 2>/dev/null
    "${ACME_EXEC}" --issue -d "${DOMAIN}" --standalone -k ec-256 --force 2>/dev/null
    systemctl start nginx 2>/dev/null
    log "证书申请成功"
else
    log "证书已存在"
fi

# 配置证书
mkdir -p "${SSL_DIR}"
cp -f "${ACME_CERT_PATH}/${DOMAIN}.key" "${SSL_DIR}/"
cp -f "${ACME_CERT_PATH}/fullchain.cer" "${SSL_DIR}/${DOMAIN}.crt"
chmod 600 "${SSL_DIR}/${DOMAIN}.key"
verify_ssl_cert

# ========== 核心修复：强制展示证书信息+续约检测，确认后才继续 ==========
show_cert_info

# Komari安装逻辑
log "检查Komari安装状态"
if [ -f "/opt/komari/komari" ]; then
    read -p "Komari已安装，是否覆盖？(y/n)：" CHOICE
    case "${CHOICE}" in
        y|Y)
            log "开始覆盖安装Komari"
            systemctl stop komari 2>/dev/null; pkill -f komari 2>/dev/null
            retry_download "https://raw.githubusercontent.com/komari-monitor/komari/main/install-komari.sh" "install-komari.sh"
            chmod +x install-komari.sh; ./install-komari.sh -q 2>&1 | tee komari_install.log
            log "Komari覆盖完成"
            
            extract_komari_password
            log "配置Komari服务"
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
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload 2>/dev/null
            systemctl restart komari 2>/dev/null; systemctl enable komari 2>/dev/null
            if systemctl is-active --quiet komari; then
                log "Komari服务已启动"
            else
                log "Komari启动失败！查看日志：${LOG_FILE}"
            fi
            ;;
        n|N)
            log "跳过Komari安装，直接配置Nginx+压缩"
            ;;
        *)
            log "输入无效，跳过Komari安装"
            ;;
    esac
else
    log "开始全新安装Komari"
    retry_download "https://raw.githubusercontent.com/komari-monitor/komari/main/install-komari.sh" "install-komari.sh"
    chmod +x install-komari.sh; ./install-komari.sh -q 2>&1 | tee komari_install.log
    log "Komari全新安装完成"
    
    extract_komari_password
    log "配置Komari服务"
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
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>/dev/null
    systemctl restart komari 2>/dev/null; systemctl enable komari 2>/dev/null
    if systemctl is-active --quiet komari; then
        log "Komari服务已启动"
    else
        log "Komari启动失败！查看日志：${LOG_FILE}"
    fi
fi

# 配置Nginx
config_nginx

# 服务状态检查
log "服务状态测试"
if systemctl is-active --quiet komari && systemctl is-active --quiet nginx; then
    log "Komari+Nginx均运行正常（Gzip压缩已配置）"
else
    log "服务未正常运行！"
fi

# 清理冗余
clean_redundant

# 部署完成
log "部署完成！"
log "访问地址：https://${DOMAIN}/admin"
log "登录账号：${KOMARI_USER}"
log "登录密码：${KOMARI_PWD}"
log "请立即修改默认密码！"
log "日志文件：${LOG_FILE}"
