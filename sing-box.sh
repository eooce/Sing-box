#!/bin/bash

# =========================
# 老王sing-box四合一安装脚本
# vless-version-reality|vmess-ws-tls(tunnel)|hysteria2|tuic5
# 最后更新时间: 2026.5.28[新增Anytls，socks5，ss2022(有封ip风险,建议ipv6使用)等协议]
# =========================

export LANG=en_US.UTF-8
# 定义颜色
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
skyblue="\e[1;36m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 定义常量
server_name="sing-box"
work_dir="/etc/sing-box"
conf_dir="${work_dir}/conf"
client_dir="${work_dir}/url.txt"
export vless_port=${PORT:-$(shuf -i 1000-65000 -n 1)}
export CFIP=${CFIP:-'cdns.doon.eu.org'} 
export CFPORT=${CFPORT:-'443'} 

# 检查是否为root下运行
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# 检查命令是否存在函数
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查服务状态通用函数
check_service() {
    local service_name=$1
    local service_file=$2
    
    [[ ! -f "${service_file}" ]] && { red "not installed"; return 2; }
        
    if command_exists apk; then
        rc-service "${service_name}" status | grep -q "started" && green "running" || yellow "not running"
    else
        systemctl is-active "${service_name}" | grep -q "^active$" && green "running" || yellow "not running"
    fi
    return $?
}

# 检查sing-box状态
check_singbox() {
    check_service "sing-box" "${work_dir}/${server_name}"
}

# 检查argo状态
check_argo() {
    check_service "argo" "${work_dir}/argo"
}

# 检查nginx状态
check_nginx() {
    command_exists nginx || { red "not installed"; return 2; }
    check_service "nginx" "$(command -v nginx)"
}

# 根据系统类型安装、卸载依赖
manage_packages() {
    if [ $# -lt 2 ]; then
        red "Unspecified package name or action"
        return 1
    fi

    action=$1
    shift

    # 工作目录不存在说明是首次安装，需要更新系统
    if [ "$action" == "install" ] && [ ! -d "$work_dir" ]; then
        yellow "正在更新系统软件包...\n"
        if command_exists apt; then
            DEBIAN_FRONTEND=noninteractive apt update -y && DEBIAN_FRONTEND=noninteractive apt upgrade -y
        elif command_exists dnf; then
            dnf update -y
        elif command_exists yum; then
            yum update -y
        elif command_exists apk; then
            apk update && apk upgrade
        else
            yellow "Unknown system!\n"
        fi
        green "finished updated system\n"
    fi

    for package in "$@"; do
        if [ "$action" == "install" ]; then
            if command_exists "$package"; then
                green "${package} already installed"
                continue
            fi
            yellow "正在安装 ${package}..."
            if command_exists apt; then
                DEBIAN_FRONTEND=noninteractive apt install -y "$package"
            elif command_exists dnf; then
                dnf install -y "$package"
            elif command_exists yum; then
                yum install -y "$package"
            elif command_exists apk; then
                apk add "$package"
            else
                red "Unknown system!"
                return 1
            fi
        elif [ "$action" == "uninstall" ]; then
            if ! command_exists "$package"; then
                yellow "${package} is not installed"
                continue
            fi
            yellow "正在卸载 ${package}..."
            if command_exists apt; then
                apt remove -y "$package" && apt autoremove -y
            elif command_exists dnf; then
                dnf remove -y "$package" && dnf autoremove -y
            elif command_exists yum; then
                yum remove -y "$package" && yum autoremove -y
            elif command_exists apk; then
                apk del "$package"
            else
                red "Unknown system!"
                return 1
            fi
        else
            red "Unknown action: $action"
            return 1
        fi
    done

    return 0
}

# 获取ip
get_realip() {
    ip=$(curl -4 -sm 2 ip.sb)
    ipv6() { curl -6 -sm 2 ip.sb; }
    if [ -z "$ip" ]; then
        echo "[$(ipv6)]"
    else 
        if curl -4 -sm 2 http://ipinfo.io/org | grep -qE 'Cloudflare|UnReal|AEZA|Andrei'; then
            echo "[$(ipv6)]"
        else
            if grep -qE '^\s*precedence\s+::ffff:0:0/96\s+100' "/etc/gai.conf" 2>/dev/null; then
                echo "$ip"
            else
                v6=$(ipv6)
                [ -n "$v6" ] && echo "[$v6]" || echo "$ip"
            fi
        fi
    fi
}

# 处理防火墙
allow_port() {
    has_ufw=0
    has_firewalld=0
    has_iptables=0
    has_ip6tables=0

    command_exists ufw && has_ufw=1
    command_exists firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1 && has_firewalld=1
    command_exists iptables && has_iptables=1
    command_exists ip6tables && has_ip6tables=1

    [ "$has_ufw" -eq 1 ] && ufw --force default allow outgoing >/dev/null 2>&1
    [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --zone=public --set-target=ACCEPT >/dev/null 2>&1
    [ "$has_iptables" -eq 1 ] && {
        iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -i lo -j ACCEPT
        iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p icmp -j ACCEPT
        iptables -P FORWARD DROP 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
    }
    [ "$has_ip6tables" -eq 1 ] && {
        ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -I INPUT 3 -i lo -j ACCEPT
        ip6tables -C INPUT -p icmp -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p icmp -j ACCEPT
        ip6tables -P FORWARD DROP 2>/dev/null || true
        ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    }

    for rule in "$@"; do
        port=${rule%/*}
        proto=${rule#*/}
        [ "$has_ufw" -eq 1 ] && ufw allow in ${port}/${proto} >/dev/null 2>&1
        [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --add-port=${port}/${proto} >/dev/null 2>&1
        [ "$has_iptables" -eq 1 ] && (iptables -C INPUT -p ${proto} --dport ${port} -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p ${proto} --dport ${port} -j ACCEPT)
        [ "$has_ip6tables" -eq 1 ] && (ip6tables -C INPUT -p ${proto} --dport ${port} -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p ${proto} --dport ${port} -j ACCEPT)
    done

    [ "$has_firewalld" -eq 1 ] && firewall-cmd --reload >/dev/null 2>&1

    if command_exists rc-service 2>/dev/null; then
        [ "$has_iptables" -eq 1 ] && iptables-save > /etc/iptables/rules.v4 2>/dev/null
        [ "$has_ip6tables" -eq 1 ] && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
    else
        if ! command_exists netfilter-persistent; then
            manage_packages install iptables-persistent || yellow "请手动安装netfilter-persistent或保存iptables规则"
            netfilter-persistent save >/dev/null 2>&1
        elif command_exists service; then
            service iptables save 2>/dev/null
            service ip6tables save 2>/dev/null
        fi
    fi
}

# 下载并安装 sing-box,cloudflared
install_singbox() {
    clear
    purple "正在安装sing-box中，请稍后..."
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64' | 'amd64')  ARCH='amd64' ;;
        'x86' | 'i686' | 'i386') ARCH='386' ;;
        'aarch64' | 'arm64') ARCH='arm64' ;;
        'armv7l')  ARCH='armv7' ;;
        's390x')   ARCH='s390x' ;;
        *) red "不支持的架构: ${ARCH_RAW}"; exit 1 ;;
    esac

    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}" && mkdir -p "${conf_dir}"
    curl -sLo "${work_dir}/argo"     "https://$ARCH.ssss.nyc.mn/bot"
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sb"
    curl -sLo "${work_dir}/qrencode" "https://$ARCH.ssss.nyc.mn/qrencode"
    chown root:root ${work_dir} && chmod +x ${work_dir}/${server_name} ${work_dir}/argo ${work_dir}/qrencode

    nginx_port=$(($vless_port + 1))
    tuic_port=$(($vless_port + 2))
    hy2_port=$(($vless_port + 3))
    uuid=$(cat /proc/sys/kernel/random/uuid)
    password=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 24)
    output=$(/etc/sing-box/sing-box generate reality-keypair)
    private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')

    allow_port $vless_port/tcp $nginx_port/tcp $tuic_port/udp $hy2_port/udp > /dev/null 2>&1

    openssl ecparam -genkey -name prime256v1 -out "${work_dir}/private.key"
    openssl req -new -x509 -days 3650 -key "${work_dir}/private.key" -out "${work_dir}/cert.pem" -subj "/CN=bing.com"

    dns_strategy=$(ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 && echo "prefer_ipv4" || \
        (ping -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1 && echo "prefer_ipv6" || echo "prefer_ipv4"))

    cat > "${conf_dir}/log.json" << EOF
{
  "log": {
    "disabled": false,
    "level": "error",
    "output": "$work_dir/sb.log",
    "timestamp": true
  }
}
EOF

    cat > "${conf_dir}/dns.json" << EOF
{
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "local",
        "strategy": "$dns_strategy"
      }
    ]
  }
}
EOF

    cat > "${conf_dir}/inbounds.json" << EOF
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": $vless_port,
      "users": [
        {
          "uuid": "$uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.iij.ad.jp",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.iij.ad.jp",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": [""]
        }
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": 8001,
      "users": [
        {
          "uuid": "$uuid"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess-argo",
        "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2",
      "listen": "::",
      "listen_port": $hy2_port,
      "users": [
        {
          "password": "$uuid"
        }
      ],
      "ignore_client_bandwidth": false,
      "masquerade": "https://bing.com",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "min_version": "1.3",
        "max_version": "1.3",
        "certificate_path": "$work_dir/cert.pem",
        "key_path": "$work_dir/private.key"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": $tuic_port,
      "users": [
        {
          "uuid": "$uuid",
          "password": "$uuid"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "$work_dir/cert.pem",
        "key_path": "$work_dir/private.key"
      }
    }
  ]
}
EOF

    cat > "${conf_dir}/outbounds.json" << EOF
{
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF

    cat > "${conf_dir}/endpoints.json" << EOF
{
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "mtu": 1280,
      "address": [
        "172.16.0.2/32",
        "2606:4700:110:8dfe:d141:69bb:6b80:925/128"
      ],
      "private_key": "YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=",
      "peers": [
        {
          "address": "engage.cloudflareclient.com",
          "port": 2408,
          "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "allowed_ips": ["0.0.0.0/0", "::/0"],
          "reserved": [78, 135, 76]
        }
      ]
    }
  ]
}
EOF

    cat > "${conf_dir}/route.json" << EOF
{
  "route": {
    "rule_set": [
      {"tag":"gemini","type":"remote","format":"binary","url":"https://main.ssss.nyc.mn/gemini.srs","download_detour":"direct"},
      {"tag":"claude","type":"remote","format":"binary","url":"https://main.ssss.nyc.mn/claude.srs","download_detour":"direct"},
      {"tag":"openai","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/openai.srs","download_detour":"direct"},
      {"tag":"tiktok","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/tiktok.srs","download_detour":"direct"},
      {"tag":"twitter","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/twitter.srs","download_detour":"direct"},
      {"tag":"google","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/google.srs","download_detour":"direct"},
      {"tag":"telegram","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/telegram.srs","download_detour":"direct"},
      {"tag":"youtube","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/youtube.srs","download_detour":"direct"},
      {"tag":"netflix","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/netflix.srs","download_detour":"direct"}
    ],
    "rules": [{"rule_set": []}],
    "final": "direct"
  }
}
EOF
}

# debian/ubuntu/centos 守护进程
main_systemd_services() {
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/etc/sing-box/sing-box run -C /etc/sing-box/conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
NoNewPrivileges=yes
TimeoutStartSec=0
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1"
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    if [ -f /etc/centos-release ]; then
        yum install -y chrony
        systemctl start chronyd
        systemctl enable chronyd
        chronyc -a makestep
        yum update -y ca-certificates
        bash -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    fi
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl enable argo
    systemctl start argo
}

# 适配alpine 守护进程
alpine_openrc_services() {
    cat > /etc/init.d/sing-box << 'EOF'
#!/sbin/openrc-run
description="sing-box service"
command="/etc/sing-box/sing-box"
command_args="run -C /etc/sing-box/conf"
command_background=true
pidfile="/var/run/sing-box.pid"
EOF

    cat > /etc/init.d/argo << 'EOF'
#!/sbin/openrc-run
description="Cloudflare Tunnel"
command="/bin/sh"
command_args="-c '/etc/sing-box/argo tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1'"
command_background=true
pidfile="/var/run/argo.pid"
EOF

    chmod +x /etc/init.d/sing-box
    chmod +x /etc/init.d/argo
    rc-update add sing-box default > /dev/null 2>&1
    rc-update add argo default     > /dev/null 2>&1
}

# 从已安装配置中获取UUID
get_current_uuid() {
    local inbounds_file="${conf_dir}/inbounds.json"
    if [ -f "$inbounds_file" ]; then
        local uuid
        uuid=$(jq -r '.inbounds[] | select(.type == "vless") | .users[0].uuid // empty' "$inbounds_file" 2>/dev/null | head -1)
        [ -z "$uuid" ] && uuid=$(jq -r '.inbounds[] | select(.type == "vmess") | .users[0].uuid // empty' "$inbounds_file" 2>/dev/null | head -1)
        [ -z "$uuid" ] && uuid=$(jq -r '.inbounds[] | select(.type == "hysteria2") | .users[0].password // empty' "$inbounds_file" 2>/dev/null | head -1)
        echo "$uuid"
    fi
}

# 生成节点和订阅链接
get_info() {
    yellow "\nip检测中,请稍等...\n"
    server_ip=$(get_realip)
    clear
    isp=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" | tr -d '\n' | \
        awk -F\" '{c="";i="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="isp")i=$(x+2)};if(c&&i)print c"-"i}' | \
        sed 's/ /_/g' || \
        curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://ipapi.co/json" | tr -d '\n' | \
        awk -F\" '{c="";o="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="org")o=$(x+2)};if(c&&o)print c"-"o}' | \
        sed 's/ /_/g' || echo "$hostname")

    if [ -f "${work_dir}/argo.log" ]; then
        for i in {1..5}; do
            purple "第 $i 次尝试获取ArgoDoamin中..."
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
            [ -n "$argodomain" ] && break
            sleep 2
        done
    else
        restart_argo
        sleep 6
        argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
    fi

    green "\nArgoDomain：${purple}$argodomain${re}\n"

    VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"firefox\", \"allowlnsecure\": \"flase\"}"

    # 保留已有额外协议行
    extra_lines=""
    if [ -f "${client_dir}" ]; then
        extra_lines=$(grep -vE '^(vless://|vmess://|hysteria2://|tuic://)' "${client_dir}" || true)
    fi

    cat > ${work_dir}/url.txt << EOF
vless://${uuid}@${server_ip}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${public_key}&type=tcp&headerType=none#${isp}

vmess://$(echo "$VMESS" | base64 -w0)

hysteria2://${uuid}@${server_ip}:${hy2_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}

tuic://${uuid}:${uuid}@${server_ip}:${tuic_port}?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#${isp}
EOF

    if [ -n "$extra_lines" ]; then
        echo "" >> "${work_dir}/url.txt"
        echo "$extra_lines" >> "${work_dir}/url.txt"
    fi

    echo ""
    while IFS= read -r line; do echo -e "${purple}$line"; done < ${work_dir}/url.txt
    base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt
    chmod 644 ${work_dir}/sub.txt
    yellow "\n温馨提醒：需打开V2rayN或其他软件里的 "跳过证书验证"，或将节点的Insecure或TLS里设置为"true"\n"
    green "V2rayN,Shadowrocket,Nekobox,Loon,Karing,Sterisand订阅链接：http://${server_ip}:${nginx_port}/${password}\n"
    $work_dir/qrencode "http://${server_ip}:${nginx_port}/${password}"
    yellow "\n=========================================================================================="
    green "\n\nClash,Mihomo系列订阅链接：https://sublink.eooce.com/clash?config=http://${server_ip}:${nginx_port}/${password}\n"
    $work_dir/qrencode "https://sublink.eooce.com/clash?config=http://${server_ip}:${nginx_port}/${password}"
    yellow "\n=========================================================================================="
    green "\n\nSing-box订阅链接：https://sublink.eooce.com/singbox?config=http://${server_ip}:${nginx_port}/${password}\n"
    $work_dir/qrencode "https://sublink.eooce.com/singbox?config=http://${server_ip}:${nginx_port}/${password}"
    yellow "\n=========================================================================================="
    green "\n\nSurge订阅链接：https://sublink.eooce.com/surge?config=http://${server_ip}:${nginx_port}/${password}\n"
    $work_dir/qrencode "https://sublink.eooce.com/surge?config=http://${server_ip}:${nginx_port}/${password}"
    yellow "\n==========================================================================================\n"
}

# nginx订阅配置
add_nginx_conf() {
    if ! command_exists nginx; then
        red "nginx未安装,无法配置订阅服务"
        return 1
    else
        manage_service "nginx" "stop" > /dev/null 2>&1
        pkill nginx > /dev/null 2>&1
    fi

    mkdir -p /etc/nginx/conf.d
    [[ -f "/etc/nginx/conf.d/sing-box.conf" ]] && cp /etc/nginx/conf.d/sing-box.conf /etc/nginx/conf.d/sing-box.conf.bak.sb

    cat > /etc/nginx/conf.d/sing-box.conf << EOF
server {
    listen $nginx_port;
    listen [::]:$nginx_port;
    server_name _;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location = /$password {
        alias /etc/sing-box/sub.txt;
        default_type 'text/plain; charset=utf-8';
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires "0";
    }

    location / { return 404; }

    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

    if [ -f "/etc/nginx/nginx.conf" ]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.sb > /dev/null 2>&1
        sed -i -e '15{/include \/etc\/nginx\/modules\/\*\.conf/d;}' \
               -e '18{/include \/etc\/nginx\/conf\.d\/\*\.conf/d;}' /etc/nginx/nginx.conf > /dev/null 2>&1
        if ! grep -q "include.*conf.d" /etc/nginx/nginx.conf; then
            http_end_line=$(grep -n "^}" /etc/nginx/nginx.conf | tail -1 | cut -d: -f1)
            [ -n "$http_end_line" ] && sed -i "${http_end_line}i \    include /etc/nginx/conf.d/*.conf;" /etc/nginx/nginx.conf > /dev/null 2>&1
        fi
    else
        cat > /etc/nginx/nginx.conf << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events { worker_connections 1024; }

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    include /etc/nginx/conf.d/*.conf;
}
EOF
    fi

    if nginx -t > /dev/null 2>&1; then
        nginx -s reload > /dev/null 2>&1 || start_nginx > /dev/null 2>&1
        green "nginx订阅配置已加载"
    else
        yellow "nginx配置检测失败，尝试重启..."
        restart_nginx > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            [[ -f "/etc/nginx/nginx.conf.bak.sb" ]] && cp "/etc/nginx/nginx.conf.bak.sb" /etc/nginx/nginx.conf > /dev/null 2>&1
            restart_nginx > /dev/null 2>&1
        fi
    fi
}

# 通用服务管理函数
manage_service() {
    local service_name="$1"
    local action="$2"

    if [ -z "$service_name" ] || [ -z "$action" ]; then
        red "缺少服务名或操作参数\n"; return 1
    fi

    local status=$(check_service "$service_name" 2>/dev/null)

    case "$action" in
        "start")
            [ "$status" == "running" ] && { yellow "${service_name} 正在运行\n"; return 0; }
            [ "$status" == "not installed" ] && { yellow "${service_name} 尚未安装!\n"; return 1; }
            yellow "正在启动 ${service_name} 服务\n"
            if command_exists rc-service; then rc-service "$service_name" start
            elif command_exists systemctl; then systemctl daemon-reload && systemctl start "$service_name"; fi
            [ $? -eq 0 ] && green "${service_name} 服务已成功启动\n" || red "${service_name} 服务启动失败\n"
            ;;
        "stop")
            [ "$status" == "not installed" ] && { yellow "${service_name} 尚未安装！\n"; return 2; }
            [ "$status" == "not running" ]   && { yellow "${service_name} 未运行\n"; return 1; }
            yellow "正在停止 ${service_name} 服务\n"
            if command_exists rc-service; then rc-service "$service_name" stop
            elif command_exists systemctl; then systemctl stop "$service_name"; fi
            [ $? -eq 0 ] && green "${service_name} 服务已成功停止\n" || red "${service_name} 服务停止失败\n"
            ;;
        "restart")
            [ "$status" == "not installed" ] && { yellow "${service_name} 尚未安装！\n"; return 1; }
            yellow "正在重启 ${service_name} 服务\n"
            if command_exists rc-service; then rc-service "$service_name" restart
            elif command_exists systemctl; then systemctl daemon-reload && systemctl restart "$service_name"; fi
            [ $? -eq 0 ] && green "${service_name} 服务已成功重启\n" || red "${service_name} 服务重启失败\n"
            ;;
        *)
            red "无效的操作: $action\n"; return 1 ;;
    esac
}

start_singbox()  { manage_service "sing-box" "start"; }
stop_singbox()   { manage_service "sing-box" "stop"; }
restart_singbox(){ manage_service "sing-box" "restart"; }
start_argo()     { manage_service "argo" "start"; }
stop_argo()      { manage_service "argo" "stop"; }
restart_argo()   { manage_service "argo" "restart"; }
start_nginx()    { manage_service "nginx" "start"; }
restart_nginx()  { manage_service "nginx" "restart"; }

# 卸载 sing-box（交互式）
uninstall_singbox() {
    reading "确定要卸载 sing-box 吗? (y/n): " choice
    case "${choice}" in
        y|Y)
            yellow "正在卸载 sing-box"
            if command_exists rc-service; then
                rc-service sing-box stop; rc-service argo stop
                rm -f /etc/init.d/sing-box /etc/init.d/argo
                rc-update del sing-box default; rc-update del argo default
            else
                systemctl stop "${server_name}"; systemctl stop argo
                systemctl disable "${server_name}"; systemctl disable argo
                systemctl daemon-reload || true
            fi
            rm -rf "${work_dir}" || true
            rm -f /etc/systemd/system/sing-box.service /etc/systemd/system/argo.service
            rm -f /etc/nginx/conf.d/sing-box.conf

            reading "\n是否卸载 Nginx？(y/n): " choice
            case "${choice}" in
                y|Y) manage_packages uninstall nginx ;;
                *)   yellow "取消卸载Nginx\n\n" ;;
            esac
            green "\nsing-box 卸载成功\n\n" && exit 0
            ;;
        *) purple "已取消卸载操作\n\n" ;;
    esac
}

# 创建快捷指令
create_shortcut() {
    cat > "$work_dir/sb.sh" << 'EOF'
#!/usr/bin/env bash
bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sing-box.sh) $1
EOF
    chmod +x "$work_dir/sb.sh"
    ln -sf "$work_dir/sb.sh" /usr/bin/sb
    [ -s /usr/bin/sb ] && green "\n快捷指令 sb 创建成功\n" || red "\n快捷指令创建失败\n"
}

# 适配alpine
change_hosts() {
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
    sed -i '2s/.*/::1         localhost/' /etc/hosts
}

# 非交互静默安装（-i 参数）
auto_install() {
    check_singbox &>/dev/null
    if [ $? -eq 0 ]; then
        yellow "sing-box 已经安装，跳过安装流程。"
        exit 0
    fi

    green "开始无交互式安装 sing-box..."
    manage_packages install nginx jq tar openssl lsof coreutils
    install_singbox

    if command_exists systemctl; then
        main_systemd_services
    elif command_exists rc-update; then
        alpine_openrc_services
        change_hosts
        rc-service sing-box restart
        rc-service argo restart
    else
        red "不支持的 init 系统，安装中止。"
        exit 1
    fi

    sleep 5
    get_info
    add_nginx_conf
    create_shortcut
    green "\nsing-box 安装完成\n"
}

# 无交互静默卸载（-u 参数），含 nginx
auto_uninstall() {
    green "开始无交互式卸载sing-box..."

    if command_exists rc-service; then
        rc-service sing-box stop  > /dev/null 2>&1
        rc-service argo stop      > /dev/null 2>&1
        rc-update del sing-box default > /dev/null 2>&1
        rc-update del argo default     > /dev/null 2>&1
        rm -f /etc/init.d/sing-box /etc/init.d/argo
    elif command_exists systemctl; then
        systemctl stop    sing-box > /dev/null 2>&1
        systemctl stop    argo     > /dev/null 2>&1
        systemctl disable sing-box > /dev/null 2>&1
        systemctl disable argo     > /dev/null 2>&1
        systemctl daemon-reload    > /dev/null 2>&1
        rm -f /etc/systemd/system/sing-box.service \
              /etc/systemd/system/argo.service
    fi

    rm -rf "${work_dir}"
    rm -f /usr/bin/sb

    if command_exists nginx; then
        if command_exists rc-service; then
            rc-service nginx stop   > /dev/null 2>&1
            rc-update del nginx default > /dev/null 2>&1
        elif command_exists systemctl; then
            systemctl stop    nginx > /dev/null 2>&1
            systemctl disable nginx > /dev/null 2>&1
        fi
        rm -f /etc/nginx/conf.d/sing-box.conf
        manage_packages uninstall nginx
        [ -f /etc/nginx/nginx.conf.bak.sb ] && \
            mv /etc/nginx/nginx.conf.bak.sb /etc/nginx/nginx.conf > /dev/null 2>&1
    else
        yellow "nginx 未安装，跳过卸载 nginx。"
    fi

    green "\nsing-box 及 nginx 已完全卸载!\n"
}

# 变更配置
change_config() {
    local singbox_status=$(check_singbox 2>/dev/null)
    local singbox_installed=$?

    if [ $singbox_installed -eq 2 ]; then
        yellow "sing-box 尚未安装！"; sleep 1; menu; return
    fi

    clear; echo ""
    green "=== 修改节点配置 ===\n"
    green "sing-box当前状态: $singbox_status\n"
    green "1. 修改端口"
    skyblue "------------"
    green "2. 修改UUID"
    skyblue "------------"
    green "3. 修改Reality伪装域名"
    skyblue "------------"
    green "4. 添加hysteria2端口跳跃"
    skyblue "------------"
    green "5. 删除hysteria2端口跳跃"
    skyblue "------------"
    green "6. 修改vmess-argo优选域名"
    skyblue "------------"
    purple "0. 返回主菜单"
    skyblue "------------"
    reading "请输入选择: " choice
    case "${choice}" in
        1)
            echo ""
            green "1. 修改vless-reality端口"
            skyblue "------------"
            green "2. 修改hysteria2端口"
            skyblue "------------"
            green "3. 修改tuic端口"
            skyblue "------------"
            green "4. 修改vmess-argo端口"
            skyblue "------------"
            purple "0. 返回上一级菜单"
            skyblue "------------"
            reading "请输入选择: " choice
            local inbounds_file="${conf_dir}/inbounds.json"
            case "${choice}" in
                1)
                    reading "\n请输入vless-reality端口 (回车跳过将使用随机端口): " new_port
                    [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
                    jq --arg port "$new_port" \
                       '(.inbounds[] | select(.type == "vless").listen_port) = ($port | tonumber)' \
                       "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"
                    restart_singbox
                    allow_port $new_port/tcp > /dev/null 2>&1
                    sed -i 's/\(vless:\/\/[^@]*@[^:]*:\)[0-9]\{1,\}/\1'"$new_port"'/' $client_dir
                    base64 -w0 /etc/sing-box/url.txt > /etc/sing-box/sub.txt
                    while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
                    green "\nvless-reality端口已修改成：${purple}$new_port${re}\n"
                    ;;
                2)
                    reading "\n请输入hysteria2端口 (回车跳过将使用随机端口): " new_port
                    [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
                    jq --arg port "$new_port" \
                       '(.inbounds[] | select(.type == "hysteria2").listen_port) = ($port | tonumber)' \
                       "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"
                    restart_singbox
                    allow_port $new_port/udp > /dev/null 2>&1
                    sed -i 's/\(hysteria2:\/\/[^@]*@[^:]*:\)[0-9]\{1,\}/\1'"$new_port"'/' $client_dir
                    base64 -w0 $client_dir > /etc/sing-box/sub.txt
                    while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
                    green "\nhysteria2端口已修改为：${purple}${new_port}${re}\n"
                    ;;
                3)
                    reading "\n请输入tuic端口 (回车跳过将使用随机端口): " new_port
                    [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
                    jq --arg port "$new_port" \
                       '(.inbounds[] | select(.type == "tuic").listen_port) = ($port | tonumber)' \
                       "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"
                    restart_singbox
                    allow_port $new_port/udp > /dev/null 2>&1
                    sed -i 's/\(tuic:\/\/[^@]*@[^:]*:\)[0-9]\{1,\}/\1'"$new_port"'/' $client_dir
                    base64 -w0 $client_dir > /etc/sing-box/sub.txt
                    while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
                    green "\ntuic端口已修改为：${purple}${new_port}${re}\n"
                    ;;
                4)
                    reading "\n请输入vmess-argo端口 (回车跳过将使用随机端口): " new_port
                    [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
                    jq --arg port "$new_port" \
                       '(.inbounds[] | select(.type == "vmess").listen_port) = ($port | tonumber)' \
                       "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"
                    allow_port $new_port/tcp > /dev/null 2>&1
                    if command_exists rc-service; then
                        grep -q "localhost:" /etc/init.d/argo && \
                            sed -i 's/localhost:[0-9]\{1,\}/localhost:'"$new_port"'/' /etc/init.d/argo && \
                            get_quick_tunnel && change_argo_domain
                    else
                        grep -q "localhost:" /etc/systemd/system/argo.service && \
                            sed -i 's/localhost:[0-9]\{1,\}/localhost:'"$new_port"'/' /etc/systemd/system/argo.service && \
                            get_quick_tunnel && change_argo_domain
                    fi
                    restart_singbox
                    green "\nvmess-argo端口已修改为：${purple}${new_port}${re}\n"
                    ;;
                0) change_config ;;
                *) red "无效的选项，请输入 1 到 4" ;;
            esac
            ;;
        2)
            reading "\n请输入新的UUID: " new_uuid
            [ -z "$new_uuid" ] && new_uuid=$(cat /proc/sys/kernel/random/uuid)
            jq --arg uuid "$new_uuid" \
               '(.inbounds[] | select(.users != null) | .users[] | select(.uuid != null).uuid) = $uuid |
                (.inbounds[] | select(.users != null) | .users[] | select(.password != null).password) = $uuid' \
               "${conf_dir}/inbounds.json" > "${conf_dir}/inbounds.json.tmp" && mv "${conf_dir}/inbounds.json.tmp" "${conf_dir}/inbounds.json"
            restart_singbox
            sed -i -E 's/(vless:\/\/|hysteria2:\/\/)[^@]*(@.*)/\1'"$new_uuid"'\2/' $client_dir
            sed -i -E "s#tuic://[0-9a-f-]{36}:[0-9a-f-]{36}@#tuic://$new_uuid:$new_uuid@#g" /etc/sing-box/url.txt
            isp=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" | tr -d '\n' | \
                awk -F\" '{c="";i="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="isp")i=$(x+2)};if(c&&i)print c"-"i}' | sed 's/ /_/g' || echo "$hostname")
            argodomain=$(grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' "${work_dir}/argo.log" | sed 's@https://@@')
            VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"www.visa.com.tw\", \"port\": \"443\", \"id\": \"${new_uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"\", \"allowlnsecure\": \"flase\"}"
            encoded_vmess=$(echo "$VMESS" | base64 -w0)
            sed -i -E '/vmess:\/\//{s@vmess://.*@vmess://'"$encoded_vmess"'@}' $client_dir
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
            green "\nUUID已修改为：${purple}${new_uuid}${re}\n"
            ;;
        3)
            clear
            green "\n1. www.joom.com\n\n2. www.stengg.com\n\n3. www.wedgehr.com\n\n4. www.cerebrium.ai\n\n5. www.nazhumi.com\n"
            reading "\n请输入新的Reality伪装域名(可自定义输入,回车留空将使用默认1): " new_sni
            case "$new_sni" in
                ""|"1") new_sni="www.joom.com" ;;
                "2") new_sni="www.stengg.com" ;;
                "3") new_sni="www.wedgehr.com" ;;
                "4") new_sni="www.cerebrium.ai" ;;
                "5") new_sni="www.nazhumi.com" ;;
            esac
            jq --arg sni "$new_sni" \
               '(.inbounds[] | select(.type == "vless") | .tls.server_name) = $sni |
                (.inbounds[] | select(.type == "vless") | .tls.reality.handshake.server) = $sni' \
               "${conf_dir}/inbounds.json" > "${conf_dir}/inbounds.json.tmp" && mv "${conf_dir}/inbounds.json.tmp" "${conf_dir}/inbounds.json"
            restart_singbox
            sed -i "s/\(vless:\/\/[^\?]*\?\([^\&]*\&\)*sni=\)[^&]*/\1$new_sni/" $client_dir
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
            green "\nReality sni已修改为：${purple}${new_sni}${re}\n"
            ;;
        4)
            purple "端口跳跃需确保跳跃区间的端口没有被占用\n"
            reading "请输入跳跃起始端口 (回车跳过将使用随机端口): " min_port
            [ -z "$min_port" ] && min_port=$(shuf -i 50000-65000 -n 1)
            yellow "你的起始端口为：$min_port"
            reading "\n请输入跳跃结束端口 (需大于起始端口): " max_port
            [ -z "$max_port" ] && max_port=$(($min_port + 100))
            yellow "你的结束端口为：$max_port\n"
            listen_port=$(jq -r '.inbounds[] | select(.type == "hysteria2").listen_port' "${conf_dir}/inbounds.json")
            iptables -t nat -A PREROUTING -p udp --dport $min_port:$max_port -j DNAT --to-destination :$listen_port > /dev/null
            command -v ip6tables &> /dev/null && ip6tables -t nat -A PREROUTING -p udp --dport $min_port:$max_port -j DNAT --to-destination :$listen_port > /dev/null
            if command_exists rc-service 2>/dev/null; then
                iptables-save > /etc/iptables/rules.v4
                command -v ip6tables &> /dev/null && ip6tables-save > /etc/iptables/rules.v6
                cat << 'IEOF' > /etc/init.d/iptables
#!/sbin/openrc-run
depend() { need net; }
start() {
    [ -f /etc/iptables/rules.v4 ] && iptables-restore < /etc/iptables/rules.v4
    command -v ip6tables &> /dev/null && [ -f /etc/iptables/rules.v6 ] && ip6tables-restore < /etc/iptables/rules.v6
}
IEOF
                chmod +x /etc/init.d/iptables && rc-update add iptables default && /etc/init.d/iptables start
            elif [ -f /etc/debian_version ]; then
                DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent > /dev/null 2>&1 && netfilter-persistent save > /dev/null 2>&1
                systemctl enable netfilter-persistent > /dev/null 2>&1 && systemctl start netfilter-persistent > /dev/null 2>&1
            elif [ -f /etc/redhat-release ]; then
                manage_packages install iptables-services > /dev/null 2>&1 && service iptables save > /dev/null 2>&1
                systemctl enable iptables > /dev/null 2>&1 && systemctl start iptables > /dev/null 2>&1
                command -v ip6tables &> /dev/null && service ip6tables save > /dev/null 2>&1
                systemctl enable ip6tables > /dev/null 2>&1 && systemctl start ip6tables > /dev/null 2>&1
            fi
            restart_singbox
            ip=$(get_realip)
            uuid=$(sed -n 's/.*hysteria2:\/\/\([^@]*\)@.*/\1/p' $client_dir)
            line_number=$(grep -n 'hysteria2://' $client_dir | cut -d':' -f1)
            isp=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" | tr -d '\n' | \
                awk -F\" '{c="";i="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="isp")i=$(x+2)};if(c&&i)print c"-"i}' | sed 's/ /_/g' || echo "$hostname")
            sed -i.bak "/hysteria2:/d" $client_dir
            sed -i "${line_number}i hysteria2://$uuid@$ip:$listen_port?peer=www.bing.com&insecure=1&alpn=h3&obfs=none&mport=$listen_port,$min_port-$max_port#$isp" $client_dir
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
            green "\nhysteria2端口跳跃已开启：${purple}$min_port-$max_port${re}\n"
            ;;
        5)
            iptables -t nat -F PREROUTING > /dev/null 2>&1
            command -v ip6tables &> /dev/null && ip6tables -t nat -F PREROUTING > /dev/null 2>&1
            if command_exists rc-service 2>/dev/null; then
                rc-update del iptables default && rm -rf /etc/init.d/iptables
            elif [ -f /etc/debian_version ]; then
                netfilter-persistent save > /dev/null 2>&1
            elif [ -f /etc/redhat-release ]; then
                service iptables save > /dev/null 2>&1
                command -v ip6tables &> /dev/null && service ip6tables save > /dev/null 2>&1
            fi
            sed -i '/hysteria2/s/&mport=[^#&]*//g' /etc/sing-box/url.txt
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            green "\n端口跳跃已删除\n"
            ;;
        6) change_cfip ;;
        0) menu ;;
        *) red "无效的选项！" ;;
    esac
}

disable_open_sub() {
    local singbox_installed=$?
    check_singbox &>/dev/null; singbox_installed=$?
    if [ $singbox_installed -eq 2 ]; then
        yellow "sing-box 尚未安装！"; sleep 1; menu; return
    fi

    clear; echo ""
    green "=== 管理节点订阅 ===\n"
    skyblue "------------"
    green "1. 关闭节点订阅"
    skyblue "------------"
    green "2. 开启节点订阅"
    skyblue "------------"
    green "3. 更换订阅端口"
    skyblue "------------"
    purple "0. 返回主菜单"
    skyblue "------------"
    reading "请输入选择: " choice
    case "${choice}" in
        1)
            if command -v nginx &>/dev/null; then
                if command_exists rc-service 2>/dev/null; then
                    rc-service nginx status | grep -q "started" && rc-service nginx stop || red "nginx not running"
                else
                    [ "$(systemctl is-active nginx)" = "active" ] && systemctl stop nginx || red "nginx not running"
                fi
            else
                yellow "Nginx is not installed"
            fi
            green "\n已关闭节点订阅\n"
            ;;
        2)
            server_ip=$(get_realip)
            password=$(tr -dc A-Za-z < /dev/urandom | head -c 32)
            sed -i "s|\(location = /\)[^ ]*|\1$password|" /etc/nginx/conf.d/sing-box.conf
            sub_port=$(grep -E 'listen [0-9]+;' "/etc/nginx/conf.d/sing-box.conf" | awk '{print $2}' | sed 's/;//' | head -1)
            start_nginx
            local link
            [ "$sub_port" -eq 80 ] 2>/dev/null && link="http://$server_ip/$password" || link="http://$server_ip:$sub_port/$password"
            green "\n已开启节点订阅\n新的节点订阅链接：$link\n"
            ;;
        3)
            reading "请输入新的订阅端口(1-65535):" sub_port
            [ -z "$sub_port" ] && sub_port=$(shuf -i 2000-65000 -n 1)
            until [[ -z $(lsof -iTCP:"$sub_port" -sTCP:LISTEN -t) ]]; do
                echo -e "${red}端口 $sub_port 已被占用${re}"
                reading "请输入新的订阅端口(1-65535):" sub_port
                [[ -z $sub_port ]] && sub_port=$(shuf -i 2000-65000 -n 1)
            done
            [ -f "/etc/nginx/conf.d/sing-box.conf" ] && \
                cp "/etc/nginx/conf.d/sing-box.conf" "/etc/nginx/conf.d/sing-box.conf.bak.$(date +%Y%m%d)"
            sed -i 's/listen [0-9]\+;/listen '$sub_port';/g' "/etc/nginx/conf.d/sing-box.conf"
            sed -i 's/listen \[::\]:[0-9]\+;/listen [::]:'$sub_port';/g' "/etc/nginx/conf.d/sing-box.conf"
            path=$(sed -n 's|.*location = /\([^ ]*\).*|\1|p' "/etc/nginx/conf.d/sing-box.conf")
            server_ip=$(get_realip)
            allow_port $sub_port/tcp > /dev/null 2>&1
            if nginx -t > /dev/null 2>&1; then
                nginx -s reload > /dev/null 2>&1 || restart_nginx
                green "\n订阅端口更换成功\n新的订阅链接为：http://$server_ip:$sub_port/$path\n"
            else
                red "nginx配置测试失败，正在恢复..."
                latest_backup=$(ls -t /etc/nginx/conf.d/sing-box.conf.bak.* 2>/dev/null | head -1)
                [ -n "$latest_backup" ] && cp "$latest_backup" "/etc/nginx/conf.d/sing-box.conf"
                return 1
            fi
            ;;
        0) menu ;;
        *) red "无效的选项！" ;;
    esac
}

# singbox 管理
manage_singbox() {
    local singbox_status=$(check_singbox 2>/dev/null)
    clear; echo ""
    green "=== sing-box 管理 ===\n"
    green "sing-box当前状态: $singbox_status\n"
    green "1. 启动sing-box服务"
    skyblue "-------------------"
    green "2. 停止sing-box服务"
    skyblue "-------------------"
    green "3. 重启sing-box服务"
    skyblue "-------------------"
    purple "0. 返回主菜单"
    skyblue "------------"
    reading "\n请输入选择: " choice
    case "${choice}" in
        1) start_singbox ;;
        2) stop_singbox ;;
        3) restart_singbox ;;
        0) menu ;;
        *) red "无效的选项！" && sleep 1 && manage_singbox ;;
    esac
}

# Argo 管理
manage_argo() {
    local argo_status=$(check_argo 2>/dev/null)
    clear; echo ""
    green "=== Argo 隧道管理 ===\n"
    green "Argo当前状态: $argo_status\n"
    green "1. 启动Argo服务"
    skyblue "------------"
    green "2. 停止Argo服务"
    skyblue "------------"
    green "3. 重启Argo服务"
    skyblue "------------"
    green "4. 添加Argo固定隧道"
    skyblue "----------------"
    green "5. 切换回Argo临时隧道"
    skyblue "------------------"
    green "6. 重新获取Argo临时域名"
    skyblue "-------------------"
    purple "0. 返回主菜单"
    skyblue "-----------"
    reading "\n请输入选择: " choice
    case "${choice}" in
        1) start_argo ;;
        2) stop_argo ;;
        3)
            clear
            if command_exists rc-service 2>/dev/null; then
                grep -Fq -- '--url http://localhost' /etc/init.d/argo && get_quick_tunnel && change_argo_domain || \
                    { green "\n当前使用固定隧道,无需获取临时域名"; sleep 2; menu; }
            else
                grep -q 'ExecStart=.*--url http://localhost' /etc/systemd/system/argo.service && get_quick_tunnel && change_argo_domain || \
                    { green "\n当前使用固定隧道,无需获取临时域名"; sleep 2; menu; }
            fi
            ;;
        4)
            clear
            yellow "\n固定隧道可为json或token，固定隧道端口为8001\njson获取地址：${purple}https://fscarmen.cloudflare.now.cc${re}\n"
            reading "\n请输入你的argo域名: " argo_domain
            ArgoDomain=$argo_domain
            reading "\n请输入你的argo密钥(token或json): " argo_auth
            if [[ $argo_auth =~ TunnelSecret ]]; then
                echo $argo_auth > ${work_dir}/tunnel.json
                cat > ${work_dir}/tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$argo_auth")
credentials-file: ${work_dir}/tunnel.json
protocol: http2

ingress:
  - hostname: $ArgoDomain
    service: http://localhost:8001
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
                if command_exists rc-service 2>/dev/null; then
                    sed -i '/^command_args=/c\command_args="-c '\''/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1'\''"' /etc/init.d/argo
                else
                    sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1"' /etc/systemd/system/argo.service
                fi
                restart_argo; sleep 1; change_argo_domain
            elif [[ $argo_auth =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
                if command_exists rc-service 2>/dev/null; then
                    sed -i "/^command_args=/c\command_args=\"-c '/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token $argo_auth 2>&1'\"" /etc/init.d/argo
                else
                    sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token '$argo_auth' 2>&1"' /etc/systemd/system/argo.service
                fi
                restart_argo; sleep 1; change_argo_domain
            else
                yellow "输入不匹配，请重新输入"; manage_argo
            fi
            ;;
        5)
            clear
            if command_exists rc-service 2>/dev/null; then alpine_openrc_services
            else main_systemd_services; fi
            get_quick_tunnel; change_argo_domain
            ;;
        6)
            if command_exists rc-service 2>/dev/null; then
                grep -Fq -- '--url http://localhost' "/etc/init.d/argo" && get_quick_tunnel && change_argo_domain || \
                    { yellow "当前使用固定隧道，无法获取临时隧道"; sleep 2; menu; }
            else
                grep -q 'ExecStart=.*--url http://localhost' "/etc/systemd/system/argo.service" && get_quick_tunnel && change_argo_domain || \
                    { yellow "当前使用固定隧道，无法获取临时隧道"; sleep 2; menu; }
            fi
            ;;
        0) menu ;;
        *) red "无效的选项！" ;;
    esac
}

# 获取argo临时隧道
get_quick_tunnel() {
    restart_argo
    yellow "获取临时argo域名中，请稍等...\n"
    sleep 3
    if [ -f /etc/sing-box/argo.log ]; then
        for i in {1..5}; do
            purple "第 $i 次尝试获取ArgoDoamin中..."
            get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "/etc/sing-box/argo.log")
            [ -n "$get_argodomain" ] && break
            sleep 2
        done
    else
        restart_argo; sleep 6
        get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "/etc/sing-box/argo.log")
    fi
    green "ArgoDomain：${purple}$get_argodomain${re}\n"
    ArgoDomain=$get_argodomain
}

# 更新Argo域名到订阅
change_argo_domain() {
    content=$(cat "$client_dir")
    vmess_url=$(grep -o 'vmess://[^ ]*' "$client_dir")
    vmess_prefix="vmess://"
    encoded_vmess="${vmess_url#"$vmess_prefix"}"
    decoded_vmess=$(echo "$encoded_vmess" | base64 --decode)
    updated_vmess=$(echo "$decoded_vmess" | jq --arg new_domain "$ArgoDomain" '.host = $new_domain | .sni = $new_domain')
    encoded_updated_vmess=$(echo "$updated_vmess" | base64 | tr -d '\n')
    new_vmess_url="${vmess_prefix}${encoded_updated_vmess}"
    new_content=$(echo "$content" | sed "s|$vmess_url|$new_vmess_url|")
    echo "$new_content" > "$client_dir"
    base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt
    green "vmess节点已更新\n"
    purple "$new_vmess_url\n"
}

# 查看节点信息和订阅链接
check_nodes() {
    if [ ! -f "${work_dir}/url.txt" ]; then
        red "节点信息文件不存在，请先安装 sing-box"; return 1
    fi

    server_ip=$(get_realip)
    local lujing sub_port base64_url

    if [ -f "/etc/nginx/conf.d/sing-box.conf" ]; then
        lujing=$(sed -n 's|.*location = /\([^ ]*\).*|\1|p' "/etc/nginx/conf.d/sing-box.conf")
        sub_port=$(sed -n 's/^\s*listen \([0-9]\+\);/\1/p' "/etc/nginx/conf.d/sing-box.conf" | head -1)
    fi
    base64_url="http://${server_ip}:${sub_port}/${lujing}"

    clear; echo ""
    green "=== 当前节点信息 ===\n"

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        echo -e "${purple}${line}${re}\n"
    done < "${work_dir}/url.txt"

    echo ""
    green "\n=== 订阅链接 ===\n"

    green "V2rayN/Shadowrocket/Nekobox/Karing 订阅链接:\n${purple}${base64_url}${re}\n"
    [ -x "${work_dir}/qrencode" ] && "${work_dir}/qrencode" "${base64_url}"
    yellow "\n=========================================================================================="

    green "\nClash/Mihomo 订阅链接:\n${purple}https://sublink.eooce.com/clash?config=${base64_url}${re}\n"
    [ -x "${work_dir}/qrencode" ] && "${work_dir}/qrencode" "https://sublink.eooce.com/clash?config=${base64_url}"
    yellow "\n=========================================================================================="

    green "\nSing-box 订阅链接:\n${purple}https://sublink.eooce.com/singbox?config=${base64_url}${re}\n"
    [ -x "${work_dir}/qrencode" ] && "${work_dir}/qrencode" "https://sublink.eooce.com/singbox?config=${base64_url}"
    yellow "\n=========================================================================================="

    green "\nSurge 订阅链接:\n${purple}https://sublink.eooce.com/surge?config=${base64_url}${re}\n"
    [ -x "${work_dir}/qrencode" ] && "${work_dir}/qrencode" "https://sublink.eooce.com/surge?config=${base64_url}"
    yellow "\n==========================================================================================\n"
}

change_cfip() {
    clear
    yellow "修改vmess-argo优选域名\n"
    green "1: cf.090227.xyz  2: cf.877774.xyz  3: cf.877771.xyz  4: cdns.doon.eu.org  5: cf.zhetengsha.eu.org  6: time.is\n"
    reading "请输入你的优选域名或优选IP\n(请输入1至6选项,可输入域名:端口 或 IP:端口,直接回车默认使用1): " cfip_input

    case "$cfip_input" in
        ""|"1") cfip="cf.090227.xyz";          cfport="443" ;;
        "2")    cfip="cf.877774.xyz";           cfport="443" ;;
        "3")    cfip="cf.877771.xyz";           cfport="443" ;;
        "4")    cfip="cdns.doon.eu.org";        cfport="443" ;;
        "5")    cfip="cf.zhetengsha.eu.org";    cfport="443" ;;
        "6")    cfip="time.is";                 cfport="443" ;;
        *)
            if [[ "$cfip_input" =~ : ]]; then
                cfip=$(echo "$cfip_input" | cut -d':' -f1)
                cfport=$(echo "$cfip_input" | cut -d':' -f2)
            else
                cfip="$cfip_input"; cfport="443"
            fi
            ;;
    esac

    content=$(cat "$client_dir")
    vmess_url=$(grep -o 'vmess://[^ ]*' "$client_dir")
    encoded_part="${vmess_url#vmess://}"
    decoded_json=$(echo "$encoded_part" | base64 --decode 2>/dev/null)
    updated_json=$(echo "$decoded_json" | jq --arg cfip "$cfip" --argjson cfport "$cfport" '.add = $cfip | .port = $cfport')
    new_encoded_part=$(echo "$updated_json" | base64 -w0)
    new_vmess_url="vmess://$new_encoded_part"
    new_content=$(echo "$content" | sed "s|$vmess_url|$new_vmess_url|")
    echo "$new_content" > "$client_dir"
    base64 -w0 "${work_dir}/url.txt" > "${work_dir}/sub.txt"
    green "\nvmess节点优选域名已更新为：${purple}${cfip}:${cfport}${re}\n"
    purple "$new_vmess_url\n"
}

# WARP 分流管理
warp_manage() {
    check_singbox &>/dev/null
    if [ $? -eq 2 ]; then
        yellow "sing-box 尚未安装！"; sleep 1; menu; return
    fi

    clear
    route_file="${conf_dir}/route.json"
    outbound_file="${conf_dir}/outbounds.json"

    echo ""
    green "=== WARP 分流管理 ===\n"
    green "当前已启用的分流规则集:"
    jq -r '.route.rules[] | select(.rule_set != null) | .rule_set[]?' "$route_file" 2>/dev/null | sort -u | while read tag; do
        echo -e " - ${skyblue}$tag${re}"
    done || echo "  无"
    green "\n已添加的socks/http代理出站:"
    jq -r '.outbounds[] | select(.tag != "direct") | " - \(.tag) [\(.type)]"' "$outbound_file" 2>/dev/null || echo "  无"

    echo ""
    green "1. 添加WARP分流规则"
    skyblue "----------------------"
    red "2. 删除WARP分流规则"
    skyblue "--------------"
    green "3. 添加 Socks5/HTTP 出站"
    skyblue "----------------------"
    red "4. 删除 Socks5/HTTP 出站"
    skyblue "----------------------"
    purple "0. 返回主菜单"
    skyblue "------------"
    purple "00. 退出脚本"
    skyblue "------------"
    reading "请输入选择: " choice
    case "${choice}" in
        1)  add_rule_menu ;;
        2)  delete_rule_menu ;;
        3)  add_socks5_proxy ;;
        4)  delete_socks5_proxy ;;
        0)  menu ;;
        00) exit 0 ;;
        *)  red "无效选项"; sleep 1; warp_manage ;;
    esac
}

add_rule_menu() {
    clear
    green "选择要分流的服务:\n"
    green "1. OpenAI"
    green "2. Claude"
    green "3. Gemini"
    green "4. Google"
    green "5. Tiktok"
    green "6. Twitter"
    green "7. YouTube"
    green "8. Netflix"
    green "9. Telegram\n"
    purple "0. 返回上级菜单"
    reading "请输入选择: " add_choice
    case "$add_choice" in
        1) rule_tag="openai" ;;
        2) rule_tag="claude" ;;
        3) rule_tag="gemini" ;;
        4) rule_tag="google" ;;
        5) rule_tag="tiktok" ;;
        6) rule_tag="twitter" ;;
        7) rule_tag="youtube" ;;
        8) rule_tag="netflix" ;;
        9) rule_tag="telegram" ;;
        0) warp_manage; return ;;
        *) red "无效选项"; sleep 1; add_rule_menu; return ;;
    esac

    if jq -e --arg tag "$rule_tag" '.route.rules[] | select(.rule_set != null) | .rule_set[]? | select(. == $tag)' "$route_file" > /dev/null 2>&1; then
        yellow "规则集 '${rule_tag}' 已启用。"; sleep 1; warp_manage; return
    fi

    jq 'if (.route.rules | length) == 1 and (.route.rules[0].rule_set | length) == 0 then .route.rules = [] else . end' \
        "$route_file" > "${route_file}.tmp" && mv "${route_file}.tmp" "$route_file"

    local out_tags=($(jq -r '.outbounds[] | select(.tag != "direct") | .tag' "$outbound_file" 2>/dev/null))
    if [ ${#out_tags[@]} -eq 0 ]; then
        selected_out="wireguard-out"
        yellow "未找到其他出站，将自动使用 wireguard-out。"
    else
        echo ""
        green "请选择分流流量要走的出站:"
        for i in "${!out_tags[@]}"; do
            echo -e "  ${green}$((i+1)). ${skyblue}${out_tags[$i]}${re}"
        done
        reading "请输入编号: " out_choice
        if [[ ! "$out_choice" =~ ^[0-9]+$ ]] || [ "$out_choice" -lt 1 ] || [ "$out_choice" -gt "${#out_tags[@]}" ]; then
            red "无效选择"; sleep 1; warp_manage; return
        fi
        selected_out="${out_tags[$((out_choice-1))]}"
    fi

    jq --arg tag "$rule_tag" --arg out "$selected_out" '
        if (.route.rules | length) == 0 then
            .route.rules = [{"rule_set": [$tag], "outbound": $out}]
        else
            (first(.route.rules[] | select(.outbound == $out)) | .rule_set) as $existing
            | if $existing then
                .route.rules = [.route.rules[] | select(.outbound == $out).rule_set += [$tag]]
              else
                .route.rules += [{"rule_set": [$tag], "outbound": $out}]
              end
        end
    ' "$route_file" > "${route_file}.tmp" && mv "${route_file}.tmp" "$route_file"

    restart_singbox
    green "'${rule_tag}' 已分流至出站 '${selected_out}'"
    sleep 1; warp_manage
}

delete_rule_menu() {
    clear
    green "当前已启用的分流规则集:"
    jq -r '.route.rules[] | select(.rule_set != null) | .rule_set[]?' "$route_file" | nl -w2 -s'. '
    reading "\n输入要删除的规则名称或序号: " del_input
    if [[ "$del_input" =~ ^[0-9]+$ ]]; then
        tag=$(jq -r --arg idx "$del_input" '[.route.rules[] | select(.rule_set != null) | .rule_set[]] | .[(($idx | tonumber) - 1)]' "$route_file")
    else
        tag="$del_input"
    fi
    if [ -z "$tag" ] || [ "$tag" == "null" ]; then
        red "无效的选择"; sleep 1; warp_manage; return
    fi
    jq --arg tag "$tag" \
       'del(.route.rules[] | select(.rule_set != null) | .rule_set[] | select(. == $tag)) |
        .route.rules = [.route.rules[] | select(.rule_set != null and (.rule_set | length) > 0)]' \
       "$route_file" > "${route_file}.tmp" && mv "${route_file}.tmp" "$route_file"
    restart_singbox
    green "规则集 '${tag}' 已禁用。"
    sleep 1; warp_manage
}

add_socks5_proxy() {
    clear
    reading "请输入代理URL (支持socks://,socks5://,http://): " proxy_url
    [ -z "$proxy_url" ] && { red "输入为空！"; sleep 1; return; }

    proto=$(echo "$proxy_url" | grep -oP '^[a-zA-Z0-9]+(?=://)')
    [[ ! "$proto" =~ ^(socks5|socks|http)$ ]] && { red "不支持的协议"; sleep 2; return; }
    case "$proto" in
        socks|socks5) outbound_type="socks" ;;
        http)         outbound_type="http" ;;
    esac

    after_proto="${proxy_url#*://}"
    if [[ "$after_proto" == *"#"* ]]; then
        tag_from_url="${after_proto##*#}"; after_proto="${after_proto%%#*}"
    else
        tag_from_url=""
    fi

    if [[ "$after_proto" == *"@"* ]]; then
        user_pass="${after_proto%%@*}"; host_port="${after_proto##*@}"
    else
        user_pass=""; host_port="$after_proto"
    fi

    user=""; password=""
    if [ -n "$user_pass" ]; then
        decoded=$(echo "$user_pass" | base64 -d 2>/dev/null)
        if [ -n "$decoded" ] && [[ "$decoded" != "$user_pass" ]] && [[ "$decoded" == *":"* ]]; then
            user="${decoded%%:*}"; password="${decoded#*:}"
        elif [[ "$user_pass" == *":"* ]]; then
            user="${user_pass%%:*}"; password="${user_pass#*:}"
        else
            user="$user_pass"
        fi
    fi

    server="${host_port%%:*}"; port="${host_port##*:}"
    [ -z "$server" ] || [ -z "$port" ] && { red "格式错误：缺少ip或端口"; sleep 2; return; }

    [[ "$proto" == "socks" || "$proto" == "socks5" ]] && check_proto="socks5" || check_proto="$proto"
    yellow "正在测试代理 ${check_proto}://${server}:${port} ..."
    local proxy_auth=""
    [ -n "$user" ] && [ -n "$password" ] && proxy_auth="${user}:${password}@" || { [ -n "$user" ] && proxy_auth="${user}@"; }

    local api_response=$(curl -s --max-time 8 -G --data-urlencode "proxy=${check_proto}://${proxy_auth}${server}:${port}" "https://check.socks5.cmliussss.net/check" 2>/dev/null)
    [ -z "$api_response" ] && { red "API 请求失败"; sleep 2; return; }

    success=$(echo "$api_response" | jq -r '.success')
    if [ "$success" != "true" ]; then
        error_msg=$(echo "$api_response" | jq -r '.error // "未知错误"')
        red "代理不可用: $error_msg"; sleep 2; return
    fi
    exit_ip=$(echo "$api_response" | jq -r '.exit.ip // empty')
    green "代理可用"
    [ -n "$exit_ip" ] && green "出口 IP: $exit_ip"

    [ -n "$tag_from_url" ] && tag="$tag_from_url" || tag="${outbound_type}-${server}"
    jq -e --arg tag "$tag" '.outbounds[] | select(.tag == $tag)' "$outbound_file" >/dev/null 2>&1 && { red "出站标签 '${tag}' 已存在"; sleep 2; return; }

    jq --arg type "$outbound_type" --arg tag "$tag" --arg server "$server" \
       --arg port "$port" --arg user "$user" --arg password "$password" \
       '.outbounds += [{"type":$type,"tag":$tag,"server":$server,"server_port":($port|tonumber),"username":$user,"password":$password}]' \
       "$outbound_file" > "${outbound_file}.tmp" && mv "${outbound_file}.tmp" "$outbound_file"

    if jq -e '.route.rules | length > 0' "$route_file" >/dev/null 2>&1; then
        jq --arg tag "$tag" '.route.rules[].outbound = $tag' "$route_file" > "${route_file}.tmp" && mv "${route_file}.tmp" "$route_file"
        yellow "已将现有分流规则出站切换为 '${tag}'。"
    fi

    restart_singbox
    green "\n${tag} 代理出站已添加\n"
    sleep 2; warp_manage
}

delete_socks5_proxy() {
    clear
    green "当前可用出站列表:"
    local out_list=$(jq -r '[.outbounds[] | select(.tag != "direct")] | to_entries | .[] | "\(.key+1). \(.value.tag) [\(.value.type)]"' "$outbound_file" 2>/dev/null)
    [ -z "$out_list" ] && { yellow "没有可删除的出站。"; sleep 2; return; }
    echo "$out_list"

    reading "输入要删除的出站编号或标签: " del_input
    if [[ "$del_input" =~ ^[0-9]+$ ]]; then
        tag=$(jq -r --arg idx "$del_input" '.outbounds | map(select(.tag != "direct")) | .[($idx | tonumber)-1].tag // empty' "$outbound_file")
        [ -z "$tag" ] && { red "编号无效！"; sleep 1; return; }
    else
        tag="$del_input"
        jq -e --arg tag "$tag" '.outbounds[] | select(.tag == $tag)' "$outbound_file" > /dev/null 2>&1 || { red "标签 '${tag}' 不存在！"; sleep 1; return; }
    fi
    [ "$tag" == "wireguard-out" ] && { red "wireguard-out 为系统内置，不可删除！"; sleep 2; return; }

    jq --arg tag "$tag" 'del(.outbounds[] | select(.tag == $tag))' "$outbound_file" > "${outbound_file}.tmp" && mv "${outbound_file}.tmp" "$outbound_file"
    jq --arg tag "$tag" '.route.rules = [.route.rules[] | select(.outbound != $tag)]' "$route_file" > "${route_file}.tmp" && mv "${route_file}.tmp" "$route_file"

    restart_singbox
    green "${tag} 代理出站已删除。"
    sleep 1
}

# ============================================================
# 协议管理模块 - 增加/删除 socks5 / anytls / shadowsocks-2022
# ============================================================

# 检查指定 tag 是否已在 inbounds 中存在
proto_exists() {
    local tag="$1"
    jq -e --arg tag "$tag" '.inbounds[] | select(.tag == $tag)' "${conf_dir}/inbounds.json" > /dev/null 2>&1
}

# 更新订阅文件
remove_url_by_tag() {
    local tag="$1"
    sed -i '/'^${tag}':\/\//d' "$client_dir"
    sed -i '/^$/{N; /\n$/D}' "$client_dir"
}

update_sub() {
    local sub_file="${work_dir}/sub.txt"
    base64_content=$(cat "$client_dir" | base64 | tr -d '\n\r')
    echo "$base64_content" > "$sub_file"
}

# ---- Socks5 入站 ----
add_socks5_inbound() {
    local inbounds_file="${conf_dir}/inbounds.json"
    local tag="socks5-in"

    if proto_exists "$tag"; then
        yellow "Socks5 协议已存在，无需重复添加。"; sleep 1; return
    fi

    # 获取当前UUID用于自动填充
    local current_uuid
    current_uuid=$(get_current_uuid | tr -d '\n\r')

    # 端口输入验证循环
    while true; do
        reading "请输入 Socks5 监听端口 (回车随机生成): " sk_port
        if [ -z "$sk_port" ]; then
            sk_port=$(shuf -i 10000-65000 -n 1)
            green "socks5监听端口：${purple}${sk_port}${re}"
            break
        fi
        
        # 统一验证端口格式和范围
        if [[ ! "$sk_port" =~ ^[0-9]+$ ]] || [ "$sk_port" -gt 65535 ] || [ "$sk_port" -lt 1 ]; then
            yellow "错误：端口必须是1-65535之间的数字！"
            continue
        fi
        
        green "socks5监听端口：${purple}${sk_port}${re}"
        break
    done

    reading "请输入 Socks5 用户名 (回车自动使用UUID前8位): " sk_user
    if [ -n "$sk_user" ]; then
        green "socks5用户名：${purple}${sk_user}${re}"
    else
        if [ -n "$current_uuid" ]; then
            sk_user=$(printf '%s' "${current_uuid:0:8}" | tr -d '\n\r')
            green "自动设置用户名: ${purple}${sk_user}${re}"
        else
            red "无法获取UUID，请手动输入用户名"
            reading "请输入 Socks5 用户名: " sk_user
            [ -z "$sk_user" ] && { red "用户名不能为空"; sleep 1; return; }
        fi
    fi

    reading "请输入 Socks5 密码 (回车自动使用UUID后12位): " sk_pass
    if [ -n "$sk_pass" ]; then
        green "socks5密码：${purple}${sk_pass}${re}"
    else
        if [ -n "$current_uuid" ]; then
            sk_pass=$(printf '%s' "${current_uuid: -12}" | tr -d '\n\r')
            green "自动设置密码: ${purple}${sk_pass}${re}"
        else
            red "无法获取UUID，请手动输入密码"
            reading "请输入 Socks5 密码: " sk_pass
            [ -z "$sk_pass" ] && { red "密码不能为空"; sleep 1; return; }
        fi
    fi

    jq --arg tag "$tag" \
       --argjson port "$sk_port" \
       --arg user "$sk_user" \
       --arg pass "$sk_pass" \
       '.inbounds += [{
           "type": "socks",
           "tag": $tag,
           "listen": "::",
           "listen_port": $port,
           "users": [{"username": $user, "password": $pass}]
       }]' "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"

    allow_port ${sk_port}/tcp ${sk_port}/udp > /dev/null 2>&1

    local server_ip
    server_ip=$(get_realip)
    local isp
    isp=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" | tr -d '\n' \
        | awk -F\" '{c="";i="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="isp")i=$(x+2)};if(c&&i)print c"-"i}' \
        | sed 's/ /_/g' || echo "Socks5")

    local url_line="socks://$(printf '%s' "${sk_user}:${sk_pass}" | base64 -w0)@${server_ip}:${sk_port}#${isp}"

    echo "" >> "${client_dir}"
    echo "${url_line}" >> "${client_dir}"
    update_sub

    restart_singbox

    green "\nSocks5 协议已添加！"
    green "端口: ${purple}${sk_port}${re}"
    green "用户名: ${purple}${sk_user}${re}  ${green}密码:${re} ${purple}${sk_pass}${re}"
    green "节点链接: ${purple}${url_line}${re}\n"
    [ -x "${work_dir}/qrencode" ] && "${work_dir}/qrencode" "$url_line"
}

remove_socks5_inbound() {
    local inbounds_file="${conf_dir}/inbounds.json"
    local tag="socks5-in"

    if ! proto_exists "$tag"; then
        yellow "Socks5 协议未添加，无需删除。"; sleep 1; return
    fi

    jq --arg tag "$tag" 'del(.inbounds[] | select(.tag == $tag))' \
        "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"

    remove_url_by_tag "socks"
    update_sub
    restart_singbox
    green "\nSocks5 协议已删除\n"
}

# ---- AnyTLS ----
add_anytls() {
    local inbounds_file="${conf_dir}/inbounds.json"
    local tag="anytls"

    if proto_exists "$tag"; then
        yellow "AnyTLS 协议已存在，无需重复添加。"; sleep 1; return
    fi

    # 使用已安装协议的UUID作为密码
    local current_uuid
    current_uuid=$(get_current_uuid)
    if [ -z "$current_uuid" ]; then
        red "无法获取当前UUID，请确认 sing-box 已正确安装并配置。"; sleep 2; return
    fi

    # 端口输入验证循环
    while true; do
        reading "请输入 AnyTLS 监听端口 (回车随机生成): " at_port
        
        if [ -z "$at_port" ]; then
            at_port=$(shuf -i 10000-65000 -n 1)
            green "Anytls监听端口：${purple}${at_port}${re}"
            break
        fi
        
        if [[ ! "$at_port" =~ ^[0-9]+$ ]] || [ "$at_port" -gt 65535 ] || [ "$at_port" -lt 1 ]; then
            yellow "错误：端口必须是1-65535之间的数字！"
            continue
        fi
        
        green "Anytls监听端口：${purple}${at_port}${re}"
        break
    done

    jq --arg tag "$tag" \
       --argjson port "$at_port" \
       --arg pass "$current_uuid" \
       --arg cert "${work_dir}/cert.pem" \
       --arg key "${work_dir}/private.key" \
       '.inbounds += [{
           "type": "anytls",
           "tag": $tag,
           "listen": "::",
           "listen_port": $port,
           "users": [{"password": $pass}],
           "tls": {
               "enabled": true,
               "certificate_path": $cert,
               "key_path": $key
           }
       }]' "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"

    allow_port ${at_port}/tcp > /dev/null 2>&1

    local server_ip
    server_ip=$(get_realip)
    local isp
    isp=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" | tr -d '\n' \
        | awk -F\" '{c="";i="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="isp")i=$(x+2)};if(c&&i)print c"-"i}' \
        | sed 's/ /_/g' || echo "AnyTLS")

    local url_line="anytls://${current_uuid}@${server_ip}:${at_port}?insecure=1&sni=bing.com#${isp}"

    echo "" >> "${client_dir}"
    echo "${url_line}" >> "${client_dir}"
    update_sub

    restart_singbox

    green "\nAnyTLS 协议已添加！"
    green "密码(UUID): ${purple}${current_uuid}${re}"
    green "端口: ${purple}${at_port}${re}"
    green "节点链接:\n${purple}${url_line}${re}\n"
    [ -x "${work_dir}/qrencode" ] && "${work_dir}/qrencode" "$url_line"
}

remove_anytls() {
    local inbounds_file="${conf_dir}/inbounds.json"
    local tag="anytls"

    if ! proto_exists "$tag"; then
        yellow "AnyTLS 协议未添加，无需删除。"; sleep 1; return
    fi

    jq --arg tag "$tag" 'del(.inbounds[] | select(.tag == $tag))' \
        "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"

    remove_url_by_tag "anytls"
    update_sub
    restart_singbox
    green "\nAnyTLS 协议已删除\n"
}

# ---- Shadowsocks-2022 ----
add_ss2022() {
    local inbounds_file="${conf_dir}/inbounds.json"
    local tag="shadowsocks-2022"

    if proto_exists "$tag"; then
        yellow "Shadowsocks-2022 协议已存在，无需重复添加。"; sleep 1; return
    fi

    # 端口输入验证循环
    while true; do
        reading "请输入 Shadowsocks-2022 监听端口 (回车随机生成): " ss_port
        
        if [ -z "$ss_port" ]; then
            ss_port=$(shuf -i 10000-65000 -n 1)
            green "Shadowsocks-2022监听端口：${purple}${ss_port}${re}"
            break
        fi
        
        if [[ ! "$ss_port" =~ ^[0-9]+$ ]] || [ "$ss_port" -gt 65535 ] || [ "$ss_port" -lt 1 ]; then
            yellow "错误：端口必须是1-65535之间的数字！"
            continue
        fi
        
        green "Shadowsocks-2022监听端口：${purple}${ss_port}${re}"
        break
    done

    echo ""
    green "请选择加密方式:"
    green "1. 2022-blake3-aes-128-gcm       (推荐，密钥16字节)"
    green "2. 2022-blake3-aes-256-gcm       (密钥32字节)"
    green "3. 2022-blake3-chacha20-poly1305 (密钥32字节)"
    reading "请输入选择 (默认1): " ss_method_choice
    local ss_method key_len
    case "${ss_method_choice}" in
        2) ss_method="2022-blake3-aes-256-gcm";        key_len=32 ;;
        3) ss_method="2022-blake3-chacha20-poly1305";   key_len=32 ;;
        *) ss_method="2022-blake3-aes-128-gcm";         key_len=16 ;;
    esac
    green "加密方式为：${purple}${ss_method}${re}"
    local ss_key
    ss_key=$(dd if=/dev/urandom bs=1 count=${key_len} 2>/dev/null | base64 -w0)
    
    jq --arg tag "$tag" \
       --argjson port "$ss_port" \
       --arg method "$ss_method" \
       --arg key "$ss_key" \
       '.inbounds += [{
           "type": "shadowsocks",
           "tag": $tag,
           "listen": "::",
           "listen_port": $port,
           "method": $method,
           "password": $key,
           "multiplex": {"enabled": true}
       }]' "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"

    allow_port ${ss_port}/tcp ${ss_port}/udp > /dev/null 2>&1

    local server_ip
    server_ip=$(get_realip)
    local isp
    isp=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" | tr -d '\n' \
        | awk -F\" '{c="";i="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="isp")i=$(x+2)};if(c&&i)print c"-"i}' \
        | sed 's/ /_/g' || echo "SS2022")

    local ss_userinfo
    ss_userinfo=$(printf '%s:%s' "${ss_method}" "${ss_key}" | base64 -w0)
    local url_line="ss://${ss_userinfo}@${server_ip}:${ss_port}#${isp}"

    echo "" >> "${client_dir}"
    echo "${url_line}" >> "${client_dir}"
    update_sub

    restart_singbox

    green "\nShadowsocks-2022 协议已添加！"
    green "加密方式: ${purple}${ss_method}${re}"
    green "密钥(base64): ${purple}${ss_key}${re}"
    green "端口: ${purple}${ss_port}${re}"
    green "节点链接:\n${purple}${url_line}${re}\n"
    [ -x "${work_dir}/qrencode" ] && "${work_dir}/qrencode" "$url_line"
}

remove_ss2022() {
    local inbounds_file="${conf_dir}/inbounds.json"
    local tag="shadowsocks-2022"

    if ! proto_exists "$tag"; then
        yellow "Shadowsocks-2022 协议未添加，无需删除。"; sleep 1; return
    fi

    jq --arg tag "$tag" 'del(.inbounds[] | select(.tag == $tag))' \
        "$inbounds_file" > "${inbounds_file}.tmp" && mv "${inbounds_file}.tmp" "$inbounds_file"

    remove_url_by_tag "ss"
    update_sub
    restart_singbox
    green "\nShadowsocks-2022 协议已删除\n"
}

# 显示当前已启用的额外协议状态
show_extra_proto_status() {
    local inbounds_file="${conf_dir}/inbounds.json"
    echo ""
    green "--- 额外协议状态 ---"

    # Socks5
    if jq -e '.inbounds[] | select(.tag == "socks5-in")' "$inbounds_file" > /dev/null 2>&1; then
        local sk_port sk_user
        sk_port=$(jq -r '.inbounds[] | select(.tag == "socks5-in") | .listen_port' "$inbounds_file")
        sk_user=$(jq -r '.inbounds[] | select(.tag == "socks5-in") | .users[0].username // "N/A"' "$inbounds_file")
        sk_pass=$(jq -r '.inbounds[] | select(.tag == "socks5-in") | .users[0].password // "N/A"' "$inbounds_file")
        echo -e " Socks5:           ${green}已启用${re} (端口: ${skyblue}${sk_port}${re}, 用户名: ${skyblue}${sk_user}${re}，密码：${skyblue}${sk_pass}${re})"
    else
        echo -e " Socks5:           ${yellow}未启用${re}"
    fi

    # AnyTLS
    if jq -e '.inbounds[] | select(.tag == "anytls")' "$inbounds_file" > /dev/null 2>&1; then
        local at_port at_pass
        at_port=$(jq -r '.inbounds[] | select(.tag == "anytls") | .listen_port' "$inbounds_file")
        at_pass=$(jq -r '.inbounds[] | select(.tag == "anytls") | .users[0].password // "N/A"' "$inbounds_file")
        echo -e " AnyTLS:           ${green}已启用${re} (端口: ${skyblue}${at_port}${re}, 密码: ${skyblue}${at_pass}${re})"
    else
        echo -e " AnyTLS:           ${yellow}未启用${re}"
    fi

    # Shadowsocks-2022
    if jq -e '.inbounds[] | select(.tag == "shadowsocks-2022")' "$inbounds_file" > /dev/null 2>&1; then
        local ss_port ss_method
        ss_port=$(jq -r '.inbounds[] | select(.tag == "shadowsocks-2022") | .listen_port' "$inbounds_file")
        ss_method=$(jq -r '.inbounds[] | select(.tag == "shadowsocks-2022") | .method' "$inbounds_file")
        echo -e " Shadowsocks-2022: ${green}已启用${re} (端口: ${skyblue}${ss_port}${re}, 加密: ${skyblue}${ss_method}${re})"
    else
        echo -e " Shadowsocks-2022: ${yellow}未启用${re}"
    fi
    echo ""
}

# 协议管理主菜单
manage_protocols() {
    check_singbox &>/dev/null
    if [ $? -eq 2 ]; then
        yellow "sing-box 尚未安装！请先安装 sing-box。"; sleep 2; menu; return
    fi

    clear; echo ""
    green "=== 协议管理 (增加/删除) ===\n"
    show_extra_proto_status

    green "--- Socks5 协议 ---"
    green "1. 添加 Socks5 协议"
    red   "2. 删除 Socks5 协议"
    skyblue "-----------------------------"
    green "--- AnyTLS 协议 ---"
    green "3. 添加 AnyTLS 协议"
    red   "4. 删除 AnyTLS 协议"
    skyblue "-----------------------------"
    green "--- Shadowsocks-2022 协议 ---"
    green "5. 添加 Shadowsocks-2022 协议"
    red   "6. 删除 Shadowsocks-2022 协议"
    skyblue "-----------------------------"
    purple "0. 返回主菜单"
    skyblue "-----------------------------"
    reading "请输入选择: " proto_choice
    echo ""
    case "${proto_choice}" in
        1) add_socks5_inbound ;;
        2) remove_socks5_inbound ;;
        3) add_anytls ;;
        4) remove_anytls ;;
        5) add_ss2022 ;;
        6) remove_ss2022 ;;
        0) menu; return ;;
        *) red "无效的选项！" ;;
    esac
    read -n 1 -s -r -p $'\n\033[1;91m按任意键返回协议管理菜单...\033[0m\n'
    manage_protocols
}

# 主菜单
menu() {
    singbox_status=$(check_singbox 2>/dev/null)
    nginx_status=$(check_nginx 2>/dev/null)
    argo_status=$(check_argo 2>/dev/null)

    clear; echo ""
    green "Telegram群组: ${purple}https://t.me/eooceu${re}"
    green "YouTube频道: ${purple}https://youtube.com/@eooce${re}"
    green "Github地址: ${purple}https://github.com/eooce/sing-box${re}\n"
    purple "=== 老王sing-box四合一安装脚本 ===\n"
    purple "---Argo 状态: ${argo_status}"
    purple "--Nginx 状态: ${nginx_status}"
    purple "singbox 状态: ${singbox_status}\n"
    green "1. 安装sing-box"
    red   "2. 卸载sing-box"
    echo "==============="
    green "3. sing-box管理"
    green "4. Argo隧道管理"
    echo "==============="
    green "5. 查看节点信息"
    green "6. 修改节点配置"
    green "7. 管理节点订阅"
    green "8. WARP分流管理"
    echo "==============="
    green "9. 增加/删除协议"
    echo "==============="
    purple "10. ssh综合工具箱"
    echo "==============="
    red "0. 退出脚本"
    echo "==========="
    # ← 去掉 reading，只负责显示
}

# 捕获 Ctrl+C
trap 'red "\n强制退出"; exit' INT

# ---- 参数解析入口 ----
case "$1" in
    -i | --install)
        auto_install
        exit 0
        ;;
    -u | --uninstall)
        auto_uninstall
        exit 0
        ;;
    -c | --check)
        check_nodes
        exit 0
        ;;
    -r | --restart)
        get_quick_tunnel
        change_argo_domain
        exit 0
        ;;
    -h | --help)
        echo ""
        green "用法: [sb或脚本] [参数], 示例: sb -c(查看节点信息)"
        echo ""
        green "  -i, --install     无交互安装sing-box"
        green "  -c, --check       查看节点信息和订阅链接"
        green "  -r, --restart     重新获取argo临时隧道并更新到订阅"
        green "  -u, --uninstall   无交互卸载sing-box（含 nginx)"
        green "  -h, --help        显示此帮助信息"
        echo ""
        green "  不带参数          进入交互式主菜单"
        echo ""
        exit 0
        ;;
    "")
        # 无参数：进入交互式主菜单
        while true; do
            menu
            reading "请输入选择(0-10): " choice 
            echo ""
            need_pause=true  
            case "${choice}" in
                1)
                    check_singbox &>/dev/null; singbox_check=$?
                    if [ ${singbox_check} -eq 0 ]; then
                        yellow "sing-box 已经安装！\n"
                    else
                        manage_packages install nginx jq tar openssl lsof coreutils
                        install_singbox
                        if command_exists systemctl; then
                            main_systemd_services
                        elif command_exists rc-update; then
                            alpine_openrc_services
                            change_hosts
                            rc-service sing-box restart
                            rc-service argo restart
                        else
                            echo "Unsupported init system"; exit 1
                        fi
                        sleep 5
                        get_info
                        add_nginx_conf
                        create_shortcut
                    fi
                    ;;
                2)  uninstall_singbox;  need_pause=false ;;
                3)  manage_singbox;     need_pause=false ;;
                4)  manage_argo;        need_pause=false ;;
                5)  check_nodes;        need_pause=false ;;
                6)  change_config;      need_pause=false ;;
                7)  disable_open_sub;   need_pause=false ;;
                8)  warp_manage;        need_pause=false ;;
                9)  manage_protocols;   need_pause=false ;;
                10)
                    clear
                    bash <(curl -Ls ssh_tool.eooce.com)
                    need_pause=false
                    ;;
                0)  exit 0 ;;       
                *)
                    red "无效的选项，请输入 0-10"
                    need_pause=true
                    ;;
            esac
            [ "$need_pause" = true ] && read -n 1 -s -r -p $'\033[1;91m按任意键返回...\033[0m'
        done
        ;;
    *)
        red "未知参数: $1"
        echo ""
        green "用法: sb [参数],相关参数:[-i|-u|-c|-r|-h], 首次安装：bash脚本 -i(前面可带环境变量)"
        exit 1
        ;;
esac
