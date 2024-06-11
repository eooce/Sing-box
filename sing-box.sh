#!/bin/bash

# 定义颜色
re='\033[0m'
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple='\e[1;35m'
skybule="\e[1;36m"

# 定义常量
server_name="sing-box"
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
log_dir="/var/log/singbox.log"
client_url="${work_dir}/url.txt"

# 检查是否为root下运行
[[ $EUID -ne 0 ]] && echo -e "${red}注意: 请在root用户下运行脚本${re}" && sleep 1 && exit 1

# 检查 sing-box 是否已安装
check_singbox() {
    if [ -f "${work_dir}/${server_name}" ]; then
        status=$(systemctl is-active sing-box)
        if [ "$status" == "active" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

#根据系统类型安装依赖
install_packages() {
    packages="jq tar openssl qrencode coreutils nginx"
    install=""

    for pkg in $packages; do
        if ! command -v $pkg &>/dev/null; then
            install="$install $pkg"
        fi
    done

    if [ -z "$install" ]; then
        echo -e "${green}All packages are already installed${re}"
        return
    fi

    if command -v apt &>/dev/null; then
        cmd="apt-get install -y -q"
    elif command -v yum &>/dev/null; then
        cmd="yum install -y"
    elif command -v dnf &>/dev/null; then
        cmd="dnf install -y"
    elif command -v apk &>/dev/null; then
        cmd="apk add"
    else
        echo -e "${red}暂不支持的系统!${re}"
        exit 1
    fi
    $cmd $install
}

# 下载并安装主程序
install_singbox() {
    clear
    echo -e "${purple}正在安装sing-box中，请稍后...${re}"
    # 判断系统架构
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86' | 'i686' | 'i386') ARCH='386' ;;
        'aarch64' | 'arm64') ARCH='arm64' ;;
        'armv7l') ARCH='armv7' ;;
        's390x') ARCH='s390x' ;;
        *) echo -e"${red}不支持的架构: ${ARCH_RAW}${re}"; exit 1 ;;
    esac

    # 下载sing-box,cloudflared
    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    latest_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name | sub("^v"; "")')
    curl -sLo "${work_dir}/${server_name}.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v${latest_version}/sing-box-${latest_version}-linux-${ARCH}.tar.gz"
    curl -sLo "${work_dir}/argo" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
    tar -xzf "${work_dir}/${server_name}.tar.gz" -C "${work_dir}/" && \
    mv "${work_dir}/sing-box-${latest_version}-linux-${ARCH}/sing-box" "${work_dir}/" && \
    rm -rf "${work_dir}/${server_name}.tar.gz" "${work_dir}/sing-box-${latest_version}-linux-${ARCH}"
    chown root:root ${work_dir} && chmod +x ${work_dir}/${server_name} ${work_dir}/argo

   # 生成随机端口和密码
    vless_port=$(shuf -i 1000-65535 -n 1) 
    tuic_port=$(($vless_port + 1))
    hy2_port=$(($vless_port + 2)) 
    nginx_port=$(($vless_port + 3)) 
    password=$(tr -dc A-Za-z < /dev/urandom | head -c 8) 
    uuid=$(cat /proc/sys/kernel/random/uuid)
    output=$(/etc/sing-box/sing-box generate reality-keypair)
    private_key=$(echo "${output}" | grep -oP 'PrivateKey:\s*\K.*')
    public_key=$(echo "${output}" | grep -oP 'PublicKey:\s*\K.*')

    # 生成自签名证书
    openssl ecparam -genkey -name prime256v1 -out "${work_dir}/private.key"
    openssl req -new -x509 -days 3650 -key "${work_dir}/private.key" -out "${work_dir}/cert.pem" -subj "/CN=bing.com"

    # 获取本机 IP 和服务器服务商
    server_ip=$(curl -s ipv4.ip.sb)
    isp=$(curl -s https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g')

   # 生成配置文件
cat > "${config_dir}" << EOF
{
  "log": {
    "output": "${log_dir}",
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "address": "8.8.8.8",
        "address_resolver": "local"
      },
      {
        "tag": "local",
        "address": "local"
      }
    ]
  },
    "inbounds": [
    {
     "tag": "vless-in",
     "type": "vless",
     "listen": "::",
     "listen_port": ${vless_port},
     "users": [
         {
             "uuid": "${uuid}",
             "flow": "xtls-rprx-vision"
         }
     ],
     "tls": {
         "enabled": true,
         "server_name": "www.yahoo.com",
         "reality": {
             "enabled": true,
             "handshake": {
                 "server": "www.yahoo.com",
                 "server_port": 443
             },
             "private_key": "${private_key}",
             "short_id": [
                 ""
                ]
            }
        }
    },

    {
      "tag": "vmess-ws-in",
      "type": "vmess",
      "listen": "::",
      "listen_port": 8001,
      "users": [
      {
        "uuid": "${uuid}"
      }
    ],
    "transport": {
      "type": "ws",
      "path": "/vmess",
      "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    },

    {
       "tag": "hysteria-in",
       "type": "hysteria2",
       "listen": "::",
       "listen_port": ${hy2_port},
       "users": [
         {
             "password": "${uuid}"
         }
     ],
     "masquerade": "https://bing.com",
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "${work_dir}/cert.pem",
         "key_path": "${work_dir}/private.key"
        }
    },

    {
      "tag": "tuic=in",
      "type": "tuic",
      "listen": "::",
      "listen_port": ${tuic_port},
      "users": [
        {
          "uuid": "${uuid}"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "${work_dir}/cert.pem",
        "key_path": "${work_dir}/private.key"
      }
    }

 ],
  "outbounds": [
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    }
  ]
}
EOF
}

sb_and_argo_systemd() {
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
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
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
ExecStart=/bin/bash -c "/etc/sing-box/argo tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2>/etc/sing-box/argo.log 2>&1"
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
}
sb_and_argo_systemd

get_info(){

  argodomain=$(grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' "${work_dir}/argo.log" | sed 's@https://@@')
  
  echo -e "${green}ArgoDomain：${re}${purple}$argodomain${re}"
  
  VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"www.visa.com.sg\", \"port\": \"443\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess?ed=2048\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\" }"

  cat > ${work_dir}/url.txt <<EOF
vless://${uuid}@${server_ip}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=${public_key}&type=tcp&headerType=none#${isp}

vmess://$(echo "$VMESS" | base64 -w0)

hysteria2://${uuid}@${server_ip}:${hy2_port}/?sni=www.bing.com&alpn=h3&insecure=1#${isp}

tuic://${uuid}:@${server_ip}:${tuic_port}?sni=www.bing.com&alpn=h3&congestion_control=bbr#${isp}
EOF
echo ""
while IFS= read -r line; do echo -e "${yellow}$line${re}"; done < ${work_dir}/url.txt
base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt
echo ""
echo -e "${green}节点订阅链接：http://${server_ip}:${nginx_port}/sub  适用于V2rayN,Nekbox,小火箭,圈X等${re}"
echo ""
qrencode -t ANSIUTF8 -m 2 -s 2 -o - "http://${server_ip}:${nginx_port}/sub"
echo ""
}

add_nginx_conf(){
new_config="server {
    listen $nginx_port;

    location /sub {
        alias /etc/sing-box/sub.txt;
        default_type 'text/plain; charset=utf-8';
    }
}"

echo "$new_config" | sudo tee /etc/nginx/server_config_temp.conf > /dev/null
sed -i '/http {/r /etc/nginx/server_config_temp.conf' /etc/nginx/nginx.conf
rm /etc/nginx/server_config_temp.conf

nginx -t

if [ $? -eq 0 ]; then
    systemctl reload nginx
    systemctl restart nginx
fi
}

# 启动 sing-box
start_singbox() {
   echo -e "${yellow}正在启动 ${server_name} 服务${re}"
   systemctl daemon-reload
   systemctl start "${server_name}"
   if [ $? -eq 0 ]; then
       echo -e "${green}${server_name} 服务已成功启动${re}"
   else
       echo -e "${red}${server_name} 服务启动失败${re}"
   fi
}

# 停止 sing-box
stop_singbox() {
   echo -e "${yellow}正在停止 ${server_name} 服务${re}"
   systemctl stop "${server_name}"
   if [ $? -eq 0 ]; then
       echo -e "${green}${server_name} 服务已成功停止${re}"
   else
       echo -e "${red}${server_name} 服务停止失败${re}"
   fi
}

# 重启 sing-box
restart_singbox() {
   echo -e "${yellow}正在重启 ${server_name} 服务${re}"
   systemctl daemon-reload
   systemctl restart "${server_name}"
   if [ $? -eq 0 ]; then
       echo -e "${green}${server_name} 服务已成功重启${re}"
   else
       echo -e "${red}${server_name} 服务重启失败${re}"
   fi
}

# 卸载 sing-box
uninstall_singbox() {
   read -p "$(echo -e "${red}确定要卸载 sing-box 吗? (y/n) ${re}")" choice
   case "${choice}" in
       y|Y)
           echo -e "${yellow}正在卸载 sing-box${re}"

           # 停止 sing-box和 argo 服务
           systemctl stop "${server_name}"
           systemctl stop argo
           # 禁用 sing-box 服务
           systemctl disable "${server_name}"
           systemctl disable argo
           # 删除配置文件和日志
           rm -rf "${work_dir}" || true
           rm -f "${log_dir}" || true

           # 重新加载 systemd
           systemctl daemon-reload || true

           echo -e "${green}sing-box 卸载成功${re}"
           echo ""
           ;;
       *)
           echo -e "${yellow}已取消卸载操作${re}"
           ;;
   esac
}

# 创建快捷指令
create_shortcut() {
  cat > "$work_dir/sb.sh" << EOF
#!/usr/bin/env bash

bash <(curl -Ls https://raw.githubusercontent.com/eooce/scripts/master/sing-box.sh) \$1
EOF
  chmod +x "$work_dir/sb.sh"
  sudo ln -sf "$work_dir/sb.sh" /usr/bin/sb
  if [ -s /usr/bin/sb ]; then
    echo -e "${green}\nsb 快捷指令创建成功${re}"
  else
    echo -e "${red}\nsb 快捷指令创建失败${re}"
  fi
}

menu() {
   check_singbox
   check_singbox=$?
   clear
   echo ""
   echo -e "${purple}=== 老王sing-box一键安装脚本 ===${re}"
   echo -e "${green}sing-box 状态: $(if [ ${check_singbox} -eq 0 ]; then echo "${green}running${re}"; else echo "${red}not running${re}"; fi)${re}   ${green}Argo 状态: ${re}$(systemctl is-active argo &>/dev/null && echo -e "${green}running${re}" || echo -e "${red}not running${re}")"
   echo -e "${green}1. 安装 sing-box${re}"
   echo -e "${red}2. 卸载 sing-box${re}"
   echo -e "${green}=================${re}"
   echo -e "${green}3. 启动 sing-box${re}"
   echo -e "${yellow}4. 停止 sing-box${re}"
   echo -e "${green}5. 重启 sing-box${re}"
   echo -e "${green}=================${re}"
   echo -e "${green}6. 查看节点信息${re}"
   echo -e "${green}7. 重新获取Argo域名${re}"
   echo -e "${green}=================${re}"
   echo -e "${red}0. 退出脚本${re}"
   echo -e "${green}=================${re}"
   read -p $'\033[1;91m请输入选择(0-7): \033[0m' choice
   echo ""
}

# 捕获 Ctrl+C 信号
trap 'echo "已取消操作"; exit' INT

# 主循环
while true; do
   menu
   case "${choice}" in
       1)
           if [ ${check_singbox} -eq 0 ]; then
                echo -e "${green}sing-box 已经安装！${re}"
           else
                install_packages
                install_singbox
                start_singbox
                systemctl daemon-reload
                systemctl enable argo
                systemctl start argo
                systemctl restart argo
                sleep 3
                get_info
                add_nginx_conf
                create_shortcut
           fi
           ;;
       2)
           if [ ${check_singbox} -eq 0 ]; then
               uninstall_singbox
           else
               echo -e "${yellow}sing-box 尚未安装！${re}"
           fi
           ;;
       3)
           start_singbox
           ;;
       4)
           stop_singbox
           ;;
       5)
           restart_singbox
           ;;
       6)
           while IFS= read -r line; do echo -e "${yellow}$line${re}"; done < ${work_dir}/url.txt
           ;;
       7)
           clear
           systemctl stop argo
           systemctl restart argo
           sleep 3
           argodomain=$(grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' "${work_dir}/argo.log" | sed 's@https://@@')
           echo ""
           echo -e "${green}ArgoDomain：${re}${purple}$argodomain${re}"
           echo ""
           echo -e "${yellow}请自行修改客户端vmess节点伪装域名${re}"
           ;;
       0)
           exit 0
           ;;
       *)
           echo -e "${red}无效的选项，请输入 0 到 7${re}"
           ;;
   esac
   read -p $'\033[1;91m按 回车键 继续...\033[0m'
done
