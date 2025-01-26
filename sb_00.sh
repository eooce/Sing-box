#!/bin/bash

re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }
export LC_ALL=C
HOSTNAME=$(hostname)
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
export UUID=${UUID:-'bc97f674-c578-4940-9234-0a1da46041b0'}
export NEZHA_SERVER=${NEZHA_SERVER:-''} 
export NEZHA_PORT=${NEZHA_PORT:-'5555'}     
export NEZHA_KEY=${NEZHA_KEY:-''} 
export SUB_TOKEN=${SUB_TOKEN:-'sub'}

[[ "$HOSTNAME" == "s1.ct8.pl" ]] && WORKDIR="${HOME}/domains/${USERNAME}.ct8.pl/logs" && FILE_PATH="${HOME}/domains/${USERNAME}.ct8.pl/public_html" || WORKDIR="${HOME}/domains/${USERNAME}.serv00.net/logs" && FILE_PATH="${HOME}/domains/${USERNAME}.serv00.net/public_html"
rm -rf "$WORKDIR" && mkdir -p "$WORKDIR" "$FILE_PATH" && chmod 777 "$WORKDIR" "$FILE_PATH" >/dev/null 2>&1
bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1

check_binexec_and_port () {
port_list=$(devil port list)
tcp_ports=$(echo "$port_list" | grep -c "tcp")
udp_ports=$(echo "$port_list" | grep -c "udp")

if [[ $tcp_ports -ne 1 || $udp_ports -ne 2 ]]; then
    red "端口数量不符合要求，正在调整..."

    if [[ $tcp_ports -gt 1 ]]; then
        tcp_to_delete=$((tcp_ports - 1))
        echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
            devil port del $type $port
            green "已删除TCP端口: $port"
        done
    fi

    if [[ $udp_ports -gt 2 ]]; then
        udp_to_delete=$((udp_ports - 2))
        echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
            devil port del $type $port
            green "已删除UDP端口: $port"
        done
    fi

    if [[ $tcp_ports -lt 1 ]]; then
        while true; do
            tcp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add tcp $tcp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                green "已添加TCP端口: $tcp_port"
                break
            else
                yellow "端口 $tcp_port 不可用，尝试其他端口..."
            fi
        done
    fi

    if [[ $udp_ports -lt 2 ]]; then
        udp_ports_to_add=$((2 - udp_ports))
        udp_ports_added=0
        while [[ $udp_ports_added -lt $udp_ports_to_add ]]; do
            udp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add udp $udp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                green "已添加UDP端口: $udp_port"
                if [[ $udp_ports_added -eq 0 ]]; then
                    udp_port1=$udp_port
                else
                    udp_port2=$udp_port
                fi
                udp_ports_added=$((udp_ports_added + 1))
            else
                yellow "端口 $udp_port 不可用，尝试其他端口..."
            fi
        done
    fi
    green "端口已调整完成,将断开ssh连接,请重新连接shh重新执行脚本"
    devil binexec on >/dev/null 2>&1
    kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
else
    tcp_port=$(echo "$port_list" | awk '/tcp/ {print $1}')
    udp_ports=$(echo "$port_list" | awk '/udp/ {print $1}')
    udp_port1=$(echo "$udp_ports" | sed -n '1p')
    udp_port2=$(echo "$udp_ports" | sed -n '2p')

    purple "当前TCP端口: $tcp_port"
    purple "当前UDP端口: $udp_port1 和 $udp_port2"
fi

export VLESS_PORT=$tcp_port
export TUIC_PORT=$udp_port1
export HY2_PORT=$udp_port2
}

read_nz_variables() {
  if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
      green "使用自定义变量哪吒运行哪吒探针"
      return
  else
      reading "是否需要安装哪吒探针？(直接回车则不安装)【y/n】: " nz_choice
      [[ -z $nz_choice ]] && return
      [[ "$nz_choice" != "y" && "$nz_choice" != "Y" ]] && return
      reading "请输入哪吒探针域名或ip：" NEZHA_SERVER
      green "你的哪吒域名为: $NEZHA_SERVER"
      reading "请输入哪吒探针端口 (回车跳过默认使用5555): " NEZHA_PORT
      [[ -z $NEZHA_PORT ]] && NEZHA_PORT="5555"
      green "你的哪吒端口为: $NEZHA_PORT"
      reading "请输入哪吒探针密钥：" NEZHA_KEY
      green "你的哪吒密钥为: $NEZHA_KEY"
  fi
}

install_singbox() {
echo -e "${yellow}本脚本同时三协议共存${purple}(vless-reality,hysteria2,tuic)${re}"
reading "\n确定继续安装吗？【y/n】: " choice
  case "$choice" in
    [Yy])
        cd $WORKDIR
        check_binexec_and_port
        read_nz_variables
        download_and_run_singbox
        get_links
      ;;
    [Nn]) exit 0 ;;
    *) red "无效的选择，请输入y或n" && menu ;;
  esac
}

uninstall_singbox() {
  reading "\n确定要卸载吗？【y/n】: " choice
    case "$choice" in
        [Yy])
	    bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
       	    rm -rf $WORKDIR && find ${FILE_PATH} -mindepth 1 ! -name 'index.html' -exec rm -rf {} +
            devil www del keep.${USERNAME}.serv00.net nodejs 2>/dev/null || true
            rm -rf ${HOME}/domains/${USERNAME}.ct8.pl/public_nodejs
	    clear
       	    green "Sing-box三合一已完全卸载"
          ;;
        [Nn]) exit 0 ;;
    	  *) red "无效的选择，请输入y或n" && menu ;;
    esac
}

kill_all_tasks() {
reading "\n确定继续清理吗？【y/n】: " choice
  case "$choice" in
    [Yy]) bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1 ;;
       *) menu ;;
  esac
}

download_and_run_singbox() {
  ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
  if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
      FILE_INFO=("https://github.com/eooce/test/releases/download/arm64/sb web" "https://github.com/eooce/test/releases/download/arm64/bot13 bot" "https://github.com/eooce/test/releases/download/ARM/swith npm")
  elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
      FILE_INFO=("https://github.com/eooce/test/releases/download/freebsd/sb web" "https://github.com/eooce/test/releases/download/freebsd/server bot" "https://github.com/eooce/test/releases/download/freebsd/npm npm")
  else
      echo "Unsupported architecture: $ARCH"
      exit 1
  fi
declare -A FILE_MAP
generate_random_name() {
    local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
    local name=""
    for i in {1..6}; do
        name="$name${chars:RANDOM%${#chars}:1}"
    done
    echo "$name"
}

download_with_fallback() {
    local URL=$1
    local NEW_FILENAME=$2

    curl -L -sS --max-time 2 -o "$NEW_FILENAME" "$URL" &
    CURL_PID=$!
    CURL_START_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)
    
    sleep 1
    CURL_CURRENT_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)
    
    if [ "$CURL_CURRENT_SIZE" -le "$CURL_START_SIZE" ]; then
        kill $CURL_PID 2>/dev/null
        wait $CURL_PID 2>/dev/null
        wget -q -O "$NEW_FILENAME" "$URL"
        echo -e "\e[1;32mDownloading $NEW_FILENAME by wget\e[0m"
    else
        wait $CURL_PID
        echo -e "\e[1;32mDownloading $NEW_FILENAME by curl\e[0m"
    fi
}

for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    RANDOM_NAME=$(generate_random_name)
    NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"
    
    if [ -e "$NEW_FILENAME" ]; then
        echo -e "\e[1;32m$NEW_FILENAME already exists, Skipping download\e[0m"
    else
        download_with_fallback "$URL" "$NEW_FILENAME"
    fi
    
    chmod +x "$NEW_FILENAME"
    FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
done
wait

output=$(./"$(basename ${FILE_MAP[web]})" generate reality-keypair)
private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')

openssl ecparam -genkey -name prime256v1 -out "private.key"
openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.serv00.net"
  
yellow "获取可用IP中,请稍等..."
available_ip=$(get_ip)
purple "当前选择IP为: $available_ip 如安装完后节点不通可尝试重新安装"
  
cat > config.json << EOF
{
  "log": {
    "disabled": true,
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
       "tag": "hysteria-in",
       "type": "hysteria2",
       "listen": "$available_ip",
       "listen_port": $HY2_PORT,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://bing.com",
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
    {
        "tag": "vless-reality-vesion",
        "type": "vless",
        "listen": "$available_ip",
        "listen_port": $VLESS_PORT,
        "users": [
            {
              "uuid": "$UUID",
              "flow": "xtls-rprx-vision"
            }
        ],
        "tls": {
            "enabled": true,
            "server_name": "www.cerebrium.ai",
            "reality": {
                "enabled": true,
                "handshake": {
                    "server": "www.cerebrium.ai",
                    "server_port": 443
                },
                "private_key": "$private_key",
                "short_id": [
                  ""
                ]
            }
        }
    },
    {
      "tag": "tuic-in",
      "type": "tuic",
      "listen": "$available_ip",
      "listen_port": $TUIC_PORT,
      "users": [
        {
          "uuid": "$UUID",
          "password": "admin"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "cert.pem",
        "key_path": "private.key"
      }
    }

 ],
 "outbounds": [
EOF

# 如果是s14,设置 WireGuard 出站
if [ "$HOSTNAME" == "s14.serv00.com" ]; then
  cat >> config.json << EOF
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "162.159.195.100",
      "server_port": 4500,
      "local_address": [
        "172.16.0.2/32",
        "2606:4700:110:83c7:b31f:5858:b3a8:c6b1/128"
      ],
      "private_key": "mPZo+V9qlrMGCZ7+E6z2NI6NOV34PD++TpAR09PtCWI=",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": [
        26,
        21,
        228
      ]
    },
EOF
fi

# 添加默认的 direct 和 block 出站
cat >> config.json << EOF
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    }
  ],
  "route": {
    "rules": [
EOF

if [ "$HOSTNAME" == "s14.serv00.com" ]; then
  cat >> config.json << EOF
      {
        "outbound": "wireguard-out",
        "domain": ["geosite:all"]
      },
      {
        "outbound": "direct",
        "domain": ["geosite:cn"]
      }
EOF
else
  cat >> config.json << EOF
      {
        "outbound": "direct",
        "domain": ["geosite:all"]
      }
EOF
fi

cat >> config.json << EOF
    ]
  }
}
EOF
wait

if [ -e "$(basename ${FILE_MAP[npm]})" ]; then
    tlsPorts=("443" "8443" "2096" "2087" "2083" "2053")
    if [[ "${tlsPorts[*]}" =~ "${NEZHA_PORT}" ]]; then
      NEZHA_TLS="--tls"
    else
      NEZHA_TLS=""
    fi
    if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
        export TMPDIR=$(pwd)
        nohup ./"$(basename ${FILE_MAP[npm]})" -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &
        sleep 2
        pgrep -x "$(basename ${FILE_MAP[npm]})" > /dev/null && green "$(basename ${FILE_MAP[npm]}) is running" || { red "$(basename ${FILE_MAP[npm]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[npm]})" && nohup ./"$(basename ${FILE_MAP[npm]})" -s "${NEZHA_SERVER}:${NEZHA_PORT}" -p "${NEZHA_KEY}" ${NEZHA_TLS} >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[npm]}) restarted"; }
    else
        purple "NEZHA variable is empty, skipping running"
    fi
fi

if [ -e "$(basename ${FILE_MAP[web]})" ]; then
    nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 &
    sleep 2
    pgrep -x "$(basename ${FILE_MAP[web]})" > /dev/null && green "$(basename ${FILE_MAP[web]}) is running" || { red "$(basename ${FILE_MAP[web]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[web]})" && nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[web]}) restarted"; }
fi
sleep 1
rm -f "$(basename ${FILE_MAP[npm]})" "$(basename ${FILE_MAP[web]})"
}

get_ip() {
  IP_LIST=($(devil vhost list | awk '/^[0-9]+/ {print $1}'))
  API_URL="https://status.eooce.com/api"
  IP=""
  THIRD_IP=${IP_LIST[2]}
  RESPONSE=$(curl -s --max-time 2 "${API_URL}/${THIRD_IP}")
  if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
      IP=$THIRD_IP
  else
      FIRST_IP=${IP_LIST[0]}
      RESPONSE=$(curl -s --max-time 2 "${API_URL}/${FIRST_IP}")
      if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
          IP=$FIRST_IP
      else
          IP=${IP_LIST[1]}
      fi
  fi
echo "$IP"
}

generate_sub_link () {
[ -d "$FILE_PATH" ] || mkdir -p "$FILE_PATH"
base64 -w0 $FILE_PATH/list.txt > ${FILE_PATH}/${SUB_TOKEN}_v2.log
V2rayN_LINK="https://${USERNAME}.serv00.net/${SUB_TOKEN}_v2.log"
PHP_URL="https://github.com/eooce/Sing-box/releases/download/00/get_sub.php"
curl -sS "https://sublink.eooce.com/clash?config=${V2rayN_LINK}" -o ${FILE_PATH}/${SUB_TOKEN}_clash.yaml
curl -sS "https://sublink.eooce.com/singbox?config=${V2rayN_LINK}" -o ${FILE_PATH}/${SUB_TOKEN}_singbox.yaml
command -v curl &> /dev/null && curl -s -o "${FILE_PATH}/get_sub.php" "$PHP_URL" || command -v wget &> /dev/null && wget -q -O "${FILE_PATH}/get_sub.php" "$PHP_URL" || red "Warning: Neither curl nor wget is installed. You can't use the subscription"
CLASH_LINK="https://${USERNAME}.serv00.net/get_sub.php?file=${SUB_TOKEN}_clash.yaml"
SINGBOX_LINK="https://${USERNAME}.serv00.net/get_sub.php?file=${SUB_TOKEN}_singbox.yaml"
yellow "\n节点订阅链接：\nClash: ${purple}${CLASH_LINK}${re}\n"   
yellow "Sing-box: ${purple}${SINGBOX_LINK}${re}\n"
yellow "V2rayN/Nekoray/小火箭: ${purple}${V2rayN_LINK}${re}\n\n"
}

get_links(){
ISP=$(curl -s --max-time 1.5 https://speed.cloudflare.com/meta | awk -F\" '{print $26}' | sed -e 's/ /_/g' || echo "0")
get_name() { if [ "$HOSTNAME" = "s1.ct8.pl" ]; then SERVER="CT8"; else SERVER=$(echo "$HOSTNAME" | cut -d '.' -f 1); fi; echo "$SERVER"; }
NAME="$ISP-$(get_name)"
yellow "注意：v2ray或其他软件的跳过证书验证需设置为true,否则hy2或tuic节点可能不通\n"
cat > $FILE_PATH/list.txt <<EOF
vless://$UUID@$available_ip:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cerebrium.ai&fp=chrome&pbk=$public_key&type=tcp&headerType=none#$NAME-reality

hysteria2://$UUID@$available_ip:$HY2_PORT/?sni=www.bing.com&alpn=h3&insecure=1#$NAME-hysteria2

tuic://$UUID:admin@$available_ip:$TUIC_PORT?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#$NAME-tuic
EOF
cat $FILE_PATH/list.txt
generate_sub_link
rm -rf config.json sb.log core fake_useragent_0.2.0.json
purple "Running done!"
}

install_keepalive () {
    clear
    reading "是否需要Telegram通知？(直接回车则不启用)【y/n】: " tg_notification
    if [[ "$tg_notification" == "y" || "$tg_notification" == "Y" ]]; then

        reading "请输入Telegram chat ID (tg上@userinfobot获取): " tg_chat_id
        [[ -z $tg_chat_id ]] && { red "Telegram chat ID不能为空"; return; }
        green "你设置的Telegram chat_id为: ${tg_chat_id}"

        reading "请输入Telegram Bot Token (tg上@Botfather创建bot后获取): " tg_token
        [[ -z $tg_token ]] && { red "Telegram Bot Token不能为空"; return; }
        green "你设置的Telegram bot token为: ${tg_token}"
    fi

    reading "是否需要保活哪吒探针？(直接回车则不启用)【y/n】: " keep_nezha
    if [[ "$keep_nezha" == "y" || "$keep_nezha" == "Y" ]]; then

        reading "请输入哪吒面板域名：" nezha_server
        green "你的哪吒面板域名为: $nezha_server"

        reading "请输入哪吒agent端口(直接回车则默认使用5555): " nezha_port
        [[ -z $nezha_port ]] && nezha_port=5555
        green "你的哪吒agent端口为: $nezha_port"

        reading "请输入哪吒agent密钥: " nezha_key
        [[ -z $nezha_key ]] && { red "哪吒agent密钥不能为空"; return; }
        green "你的哪吒agent密钥为: $nezha_key"
    fi

    reading "是否需要设置Argo固定隧道？(直接回车则使用临时隧道)【y/n】: " argo
    if [[ "$argo" == "y" || "$argo" == "Y" ]]; then

        reading "请输入Argo固定隧道域名: " argo_domain
        [[ -z $argo_domain ]] && { red "Argo固定隧道域名不能为空"; return; }
        green "你的Argo固定隧道域名为: $argo_domain"

        reading "请输入Argo固定隧道密钥(json或token): " argo_key
        [[ -z $argo_key ]] && { red "Argo固定隧道密钥不能为空"; return; }
        green "你的Argo固定隧道密钥为: $argo_key"
    fi

    purple "正在安装保活服务中,请稍等......"
    keep_path="$HOME/domains/keep.${USERNAME}.serv00.net/public_nodejs"
    [ -d "$keep_path" ] || mkdir -p "$keep_path"
    app_file_url="https://sb3.2go.us.kg/app.js"

    if command -v curl &> /dev/null; then
        curl -s -o "${keep_path}/app.js" "$app_file_url"
    elif command -v wget &> /dev/null; then
        wget -q -O "${keep_path}/app.js" "$app_file_url"
    else
        echo "警告: 文件下载失败,请手动从https://sb3.2go.us.kg/app.js下载文件,并将文件上传到${keep_path}目录下"
        return
    fi

    cat > ${keep_path}/.env <<EOF
# Telegram 通知
${tg_chat_id:+TELEGRAM_CHAT_ID=$tg_chat_id}
${tg_token:+TELEGRAM_BOT_TOKEN=$tg_token}

# 哪吒探针
${nezha_server:+NEZHA_SERVER=$nezha_server}
${nezha_port:+NEZHA_PORT=$nezha_port}
${nezha_key:+NEZHA_KEY=$nezha_key}

# Argo 隧道
ARGO_DOMAIN=$argo_domain
ARGO_AUTH='${argo_key}'
EOF
    devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1
    devil www add keep.${USERNAME}.serv00.net nodejs /usr/local/bin/node18 > /dev/null 2>&1
    ip_address=$(devil vhost list | sed -n '5p' | awk '{print $1}')
    devil ssl www add $ip_address le le keep.${USERNAME}.serv00.net > /dev/null 2>&1
    ln -fs /usr/local/bin/node18 ~/bin/node > /dev/null 2>&1
    ln -fs /usr/local/bin/npm18 ~/bin/npm > /dev/null 2>&1
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    echo 'export PATH=~/.npm-global/bin:~/bin:$PATH' >> $HOME/.bash_profile && source $HOME/.bash_profile
    rm -rf $HOME/.npmrc > /dev/null 2>&1
    cd ${keep_path} && npm install dotenv axios --silent > /dev/null 2>&1
    rm $HOME/domains/keep.${USERNAME}.serv00.net/public_nodejs/public/index.html > /dev/null 2>&1
    devil www options keep.${USERNAME}.serv00.net sslonly on > /dev/null 2>&1
    if devil www restart keep.${USERNAME}.serv00.net 2>&1 | grep -q "succesfully"; then
        green "\n全自动保活服务安装成功\n"
        green "========================================================"
        purple "\n访问 https://keep.${USERNAME}.serv00.net/status 查看进程状态\n"
        yellow "访问 https://keep.${USERNAME}.serv00.net/start 调起保活程序\n"
        purple "访问 https://keep.${USERNAME}.serv00.net/list 全部进程列表\n"
        purple "访问 https://keep.${USERNAME}.serv00.net/stop 结束进程和保活\n"
        green "========================================================"
        yellow "如发现掉线访问https://keep.${USERNAME}.serv00.net/start唤醒,或者用https://console.cron-job.org在线访问网页自动唤醒\n"
        purple "如果需要Telegram通知，请先在Telegram @Botfather 申请 Bot-Token，并带CHAT_ID和BOT_TOKEN环境变量运行\n\n"
        
    else
        red "全自动保活服务安装失败,请删除所有文件夹后重试\n"
    fi
}
menu() {
   clear
   echo ""
   purple "=== Serv00|ct8老王sing-box一键三协议安装脚本 ===\n"
   echo -e "${green}脚本地址：${re}${yellow}https://github.com/eooce/Sing-box${re}\n"
   echo -e "${green}反馈论坛：${re}${yellow}https://bbs.vps8.me${re}\n"
   echo -e "${green}TG反馈群组：${re}${yellow}https://t.me/vps888${re}\n"
   purple "转载请著名出处，请勿滥用\n"
   green "1. 安装sing-box"
   echo  "==============="
   green "2. 安装全自动保活"
   echo  "==============="
   red "3. 卸载sing-box"
   echo  "==============="
   green "4. 查看节点信息"
   echo  "==============="
   yellow "5. 清理所有进程"
   echo  "==============="
   red "0. 退出脚本"
   echo "==========="
   reading "请输入选择(0-3): " choice
   echo ""
    case "${choice}" in
        1) install_singbox ;;
        2) install_keepalive ;;
        3) uninstall_singbox ;; 
        4) cat $FILE_PATH/list.txt && yellow "\n节点订阅链接:\nClash: ${purple}https://${USERNAME}.serv00.net/get_sub.php?file=${SUB_TOKEN}_clash.yaml${re}\n\n${yellow}Sing-box: ${purple}https://${USERNAME}.serv00.net/get_sub.php?file=${SUB_TOKEN}_singbox.yaml${re}\n\n${yellow}V2rayN/Nekoray/小火箭: ${purple}https://${USERNAME}.serv00.net/${SUB_TOKEN}_v2.log${re}\n";; 
	5) kill_all_tasks ;;
        0) exit 0 ;;
        *) red "无效的选项，请输入 0 到 5" ;;
    esac
}
menu
