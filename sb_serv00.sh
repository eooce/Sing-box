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
USERNAME=$(whoami)
HOSTNAME=$(hostname)
export UUID=${UUID:-'bc97f674-c578-4940-9234-0a1da46041b0'}
export NEZHA_SERVER=${NEZHA_SERVER:-''} 
export NEZHA_PORT=${NEZHA_PORT:-'5555'}     
export NEZHA_KEY=${NEZHA_KEY:-''} 
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}   
export ARGO_AUTH=${ARGO_AUTH:-''}
export CFIP=${CFIP:-'www.visa.com.tw'} 
export CFPORT=${CFPORT:-'443'}
export SUB_TOKEN=${SUB_TOKEN:-'sub'}
FILE_PATH="$HOME/domains/${USERNAME}.serv00.net/public_html"
[[ "$HOSTNAME" == "s1.ct8.pl" ]] && WORKDIR="domains/${USERNAME}.ct8.pl/logs" || WORKDIR="domains/${USERNAME}.serv00.net/logs"
[ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")
bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1

check_binexec_and_port () {
port_list=$(devil port list)
tcp_ports=$(echo "$port_list" | grep -c "tcp")
udp_ports=$(echo "$port_list" | grep -c "udp")

if [[ $tcp_ports -ne 1 || $udp_ports -ne 2 ]]; then
    red "端口规则不符合要求，正在调整..."

    if [[ $tcp_ports -gt 1 ]]; then
        tcp_to_delete=$((tcp_ports - 1))
        echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
            devil port del $type $port >/dev/null 2>&1
            green "已删除TCP端口: $port"
        done
    fi

    if [[ $udp_ports -gt 2 ]]; then
        udp_to_delete=$((udp_ports - 2))
        echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
            devil port del $type $port >/dev/null 2>&1
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

export VMESS_PORT=$tcp_port
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
      reading "请输入哪吒探针端口（回车跳过默认使用5555）：" NEZHA_PORT
      [[ -z $NEZHA_PORT ]] && NEZHA_PORT="5555"
      green "你的哪吒端口为: $NEZHA_PORT"
      reading "请输入哪吒探针密钥：" NEZHA_KEY
      green "你的哪吒密钥为: $NEZHA_KEY"
  fi
}

install_singbox() {
echo -e "${yellow}本脚本同时四协议共存${purple}(vmess-ws,vmess-ws-tls(argo),hysteria2,tuic)${re}"
reading "\n确定继续安装吗？【y/n】: " choice
  case "$choice" in
    [Yy])
        cd $WORKDIR
        check_binexec_and_port
        read_nz_variables
        argo_configure
        generate_config
        download_singbox
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
            devil www  keep.${USERNAME}.serv00.net nodejs 2>/dev/null || true
	    clear
       	    green "Sing-box四合一已完全卸载"
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

# Generating argo Config
argo_configure() {
  if [[ -z $ARGO_AUTH || -z $ARGO_DOMAIN ]]; then
      reading "是否需要使用固定argo隧道？(直接回车将使用临时隧道)【y/n】: " argo_choice
      [[ -z $argo_choice ]] && return
      [[ "$argo_choice" != "y" && "$argo_choice" != "Y" && "$argo_choice" != "n" && "$argo_choice" != "N" ]] && { red "无效的选择，请输入y或n"; return; }
      if [[ "$argo_choice" == "y" || "$argo_choice" == "Y" ]]; then
          reading "请输入argo固定隧道域名: " ARGO_DOMAIN
          green "你的argo固定隧道域名为: $ARGO_DOMAIN"
          reading "请输入argo固定隧道密钥（Json或Token）: " ARGO_AUTH
          green "你的argo固定隧道密钥为: $ARGO_AUTH"
	        echo -e "${red}注意：${purple}使用token，需要在cloudflare后台设置隧道端口和面板开放的tcp端口一致${re}"
      else
          green "ARGO隧道变量未设置，将使用临时隧道"
          return
      fi
  fi

  if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    echo $ARGO_AUTH > tunnel.json
    cat > tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$ARGO_AUTH")
credentials-file: tunnel.json
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$VMESS_PORT
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
  else
    green "ARGO_AUTH mismatch TunnelSecret,use token connect to tunnel"
  fi
}

# Generating Configuration Files
generate_config() {

  openssl ecparam -genkey -name prime256v1 -out "private.key"
  openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.serv00.net"
  
  yellow "获取可用IP中，请稍等..."
  available_ip=$(get_ip)
  purple "当前选择IP为：$available_ip 如安装完后节点不通可尝试重新安装"
  
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
      "tag": "vmess-ws-in",
      "type": "vmess",
      "listen": "::",
      "listen_port": $VMESS_PORT,
      "users": [
      {
        "uuid": "$UUID"
      }
    ],
    "transport": {
      "type": "ws",
      "path": "/vmess-argo",
      "early_data_header_name": "Sec-WebSocket-Protocol"
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
          "password": "admin123"
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

# Download Dependency Files
download_singbox() {
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

if [ -e "$(basename ${FILE_MAP[bot]})" ]; then
    if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
    elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
      args="tunnel --edge-ip-version auto --config tunnel.yml run"
    else
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile boot.log --loglevel info --url http://localhost:$VMESS_PORT"
    fi
    nohup ./"$(basename ${FILE_MAP[bot]})" $args >/dev/null 2>&1 &
    sleep 2
    pgrep -x "$(basename ${FILE_MAP[bot]})" > /dev/null && green "$(basename ${FILE_MAP[bot]}) is running" || { red "$(basename ${FILE_MAP[bot]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[bot]})" && nohup ./"$(basename ${FILE_MAP[bot]})" "${args}" >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[bot]}) restarted"; }
fi
sleep 2
rm -f "$(basename ${FILE_MAP[npm]})" "$(basename ${FILE_MAP[web]})" "$(basename ${FILE_MAP[bot]})"
}

get_argodomain() {
  if [[ -n $ARGO_AUTH ]]; then
    echo "$ARGO_DOMAIN"
  else
    local retry=0
    local max_retries=6
    local argodomain=""
    while [[ $retry -lt $max_retries ]]; do
      ((retry++))
      argodomain=$(grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' boot.log | sed 's@https://@@') 
      if [[ -n $argodomain ]]; then
        break
      fi
      sleep 1
    done
    echo "$argodomain"
  fi
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
base64 -w0 list.txt > ${FILE_PATH}/${SUB_TOKEN}_v2.log
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
argodomain=$(get_argodomain)
echo -e "\e[1;32mArgoDomain:\e[1;35m${argodomain}\e[0m\n"
ISP=$(curl -s --max-time 1.5 https://speed.cloudflare.com/meta | awk -F\" '{print $26}' | sed -e 's/ /_/g' || echo "0")
get_name() { if [ "$HOSTNAME" = "s1.ct8.pl" ]; then SERVER="CT8"; else SERVER=$(echo "$HOSTNAME" | cut -d '.' -f 1); fi; echo "$SERVER"; }
NAME="$ISP-$(get_name)"
yellow "注意：v2ray或其他软件的跳过证书验证需设置为true,否则hy2或tuic节点可能不通\n"
cat > list.txt <<EOF
vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess\", \"add\": \"$available_ip\", \"port\": \"$VMESS_PORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/vmess-argo?ed=2048\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)

vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-argo\", \"add\": \"$CFIP\", \"port\": \"$CFPORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/vmess-argo?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)

hysteria2://$UUID@$available_ip:$HY2_PORT/?sni=www.bing.com&alpn=h3&insecure=1#$NAME-hysteria2

tuic://$UUID:admin123@$available_ip:$TUIC_PORT?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#$NAME-tuic
EOF
cat list.txt
generate_sub_link
rm -rf boot.log config.json sb.log core tunnel.yml tunnel.json fake_useragent_0.2.0.json
quick_command
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
    app_file_url="https://00.2go.us.kg/app.js"

    if command -v curl &> /dev/null; then
        curl -s -o "${keep_path}/app.js" "$app_file_url"
    elif command -v wget &> /dev/null; then
        wget -q -O "${keep_path}/app.js" "$app_file_url"
    else
        echo "警告: 文件下载失败,请手动从https://00.2go.us.kg/app.js下载文件,并将文件上传到${keep_path}目录下"
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
    devil www add keep.${USERNAME}.serv00.net nodejs /usr/local/bin/node18 > /dev/null 2>&1
    ln -fs /usr/local/bin/node18 ~/bin/node > /dev/null 2>&1
    ln -fs /usr/local/bin/npm18 ~/bin/npm > /dev/null 2>&1
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    echo 'export PATH=~/.npm-global/bin:~/bin:$PATH' >> $HOME/.bash_profile && source $HOME/.bash_profile
    cd ${keep_path} && npm install dotenv axios --silent > /dev/null 2>&1
    rm $HOME/domains/keep.${USERNAME}.serv00.net/public_nodejs/public/index.html > /dev/null 2>&1
    devil www options keep.${USERNAME}.serv00.net sslonly on > /dev/null 2>&1
    devil www restart keep.${USERNAME}.serv00.net
    green "保活服务已安装成功\n"
    green "================================================================"
    purple "访问 https://keep.${USERNAME}.serv00.net/status 查看进程状态\n"
    yellow "访问 https://keep.${USERNAME}.serv00.net/start 调起保活程序\n"
    purple "访问 https://keep.${USERNAME}.serv00.net/list 全部进程列表\n"
    purple "访问 https://keep.${USERNAME}.serv00.net/stop 结束进程\n"
    yellow "如发现掉线访问https://keep.${USERNAME}.serv00.net/start唤醒,或者用https://console.cron-job.org在线访问网页自动唤醒\n"
    yellow "如果需要 Telegram通知，请先在 Telegram @Botfather 申请 Bot-Token，并将其填入并重新运行\n"
}

quick_command () {
script_url="https://raw.githubusercontent.com/eooce/sing-box/main/sb_serv00.sh"
command -v curl &> /dev/null && curl -s -o "$HOME/sb.sh" "$script_url" || command -v wget &> /dev/null && wget -q -O "$HOME/sb.sh" "$script_url" || red "sb快捷指令添加失败,issues反馈: https://github.com/eooce/Sing-box/issues"
  add_alias () {
    local config_file=$1
    local alias_names=("sb" "SB")
    if [[ ! -f "$config_file" ]]; then
        touch "$config_file" > /dev/null 2>&1
    fi
    for alias_name in "${alias_names[@]}"; do
        if ! grep -q "alias $alias_name=" "$config_file"; then
            echo "alias $alias_name='cd ~ && ./sb.sh'" >> "$config_file" > /dev/null 2>&1
        fi
    done
    source "$config_file" > /dev/null 2>&1
  }
  config_file="$HOME/.bashrc"
  add_alias "$config_file"
}

menu() {
   clear
   echo ""
   purple "=== Serv00|ct8老王sing-box一键四合一安装脚本 ===\n"
   echo -e "${green}脚本地址：${re}${yellow}https://github.com/eooce/Sing-box${re}\n"
   echo -e "${green}反馈论坛：${re}${yellow}https://bbs.vps8.me${re}\n"
   echo -e "${green}TG反馈群组：${re}${yellow}https://t.me/vps888${re}\n"
   purple "转载请著名出处，请勿滥用\n"
   yellow "快捷键sb,下次运行输入sb快速运行脚本\n"
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
        4) cat $WORKDIR/list.txt && yellow "\n节点订阅链接:\nClash: ${purple}https://${USERNAME}.serv00.net/get_sub.php?file=sub_clash.yaml${re}\n\n${yellow}Sing-box: ${purple}https://${USERNAME}.serv00.net/get_sub.php?file=sub_singbox.yaml${re}\n\n${yellow}V2rayN/Nekoray/小火箭: ${purple}https://${USERNAME}.serv00.net/sub_v2.log${re}\n";; 
	5) kill_all_tasks ;;
        0) exit 0 ;;
        *) red "无效的选项，请输入 0 到 5" ;;
    esac
}
menu
