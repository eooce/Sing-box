#!/bin/bash  
export UUID=${UUID:-'bc97f674-c578-4940-9234-0a1da46041b9'}
export NEZHA_SERVER=${NEZHA_SERVER:-''} 
export NEZHA_PORT=${NEZHA_PORT:-'5555'}     
export NEZHA_KEY=${NEZHA_KEY:-''}
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}   
export ARGO_AUTH=${ARGO_AUTH:-''} 
export CFIP=${CFIP:-'www.visa.com.tw'} 
export CFPORT=${CFPORT:-'8443'}    
export ARGO_PORT=${ARGO_PORT:-'8001'}                # argo端口也是vmess端口 使用固定隧道token需和cf后台设置对应
export SERVER_PORT="${SERVER_PORT:-${PORT:-7860}}"   # Hy2 端口，自动获取玩具端口，无需不用填写
export REALITY_PORT=${REALITY_PORT:-'50000'}         # vless-reality 端口,支持多端口玩具可填写
export TUIC_PORT=${TUIC_PORT:-'60000'}               # tuic5 端口，支持多端口玩具可填写

# Select Tunnel mode
argo_configure() {
  if [[ -z $ARGO_AUTH || -z $ARGO_DOMAIN ]]; then
    echo -e "\e[1;32mARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels\e[0m"
    return
  fi

  if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    echo $ARGO_AUTH > tunnel.json
    cat > tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$ARGO_AUTH")
credentials-file: tunnel.json
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$ARGO_PORT
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
  else
    echo -e "\e[1;32mARGO_AUTH mismatch TunnelSecret,use token connect to tunnel\e[0m"
  fi
}
argo_configure
wait

# Download Dependency Files
ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
    FILE_INFO=("https://github.com/eooce/test/releases/download/arm64/sb web" "https://github.com/eooce/test/releases/download/arm64/bot13 bot" "https://github.com/eooce/test/releases/download/ARM/swith npm")
elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
    FILE_INFO=("https://github.com/eooce/test/releases/download/amd64/sb web" "https://github.com/eooce/test/releases/download/amd64/bot13 bot" "https://github.com/eooce/test/releases/download/freebsd/swith npm")
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi
for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    NEW_FILENAME=$(echo "$entry" | cut -d ' ' -f 2)
    FILENAME="$DOWNLOAD_DIR/$NEW_FILENAME"
    if [ -e "$FILENAME" ]; then
        echo -e "\e[1;32m$FILENAME already exists,Skipping download\e[0m"
    else
        curl -L -sS -o "$FILENAME" "$URL"
        echo -e "\e[1;32mDownloading $FILENAME\e[0m"
    fi
    chmod +x $FILENAME
done
wait

# Generating Configuration Files
generate_config() {

    output=$(/home/container/web generate reality-keypair)
    private_key=$(echo "${output}" | grep -oP 'PrivateKey:\s*\K.*')
    public_key=$(echo "${output}" | grep -oP 'PublicKey:\s*\K.*')

    openssl ecparam -genkey -name prime256v1 -out "private.key"
    openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=bing.com"

  cat > config.json << EOF
{
  "log": {
    "output": "sb.log",
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
       "listen": "::",
       "listen_port": ${SERVER_PORT},
       "users": [
         {
             "password": "${UUID}"
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
     "tag": "vless-in",
     "type": "vless",
     "listen": "::",
     "listen_port": ${REALITY_PORT},
     "users": [
         {
             "uuid": "${UUID}",
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
      "listen_port": ${ARGO_PORT},
      "users": [
      {
        "uuid": "${UUID}"
      }
    ],
    "transport": {
      "type": "ws",
      "path": "/vmess",
      "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    },

    {
      "tag": "tuic=in",
      "type": "tuic",
      "listen": "::",
      "listen_port": ${TUIC_PORT},
      "users": [
        {
          "uuid": "${UUID}"
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
generate_config
wait

# running files
run() {
  if [ -e npm ]; then
    tlsPorts=("443" "8443" "2096" "2087" "2083" "2053")
    if [[ "${tlsPorts[*]}" =~ "${NEZHA_PORT}" ]]; then
      NEZHA_TLS="--tls"
    else
      NEZHA_TLS=""
    fi
    if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
        nohup ./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &
	    sleep 2
        echo -e "\e[1;32mnpm is running\e[0m"
    else
        echo -e "\e[1;35mNEZHA variable is empty,skiping runing\e[0m"
    fi
  fi

  if [ -e web ]; then
    nohup ./web run -c config.json >/dev/null 2>&1 &
    sleep 2
    echo -e "\e[1;32mweb is running\e[0m"
  fi

  if [ -e bot ]; then
    if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
    elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
      args="tunnel --edge-ip-version auto --config tunnel.yml run"
    else
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile boot.log --loglevel info --url http://localhost:$ARGO_PORT"
    fi
    nohup ./bot $args >/dev/null 2>&1 &
    sleep 2
    echo -e "\e[1;32mbot is running\e[0m"
  fi

}
run
sleep 3

get_argodomain() {
  if [[ -n $ARGO_AUTH ]]; then
    echo "$ARGO_DOMAIN"
  else
    grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' boot.log | sed 's@https://@@'
  fi
}
argodomain=$(get_argodomain)
echo -e "\e[1;32mArgoDomain:\e[1;35m${argodomain}\e[0m"
sleep 1
# get ip
IP=$(curl -s ipv4.ip.sb)
sleep 1
# get ipinfo
ISP=$(curl -s https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g') 
sleep 1
VMESS="{ \"v\": \"2\", \"ps\": \"${ISP}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess?ed=2048\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"randomized\"}"

cat > list.txt <<EOF
vmess://$(echo "$VMESS" | base64 -w0)

hysteria2://${UUID}@${IP}:${SERVER_PORT}/?sni=www.bing.com&alpn=h3&insecure=1#${ISP}

tuic://${UUID}:@${IP}:${TUIC_PORT}?sni=www.bing.com&alpn=h3&congestion_control=bbr#${ISP}

vless://${UUID}@${IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=${public_key}&type=tcp&headerType=none#${ISP}
EOF
base64 -w0 list.txt > sub.txt
cat sub.txt
echo -e "\n\e[1;32msub.txt saved successfully\e[0m"
echo -e "\n\e[1;32mRunning dode!\e[0m"
echo ""
sleep 10 
clear
rm -rf web bot npm boot.log config.json sb.log list.txt core

#tail -f /dev/null