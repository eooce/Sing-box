#!/bin/bash
export UUID=${UUID:-'fc44fe6a-f083-4591-9c03-f8d61dc3907f'}
export NEZHA_SERVER=${NEZHA_SERVER:-'nz.f4i.cn'} 
export NEZHA_PORT=${NEZHA_PORT:-'5555'}     
export NEZHA_KEY=${NEZHA_KEY:-''} 
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}   
export ARGO_AUTH=${ARGO_AUTH:-''}    
export CFIP=${CFIP:-'www.visa.com.tw'} 
export CFPORT=${CFPORT:-'443'}          
export VLESS_PORT=${VLESS_PORT:-'10000'}    
export ARGO_PORT=${ARGO_PORT:-'20000'}
export LC_ALL=C
USERNAME=$(whoami)
HOSTNAME=$(hostname)
[[ "$HOSTNAME" == "s1.ct8.pl" ]] && WORKDIR="domains/${USERNAME}.ct8.pl/logs" || WORKDIR="domains/${USERNAME}.serv00.net/logs" && rm -rf $WORKDIR
[ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")

argo_configure() {
  if [[ -z $ARGO_AUTH || -z $ARGO_DOMAIN ]]; then
    echo -e "\e[1;32mARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels\e[0m"
    return
  fi

  if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    echo $ARGO_AUTH > ${WORKDIR}/tunnel.json
    cat > ${WORKDIR}/tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$ARGO_AUTH")
credentials-file: ${WORKDIR}/tunnel.json
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

ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
    FILE_INFO=("https://github.com/eooce/test/releases/download/arm64/bot13 arg" "https://github.com/eooce/test/releases/download/ARM/web http" "https://github.com/eooce/test/releases/download/ARM/swith php")
elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
    FILE_INFO=("https://github.com/eooce/test/releases/download/freebsd/bot arg" "https://github.com/eooce/test/releases/download/freebsd/xary http" "https://github.com/eooce/test/releases/download/freebsd/swith php")
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

generate_config() {
  output=$(./http x25519)
  private_key=$(echo "$output" | grep "Private key" | cut -d ' ' -f 3)
  public_key=$(echo "$output" | grep "Public key" | cut -d ' ' -f 3)
  
  cat > config.json << EOF
{
    "log":{
        "access":"/dev/null",
        "error":"/dev/null",
        "loglevel":"none"
    },
    "inbounds":[
      {
        "tag":"vless-reality",
        "protocol":"vless",
        "port":${VLESS_PORT},
            "settings":{
              "clients":[
                {
                  "id":"${UUID}",
                  "flow":"xtls-rprx-vision"
                }
            ],
            "decryption":"none"
            },
            "streamSettings":{
                "network":"tcp",
                "security":"reality",
                "realitySettings":{
                    "show":true,
                    "dest":"www.ups.com:443",
                    "xver":0,
                    "serverNames":[
                        "www.ups.com"
                    ],
                    "privateKey":"${private_key}",
                    "publicKey":"${public_key}",
                    "maxTimeDiff":0,
                    "shortIds":[
                        ""
                    ]
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls"
                ]
            }
        },
        {
          "tag":"vmess-splithttp",
          "port": ${ARGO_PORT},
          "protocol": "vmess",
          "settings": {
            "clients": [
              {
                "id": "${UUID}",
                "alterId": 0,
                "security": "auto"
              }
            ]
          },
          "streamSettings": {
            "network": "splithttp",
            "security": "none",
            "httpSettings": {
              "host": "",
              "path": ""
            }
          }
        }
    ],
    "dns":{
        "servers":[
            "https+local://8.8.8.8/dns-query"
        ]
    },
    "outbounds":[
        {
            "protocol":"freedom"
        },
        {
            "tag":"WARP",
            "protocol":"wireguard",
            "settings":{
                "secretKey":"YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=",
                "address":[
                    "172.16.0.2/32",
                    "2606:4700:110:8a36:df92:102a:9602:fa18/128"
                ],
                "peers":[
                    {
                        "publicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                        "allowedIPs":[
                            "0.0.0.0/0",
                            "::/0"
                        ],
                        "endpoint":"162.159.193.10:2408"
                    }
                ],
                "reserved":[78, 135, 76],
                "mtu":1280
            }
        }
    ],
    "routing":{
        "domainStrategy":"AsIs",
        "rules":[
            {
                "type":"field",
                "domain":[
                    "domain:openai.com",
                    "domain:chatgpt.com",
                    "domain:auth.openai.com",
                    "domain:chat.openai.com"
                ],
                "outboundTag":"WARP"
            }
        ]
    }
}
EOF
}
generate_config
wait

run() {
  if [ -e php ]; then
    tlsPorts=("443" "8443" "2096" "2087" "2083" "2053")
    if [[ "${tlsPorts[*]}" =~ "${NEZHA_PORT}" ]]; then
      NEZHA_TLS="--tls"
    else
      NEZHA_TLS=""
    fi
    if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
        export TMPDIR=$(pwd)
        nohup ./php -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &
		    sleep 2
        pgrep -x "php" > /dev/null && echo -e "\e[1;32mphp is running\e[0m" || { echo -e "\e[1;35mphp is not running, restarting...\e[0m"; pkill -x "php" && nohup ./php -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 & sleep 2; echo -e "\e[1;32mphp restarted\e[0m"; }
    else
        echo -e "\e[1;35mNEZHA variable is empty,skiping runing\e[0m"
    fi
  fi

  if [ -e http ]; then
    nohup ./http -c config.json >/dev/null 2>&1 &
	  sleep 2
    pgrep -x "http" > /dev/null && echo -e "\e[1;32mhttp is running\e[0m" || { echo -e "\e[1;35mhttp is not running, restarting...\e[0m"; pkill -x "http" && nohup ./http -c config.json >/dev/null 2>&1 & sleep 2; echo -e "\e[1;32mhttp restarted\e[0m"; }
  fi

  if [ -e arg ]; then
    if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
    elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
      args="tunnel --edge-ip-version auto --config ${WORKDIR}/tunnel.yml run"
    else
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${WORKDIR}/boot.log --loglevel info --url http://localhost:$ARGO_PORT"
    fi
    nohup ./arg $args >/dev/null 2>&1 &
    sleep 2
    pgrep -x "arg" > /dev/null && echo -e "\e[1;32marg is running\e[0m" || { echo -e "\e[1;35marg is not running, restarting...\e[0m"; pkill -x "arg" && nohup ./arg $args >/dev/null 2>&1 & sleep 2; echo -e "\e[1;32marg restarted\e[0m"; }
  fi
} 
run
sleep 4

get_ip() {
ip=$(curl -s --max-time 2 ipv4.ip.sb)
if [ -z "$ip" ]; then
    if [[ "$HOSTNAME" =~ s[0-9]\.serv00\.com ]]; then
        ip=${HOSTNAME/s/web}
    else
        ip="$HOSTNAME"
    fi
fi
echo $ip
}

get_argodomain() {
  if [[ -n $ARGO_AUTH ]]; then
    echo "$ARGO_DOMAIN"
  else
    grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' "${WORKDIR}/boot.log" | sed 's@https://@@'
  fi
}

generate_links() {
  argodomain=$(get_argodomain)
  echo -e "\e[1;32mArgoDomain:\e[1;35m${argodomain}\e[0m\n"
  sleep 2
  SERVER_IP=$(get_ip)
  isp=$(curl -s https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g')
  sleep 2
  VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${SERVER_IP}\", \"port\": \"${ARGO_PORT}\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"splithttp\", \"type\": \"none\", \"host\": \"\", \"path\": \"\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\" }"
  VMESS2="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"splithttp\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\" }"
  cat > ${WORKDIR}/list.txt <<EOF
vless://${UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.ups.com&fp=chrome&pbk=${public_key}&type=tcp&headerType=none#${isp}

vmess://$(echo "$VMESS" | base64 -w0)

vmess://$(echo "$VMESS2" | base64 -w0)
EOF

  cat ${WORKDIR}/list.txt
  echo -e "\n\e[1;32m${WORKDIR}/list.txt saved successfully\e[0m"
  sleep 2  
  rm -rf php http arg config.json fake_useragent_0.2.0.json ${WORKDIR}/boot.log ${WORKDIR}/tunnel.json ${WORKDIR}/tunnel.yml 
}
generate_links
echo -e "\n\e[1;96mRunning done!\e[0m"
echo -e "\e[1;96mThank you for using this script,enjoy!\e[0m"
echo -e "\e[1;35missues反馈：https://github.com/eooce/Sing-box/issues\e[0m\n"
exit 0
