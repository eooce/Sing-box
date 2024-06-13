#!/bin/bash
export UUID=${UUID:-'92880617-c2f5-4c16-b1cb-68ccde9a1c1b'}
export NEZHA_SERVER=${NEZHA_SERVER:-'nz.abcd.com'}
export NEZHA_PORT=${NEZHA_PORT:-'5555'}   # 哪吒端口为443时开启tls
export NEZHA_KEY=${NEZHA_KEY:-''}        # 哪吒三个变量不全不运行
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}
export ARGO_AUTH=${ARGO_AUTH:-''}
export NAME=${NAME:-'Vl+VM+TR'}
export CFIP=${CFIP:-'government.se'}
export FILE_PATH=${FILE_PATH:-'./temp'}
export ARGO_PORT=${ARGO_PORT:-'8001'}  # argo隧道端口，若使用固定隧道token请改回8080或CF后台改为与这里对应

if [ ! -d "${FILE_PATH}" ]; then
    mkdir ${FILE_PATH}
fi

#清理历史运行文件
cleanup_oldfiles() {
  rm -rf ${FILE_PATH}/boot.log ${FILE_PATH}/sub.txt ${FILE_PATH}/config.json ${FILE_PATH}/tunnel.json ${FILE_PATH}/tunnel.yaml
}
cleanup_oldfiles
sleep 2

#生成xr-ay配置文件
generate_config() {
  cat > ${FILE_PATH}/config.json << EOF
{
    "log":{
        "access":"/dev/null",
        "error":"/dev/null",
        "loglevel":"none"
    },
    "inbounds":[
        {
            "port":$ARGO_PORT,
            "protocol":"vless",
            "settings":{
                "clients":[
                    {
                        "id":"${UUID}",
                        "flow":"xtls-rprx-vision"
                    }
                ],
                "decryption":"none",
                "fallbacks":[
                    {
                        "dest":3001
                    },
                    {
                        "path":"/vless",
                        "dest":3002
                    },
                    {
                        "path":"/vmess",
                        "dest":3003
                    },
                    {
                        "path":"/trojan",
                        "dest":3004
                    }
                ]
            },
            "streamSettings":{
                "network":"tcp"
            }
        },
        {
            "port":3001,
            "listen":"127.0.0.1",
            "protocol":"vless",
            "settings":{
                "clients":[
                    {
                        "id":"${UUID}"
                    }
                ],
                "decryption":"none"
            },
            "streamSettings":{
                "network":"ws",
                "security":"none"
            }
        },
        {
            "port":3002,
            "listen":"127.0.0.1",
            "protocol":"vless",
            "settings":{
                "clients":[
                    {
                        "id":"${UUID}",
                        "level":0
                    }
                ],
                "decryption":"none"
            },
            "streamSettings":{
                "network":"ws",
                "security":"none",
                "wsSettings":{
                    "path":"/vless"
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly":false
            }
        },
        {
            "port":3003,
            "listen":"127.0.0.1",
            "protocol":"vmess",
            "settings":{
                "clients":[
                    {
                        "id":"${UUID}",
                        "alterId":0
                    }
                ]
            },
            "streamSettings":{
                "network":"ws",
                "wsSettings":{
                    "path":"/vmess"
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly":false
            }
        },
        {
            "port":3004,
            "listen":"127.0.0.1",
            "protocol":"trojan",
            "settings":{
                "clients":[
                    {
                        "password":"${UUID}"
                    }
                ]
            },
            "streamSettings":{
                "network":"ws",
                "security":"none",
                "wsSettings":{
                    "path":"/trojan"
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly":false
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
                    "domain:ai.com"
                ],
                "outboundTag":"WARP"
            }
        ]
    }
}
EOF
}
generate_config
sleep 3

# 下载依赖文件
set_download_url() {
  local program_name="$1"
  local default_url="$2"
  local x64_url="$3"

  if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "amd64" ] || [ "$(uname -m)" = "x64" ]; then
    download_url="$x64_url"
  else
    download_url="$default_url"
  fi
}

download_program() {
  local program_name="$1"
  local default_url="$2"
  local x64_url="$3"

  set_download_url "$program_name" "$default_url" "$x64_url"

  if [ ! -f "$program_name" ]; then
    if [ -n "$download_url" ]; then
      curl -sSL -C - "$download_url" -o "$program_name" > /dev/null 2>&1
      if [ $? -eq 33 ]; then
        echo "Resuming download $program_name..."
        curl -sSL "$download_url" -o "$program_name" > /dev/null 2>&1
      fi
      if [ $? -eq 0 ]; then
        echo "$program_name download finished"
      else
        echo "Failed to download $program_name"
      fi
    else
      echo "Skipping download $program_name"
    fi
  else
    echo "$program_name already exists, skipping download"
  fi
}

download_program "${FILE_PATH}/swith" "https://github.com/eoovve/test/releases/download/ARM/swith" "https://github.com/eoovve/test/releases/download/bulid/swith"
sleep 5

download_program "${FILE_PATH}/web" "https://github.com/eoovve/test/releases/download/ARM/web" "https://github.com/eoovve/test/releases/download/123/web"
sleep 5

download_program "${FILE_PATH}/server" "https://github.com/eoovve/test/releases/download/arm64/server" "https://github.com/eoovve/test/releases/download/amd64/server"
sleep 5

argo_configure() {
  if [[ -z $ARGO_AUTH || -z $ARGO_DOMAIN ]]; then
    echo "ARGO_DOMAIN or ARGO_AUTH variable isn't set, Use Quick Tunnels"
    return
  fi

  if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    echo $ARGO_AUTH > ${FILE_PATH}/tunnel.json
    cat > ${FILE_PATH}/tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$ARGO_AUTH")
credentials-file: ${FILE_PATH}/tunnel.json
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$ARGO_PORT
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
  else
    echo "ARGO_AUTH mismatch TunnelSecret,use Token connect to Tunnel"
  fi
}
argo_configure
sleep 3

run() {
  if [ -e ${FILE_PATH}/swith ]; then
    chmod 775 ${FILE_PATH}/swith 
    if [ "$NEZHA_PORT" = "443" ]; then
      NEZHA_TLS="--tls"
    else
      NEZHA_TLS=""
    fi
    if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
        nohup ${FILE_PATH}/swith -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &
    else
        echo "NEZHA variable isn't set,skiping runing"
    fi
  fi

  if [ -e ${FILE_PATH}/web ]; then
    chmod 775 ${FILE_PATH}/web
    nohup ${FILE_PATH}/web -c ${FILE_PATH}/config.json >/dev/null 2>&1 &
  fi

  if [ -e ${FILE_PATH}/server ]; then
    chmod 775 ${FILE_PATH}/server
    if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
    args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
    elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    args="tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run"
    else
    args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:$ARGO_PORT"
    fi
    nohup ${FILE_PATH}/server $args >/dev/null 2>&1 &
  fi
} 
run
sleep 8

function get_argodomain() {
  if [[ -n $ARGO_AUTH ]]; then
    echo "$ARGO_DOMAIN"
  else
    cat ${FILE_PATH}/boot.log | grep trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}'
  fi
}

generate_links() {
  argodomain=$(get_argodomain)
  sleep 2

  isp=$(curl -s https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g')
  sleep 3

  VMESS="{ \"v\": \"2\", \"ps\": \"${NAME}-${isp}\", \"add\": \"${CFIP}\", \"port\": \"443\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess?ed=2048\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\" }"

  cat > ${FILE_PATH}/list.txt <<EOF
vless://${UUID}@${CFIP}:443?encryption=none&security=tls&sni=${argodomain}&type=ws&host=${argodomain}&path=%2Fvless?ed=2048#${NAME}-${isp}

vmess://$(echo "$VMESS" | base64 -w0)

trojan://${UUID}@${CFIP}:443?security=tls&sni=${argodomain}&type=ws&host=${argodomain}&path=%2Ftrojan?ed=2048#${NAME}-${isp}
EOF

  base64 -w0 ${FILE_PATH}/list.txt > ${FILE_PATH}/sub.txt
  cat ${FILE_PATH}/sub.txt
  echo -e "\nFile saved successfully"
  sleep 8  
  rm -rf ${FILE_PATH}/list.txt ${FILE_PATH}/boot.log ${FILE_PATH}/config.json ${FILE_PATH}/tunnel.json ${FILE_PATH}/tunnel.yml
}
generate_links
sleep 15
clear

echo "Server is running"
echo -e "Thank you for using this script,enjoy!"
