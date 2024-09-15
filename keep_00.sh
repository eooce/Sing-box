#!/bin/bash
# 如果要检测哪吒是否在线，请将哪吒面板上agent名字以：S1,S2,S3,S4....形式命名 
SCRIPT_PATH="/root/keep_00.sh"                 # 脚本路径
NEZHA_URL="http://nezha.abcgefg.com"           # 哪吒面板地址 
API_TOKEN="RtzwTHlXjG2RXHaVW5JUBMcO2DR9OI123"   # 哪吒面板api token

export CFIP=${CFIP:-'www.visa.com.tw'}         # 优选域名或优选ip
export CFPORT=${CFIPPORT:-'443'}               # 优选域名或优选ip对应端口
 
 # serv00或ct8服务器及端口配置, 哪吒，argo固定隧道可不填写
declare -A servers=(  # 账号:密码:tcp端口:udp1端口:udp2端口:哪吒客户端域名:哪吒agent端口:哪吒密钥:argo域名:Argo隧道json或token 
    ["s0.serv00.com"]='abcd:abd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s0.2go.ync,mn:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s1.serv00.com"]='abcd:dbc12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s1.2go.ync,mn:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s2.serv00.com"]='abcd:avd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s2.2go.ync,mn:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s3.serv00.com"]='abcd:dss12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s3.2go.ync,mn:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PfRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s4.serv00.com"]='abcd:sds12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s4.2go.ync,mn:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s5.serv00.com"]='abcd:dsd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s5.2go.ync,mn:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s6.serv00.com"]='abcd:dsd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s6.2go.ync,mn:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s7.serv00.com"]='abcd:dsd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s7.2go.ync,mn:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s8.serv00.com"]='abcd:dss12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s8.2go.ync,mn:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    # 添加更多服务器......
)

# 定义颜色
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }

export TERM=xterm
export DEBIAN_FRONTEND=noninteractive
install_packages() {
    if [ -f /etc/debian_version ]; then
        package_manager="apt-get install -y"
    elif [ -f /etc/redhat-release ]; then
        package_manager="yum install -y"
    elif [ -f /etc/fedora-release ]; then
        package_manager="dnf install -y"
    elif [ -f /etc/alpine-release ]; then
        package_manager="apk add"
    else
        red "不支持的系统架构！"
        exit 1
    fi
    $package_manager sshpass curl netcat-openbsd jq cron >/dev/null 2>&1 &
}
install_packages
clear

# 添加定时任务
add_cron_job() {
    if [ -f /etc/alpine-release ]; then
        if ! command -v crond >/dev/null 2>&1; then
            apk add --no-cache cronie bash >/dev/null 2>&1 &
            rc-update add crond && rc-service crond start
        fi
    fi
    # 检查定时任务是否已经存在
    if ! crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH"; then
        (crontab -l 2>/dev/null; echo "*/2 * * * * /bin/bash $SCRIPT_PATH >> /root/keep_00.log 2>&1") | crontab -
        green "已添加计划任务，每两分钟执行一次"
    else
        purple "计划任务已存在，跳过添加计划任务"
    fi
}
add_cron_job

# 检查 TCP 端口是否通畅
check_tcp_port() {
    local host=$1
    local port=$2
    nc -z -w 3 "$host" "$port" &> /dev/null
    return $?
}

# 检查 Argo 隧道是否在线
check_argo_tunnel() {
    local domain=$1
    if [ -z "$domain" ]; then
        return 1
    else
        http_code=$(curl -o /dev/null -s -w "%{http_code}\n" "https://$domain")
        if [ "$http_code" -eq 404 ]; then
            return 0
        else
            return 1
        fi
    fi
}

# 检查哪吒 agent 是否在线
check_nezha_agent() {
    NEZHA_API="$NEZHA_URL/api/v1/server/list"
    response=$(curl -s -H "Authorization: $API_TOKEN" "$NEZHA_API")
    
    if [ $? -ne 0 ]; then
        red "请求失败，请检查您的哪吒URL或api_token"
        return 1
    fi
    
    local current_time=$(date +%s)
    local target_agent="S${1}"
    local agent_found=false
    local agent_online=false

    while read -r server; do
        server_name=$(echo "$server" | jq -r '.name')
        last_active=$(echo "$server" | jq -r '.last_active')

        if [[ $server_name == $target_agent ]]; then
            agent_found=true
            if [ $(( current_time - last_active )) -le 30 ]; then
                agent_online=true
                break
            fi
        fi
    done < <(echo "$response" | jq -c '.result[]')

    if ! $agent_found; then
        red "未找到 agent: $target_agent"
        return 1
    elif $agent_online; then
        return 0
    else
        return 1
    fi
}

# 执行远程命令
run_remote_command() {
    local host=$1
    local ssh_user=$2
    local ssh_pass=$3
    local tcp_port=$4
    local udp1_port=$5
    local udp2_port=$6
    local nezha_server=$7
    local nezha_port=$8
    local nezha_key=$9
    local argo_domain=${10}
    local argo_auth=${11}

    remote_command="VMESS_PORT=$tcp_port HY2_PORT=$udp1_port TUIC_PORT=$udp2_port NEZHA_SERVER=$nezha_server NEZHA_PORT=$nezha_port NEZHA_KEY=$nezha_key ARGO_DOMAIN=$argo_domain ARGO_AUTH='$argo_auth' CFIP=$CFIP CFPORT=$CFPORT bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sb_00.sh)"
    
    sshpass -p "$ssh_pass" ssh -o StrictHostKeyChecking=no "$ssh_user@$host" "$remote_command"
}

# 循环遍历服务器列表检测
for host in "${!servers[@]}"; do
    IFS=':' read -r ssh_user ssh_pass tcp_port udp1_port udp2_port nezha_server nezha_port nezha_key argo_domain argo_auth <<< "${servers[$host]}"

    nezha_agent_name=${host%%.*}
    nezha_index=${nezha_agent_name:1}

    tcp_attempt=0
    argo_attempt=0
    nezha_attempt=0
    max_attempts=3
    time=$(TZ="Asia/Hong_Kong" date +"%Y-%m-%d %H:%M")

    # 检查 Nezha agent
    while [ $nezha_attempt -lt $max_attempts ]; do
        if check_nezha_agent "$nezha_index"; then
            green "$time  Nezha agent在线 服务器: $host  账户: $ssh_user"
            nezha_attempt=0
            break
        else
            red "$time  Nezha agent离线 服务器: $host  账户: $ssh_user"
            sleep 10
            nezha_attempt=$((nezha_attempt+1))
        fi
    done

    # 检查 TCP 端口
    while [ $tcp_attempt -lt $max_attempts ]; do
        if check_tcp_port "$host" "$tcp_port"; then
            green "$time  TCP端口${tcp_port}通畅 服务器: $host  账户: $ssh_user"
            tcp_attempt=0
            break
        else
            red "$time  TCP端口${tcp_port}不通 服务器: $host  账户: $ssh_user"
            sleep 10
            tcp_attempt=$((tcp_attempt+1))
        fi
    done

    # 检查 Argo 隧道
    while [ $argo_attempt -lt $max_attempts ]; do
        if check_argo_tunnel "$argo_domain"; then
            green "$time  Argo 隧道在线 Argo域名: $argo_domain   账户: $ssh_user\n"
            argo_attempt=0
            break
        else
            red "$time  Argo 隧道离线 Argo域名: $argo_domain   账户: $ssh_user"
            sleep 10
            argo_attempt=$((argo_attempt+1))
        fi
    done
   
    # 如果3次检测失败，则执行 SSH 连接并执行远程命令
    if [ $tcp_attempt -ge 3 ] || [ $argo_attempt -ge 3 ] || [ $nezha_attempt -ge 3 ]; then
        yellow "$time 多次检测失败，尝试通过SSH连接并远程执行命令  服务器: $host  账户: $ssh_user"
        if sshpass -p "$ssh_pass" ssh -o StrictHostKeyChecking=no "$ssh_user@$host" -q exit; then
            green "$time  SSH远程连接成功 服务器: $host  账户 : $ssh_user"
            output=$(run_remote_command "$host" "$ssh_user" "$ssh_pass" "$tcp_port" "$udp1_port" "$udp2_port" "$nezha_server" "$nezha_port" "$nezha_key" "$argo_domain" "$argo_auth")
            yellow "远程命令执行结果：\n"
            echo "$output"
        else
            red "$time  连接失败，请检查你的账户密码 服务器: $host  账户: $ssh_user"
        fi
    fi
done
