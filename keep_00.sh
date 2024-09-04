#!/bin/bash

export TERM=xterm
export DEBIAN_FRONTEND=noninteractive
export cfip=${cfip:-'www.visa.com.tw'}  # 优选域名或优选ip
export cfport=${cfport:-'443'}     # 优选域名或优选ip对应端口
SCRIPT_PATH="/root/keep_00.sh"  # 脚本路径

# serv00或ct8服务器及端口配置, 哪吒，argo固定隧道可不填写  密码中包含$号请提前修改，否则无法识别
declare -A servers   # 账号:密码:tcp端口:udp1端口:udp2端口:哪吒客户端域名:哪吒agent端口:哪吒密钥:argo域名:Argo隧道token 
servers=(             
    ["s1.serv00.com"]='abcd:JPAyxIfODwjxKOV7wRoT:7167:7168:7169:nz.abcd.cn:5555:dLMCQtBFwzpHzJq1RK:argo.zzx.free.hr:eyJhIjoGI5NzI0MDgwZTU1ZTcwMzcwZmI3NDI4NzkyMmYzMWIiLCJ0IjoiNGNhNDUwZGItOTBiZS00MTMzLTljOWItYWY0YjE0MDNhNjQ5IiwicyI6InI5bkFPY0laRG5kMEdwV0NoS3ZsM1BQaDVOVStMNjRKRHVleGE1K2NsOW89In0='  
    ["s2.serv00.com"]='bcda:jnJddX2RhfAVTisj97bs:6166:6167:6168:nz.abcd.cn:5555:1zOW9AVfhyFmKDBL1d'
    ["s3.serv00.com"]='abcd:HirdnxS0Zy0vunayded:7777:8888:9999'
    ["s4.serv00.com"]='abcd:HirdnxS0Zy0vunayded:7777:8888:9999'
    ["s5.serv00.com"]='abcd:HirdnxS0Zy0vunayded:7777:8888:9999'
    ["s6.serv00.com"]='abcd:HirdnxS0Zy0vunayded:7777:8888:9999'
    ["s7.serv00.com"]='abcd:HirdnxS0Zy0vunayded:7777:8888:9999'
    # 添加更多服务器
)

# 最大尝试检测次数
MAX_ATTEMPTS=5

# 根据对应系统安装依赖
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
        echo -e "\e[1;33m不支持的系统架构！\e[0m"
        exit 1
    fi
    $package_manager sshpass curl netcat-openbsd cron > /dev/null
}
install_packages
clear

# 添加定时任务的函数
add_cron_job() {
    if ! crontab -l | grep -q "$SCRIPT_PATH" > /dev/null 2>&1; then
        (crontab -l; echo "*/2 * * * * /bin/bash $SCRIPT_PATH >> /root/00_keep.log 2>&1") | crontab -
        echo -e "\e[1;32m已添加定时任务，每两分钟执行一次\e[0m"
    else
        echo -e "\e[1;35m定时任务已存在，跳过添加计划任务\e[0m"
    fi
}
add_cron_job

# 检测 TCP 端口是否通畅
check_tcp_port() {
    local host=$1
    local port=$2
    nc -zv $host $port &> /dev/null
    return $?
}

# 连接ssh并执行远程命令
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

    sshpass -p "$ssh_pass" ssh -o StrictHostKeyChecking=no "$ssh_user@$host" \
        "VMESS_PORT=$tcp_port HY2_PORT=$udp1_port TUIC_PORT=$udp2_port NEZHA_SERVER=$nezha_server NEZHA_PORT=$nezha_port NEZHA_KEY=$nezha_key ARGO_DOMAIN=$argo_domain ARGO_AUTH=$argo_auth CFIP=$cfip CFPORT=$cfport bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sb_00.sh)"
}

# 循环遍历服务器检测
for host in "${!servers[@]}"; do
    IFS=':' read -r ssh_user ssh_pass tcp_port udp1_port udp2_port nezha_server nezha_port nezha_key argo_domain argo_auth <<< "${servers[$host]}"

    attempt=0 
    time=$(TZ="Asia/Hong_Kong" date +"%Y-%m-%d %H:%M")

    while [ $attempt -lt $MAX_ATTEMPTS ]; do
        
        if check_tcp_port "$host" "$tcp_port"; then
            echo -e "\e[1;32m程序正在运行，TCP端口 $tcp_port 通畅  \e[1;35m 服务器: $host   账户：$ssh_user  [$time]\e[0m"
            break
        else
            echo -e "\e[1;33mTCP 端口 $tcp_port 不通畅，进程可能不存在，休眠30s后重新检测  \e[1;35m 服务器: $host   账户：$ssh_user  [$time]\e[0m"
            sleep 30
            attempt=$((attempt+1))
        fi
    done

    # 如果达到最大尝试次数，连接服务器并执行远程命令
    if [ $attempt -ge $MAX_ATTEMPTS ]; then
        echo -e "\e[1;33m多次检测失败，尝试通过SSH连接并远程执行命令  \e[1;35m 服务器: $host   账户：$ssh_user  [$time]\e[0m"
        if sshpass -p "$ssh_pass" ssh -o StrictHostKeyChecking=no "$ssh_user@$host" -q exit; then
            echo -e "\e[1;32mSSH远程连接成功  \e[1;35m 服务器: $host   账户：$ssh_user  [$time]\e[0m"
            output=$(run_remote_command "$host" "$ssh_user" "$ssh_pass" "$tcp_port" "$udp1_port" "$udp2_port" "$nezha_server" "$nezha_port" "$nezha_key" "$argo_domain" "$argo_auth")
            echo -e "\e[1;35m远程命令执行结果：\e[0m\n"
            echo "$output"
        else
            echo -e "\e[1;33m连接失败，请检查你的账户和密码  \e[1;35m 服务器: $host   账户：$ssh_user  [$time]\e[0m"
        fi
    fi
done
