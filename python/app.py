import os
import json
import subprocess
import base64
import time
import requests
import random
import string
import OpenSSL
import re
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from rich.console import Console

console = Console()

# 配置环境变量
ENV = {
    'UUID': os.getenv('UUID', 'cfa8c36c-9652-484a-89e1-34dcc98faac3'),  # 默认UUID
    'NEZHA_SERVER': os.getenv('NEZHA_SERVER', 'nz.abc.cn'),             # 哪吒面板地址
    'NEZHA_PORT': os.getenv('NEZHA_PORT', '5555'),                      # 哪吒agent端口，为{443,8443,2096,2087,2083,2053}时自动开启tls
    'NEZHA_KEY': os.getenv('NEZHA_KEY', ''),                            # 哪吒密钥
    'ARGO_DOMAIN': os.getenv('ARGO_DOMAIN', ''),                        # 固定隧道Argo域名，留空即使用临时隧道
    'ARGO_AUTH': os.getenv('ARGO_AUTH', ''),                            # 固定argo隧道密钥，token或json，留空即使用临时隧道
    'CFIP': os.getenv('CFIP', 'www.visa.com.tw'),                       # 优选域名或优选ip
    'CFPORT': os.getenv('CFPORT', '8443'),                              # 优选域名或优选ip对应端口
    'NAME': os.getenv('NAME', 'AAA'),                                   # 节点名称
    'FILE_PATH': os.getenv('FILE_PATH', './.cache'),                    # 节点文件路径
    'ARGO_PORT': os.getenv('ARGO_PORT', '8001'),                        # ARGO端口,使用固定隧道token时,cloudflared 后台设置和需这里一致
    'TUIC_PORT': os.getenv('TUIC_PORT', '40000'),                       # TUIC端口,支持多端口的容器或玩具可以填写，否则不动
    'HY2_PORT': os.getenv('HY2_PORT', '50000'),                         # HY2端口，支持多端口的容器或玩具可以填写，否则不动
    'REALITY_PORT': os.getenv('REALITY_PORT', '60000'),                 # REALITY端口，支持多端口的容器或玩具可以填写，否则不动
    'PORT': os.getenv('PORT', '7860'),                                  # HTTP订阅端口，支持多端口可以订阅的可以填写开启订阅，否则不动
    'TELEGRAM_BOT_TOKEN': os.getenv('TELEGRAM_BOT_TOKEN', ''),          # Telegram Bot Token
    'TELEGRAM_CHAT_ID': os.getenv('TELEGRAM_CHAT_ID', ''),              # Telegram Chat ID
}

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'Hello World')
            
        elif self.path == '/sub':
            try:
                with open(f"{ENV['FILE_PATH']}/sub.txt", 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(content)
            except:
                self.send_response(404)
                self.end_headers()             

def send_telegram():
    """发送 Telegram 消息"""
    TELEGRAM_BOT_TOKEN = ENV['TELEGRAM_BOT_TOKEN']
    TELEGRAM_CHAT_ID = ENV['TELEGRAM_CHAT_ID']
    FILE_PATH = Path(ENV['FILE_PATH'])
    NAME = ENV.get('NAME', 'Node')  # 获取NAME，如果不存在则默认为'Node'

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        console.print("\n[bold magenta]Telegram bot token or chat ID is empty. Skip pushing nodes to TG[/bold magenta]")
        return

    try:
        with open(FILE_PATH / 'sub.txt', 'r', encoding='utf-8') as file:
            message = file.read().strip()

        # 处理特殊字符
        escaped_name = NAME
        for char in '_*[]()~`>#+=|{}.!-':
            escaped_name = escaped_name.replace(char, f'\\{char}')

        # 构建Markdown格式的消息
        formatted_message = f"**{escaped_name}节点推送通知**\n```\n{message}\n```"

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        params = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": formatted_message,
            "parse_mode": "MarkdownV2"
        }
        
        response = requests.post(url, params=params)

        if response.status_code == 200:
            console.print("\n[bold green]Telegram message sent successfully[/bold green]")
        else:
            console.print(f"\n[bold red]Failed to send Telegram message. Status code: {response.status_code}[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Failed to send Telegram message: {e}[/bold red]")

def generate_cert():
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    
    cert = OpenSSL.crypto.X509()
    cert.get_subject().CN = "bing.com"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    with open("cert.pem", "wb") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
    with open("private.key", "wb") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

def download_files():
    arch = os.uname().machine
    if arch in ['arm', 'arm64', 'aarch64']:
        files = {
            'web': 'https://arm64.2go.us.kg/sb',
            'bot': 'https://arm64.2go.us.kg/bot',
            'npm': 'https://arm64.2go.us.kg/agent'
        }
    else:
        files = {
            'web': 'https://amd64.2go.us.kg/sb',
            'bot': 'https://amd64.2go.us.kg/2go',
            'npm': 'https://amd64.2go.us.kg/agent'
        }
    
    file_map = {}
    for name, url in files.items():
        random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            with open(random_name, 'wb') as f:
                f.write(response.content)
            os.chmod(random_name, 0o755)
            file_map[name] = random_name
            console.print(f"[bold green]Downloaded {random_name} successfully[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to download {random_name}: {str(e)}[/bold red]")
    
    return file_map

def generate_reality_keypair(web_file):
    cmd = f'./{web_file} generate reality-keypair'
    output = subprocess.check_output(cmd, shell=True).decode()
    private_key = ''
    public_key = ''
    for line in output.splitlines():
        if 'PrivateKey:' in line:
            private_key = line.split()[1]
        elif 'PublicKey:' in line:
            public_key = line.split()[1]
    return private_key, public_key

def generate_config(file_map):
    private_key, public_key = generate_reality_keypair(file_map['web'])
    
    config = {
        "log": {
            "disabled": False,
            "level": "info",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "tag": "google",
                    "address": "tls://8.8.8.8"
                }
            ]
        },
        "inbounds": [
            {
                "tag": "vless-ws-in",
                "type": "vless",
                "listen": "::",
                "listen_port": int(ENV['ARGO_PORT']),
                "users": [
                    {
                        "uuid": ENV['UUID']
                    }
                ],
                "transport": {
                    "type": "ws",
                    "path": "/vless",
                    "early_data_header_name": "Sec-WebSocket-Protocol"
                }
            },
            {
                "tag": "tuic-in",
                "type": "tuic",
                "listen": "::",
                "listen_port": int(ENV['TUIC_PORT']),
                "users": [
                    {
                        "uuid": ENV['UUID'],
                        "password": "admin"
                    }
                ],
                "congestion_control": "bbr",
                "tls": {
                    "enabled": True,
                    "alpn": ["h3"],
                    "certificate_path": "cert.pem",
                    "key_path": "private.key"
                }
            },
            {
                "tag": "hysteria2-in",
                "type": "hysteria2",
                "listen": "::",
                "listen_port": int(ENV['HY2_PORT']),
                "users": [
                    {
                        "password": ENV['UUID']
                    }
                ],
                "masquerade": "https://bing.com",
                "tls": {
                    "enabled": True,
                    "alpn": ["h3"],
                    "certificate_path": "cert.pem",
                    "key_path": "private.key"
                }
            },
            {
                "tag": "vless-reality-vesion",
                "type": "vless",
                "listen": "::",
                "listen_port": int(ENV['REALITY_PORT']),
                "users": [
                    {
                        "uuid": ENV['UUID'],
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "tls": {
                    "enabled": True,
                    "server_name": "who.cx",
                    "reality": {
                        "enabled": True,
                        "handshake": {
                            "server": "who.cx",
                            "server_port": 443
                        },
                        "private_key": private_key,
                        "short_id": [""]
                    }
                }
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "direct", "tag": "direct-ipv4-prefer-out", "domain_strategy": "prefer_ipv4"},
            {"type": "direct", "tag": "direct-ipv4-only-out", "domain_strategy": "ipv4_only"},
            {"type": "direct", "tag": "direct-ipv6-prefer-out", "domain_strategy": "prefer_ipv6"},
            {"type": "direct", "tag": "direct-ipv6-only-out", "domain_strategy": "ipv6_only"},
            {
                "type": "wireguard",
                "tag": "wireguard-out",
                "server": "engage.cloudflareclient.com",
                "server_port": 2408,
                "local_address": [
                    "172.16.0.2/32",
                    "2606:4700:110:812a:4929:7d2a:af62:351c/128"
                ],
                "private_key": "gBthRjevHDGyV0KvYwYE52NIPy29sSrVr6rcQtYNcXA=",
                "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "reserved": [6, 146, 6]
            }
        ],
        "route": {
            "rule_set": [
                {
                    "tag": "geosite-netflix",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
                    "update_interval": "1d"
                },
                {
                    "tag": "geosite-openai",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
                    "update_interval": "1d"
                }
            ],
            "rules": [
              {
                "ip_is_private": True,
                "outbound": "direct"
              },
              {
                "rule_set": ["geosite-openai"],
                "outbound": "wireguard-out"
              },
              {
                "rule_set": ["geosite-netflix"],
                "outbound": "wireguard-out"
              }
            ],
            "final": "direct"
        },
        "experimental": {
            "cache_file": {
                "path": "cache.db",
                "cache_id": "mycacheid",
                "store_fakeip": True
            }
        }
    }
    
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    return public_key

def configure_argo():
    """配置Argo"""
    if not ENV['ARGO_AUTH'] or not ENV['ARGO_DOMAIN']:
        console.print("\n[bold green]ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels[/bold green]")
        return
    
    if 'TunnelSecret' in ENV['ARGO_AUTH']:
        with open('tunnel.json', 'w') as f:
            f.write(ENV['ARGO_AUTH'])
        
        tunnel_id = re.search(r'"TunnelID":"([^"]+)"', ENV['ARGO_AUTH']).group(1)
        
        with open('tunnel.yml', 'w') as f:
            f.write(f"""tunnel: {tunnel_id}
credentials-file: tunnel.json
protocol: http2

ingress:
  - hostname: {ENV['ARGO_DOMAIN']}
    service: http://localhost:{ENV['ARGO_PORT']}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
""")
    else:
        console.print("\n[bold green]ARGO_AUTH mismatch TunnelSecret,use token connect to tunnel[/bold green]")
        
def run_service_with_retry(cmd, service_name, max_retries=3):
    """通用的服务启动函数,包含重试机制"""
    for attempt in range(max_retries):
        process = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)  # 等待服务启动
        
        if process.poll() is None:
            console.print(f"[bold green]{service_name} is running[/bold green]")
            return True
        else:
            if attempt < max_retries - 1:
                console.print(f"[bold yellow]{service_name} failed to start, retrying... ({attempt + 1}/{max_retries})[/bold yellow]")
                process.kill()  # 确保进程被终止
                time.sleep(1)
            else:
                console.print(f"[bold red]{service_name} failed to start after {max_retries} attempts[/bold red]")
    return False

def run_services(file_map):
    # 运行 npm
    if os.path.exists(file_map['npm']):
        if all([ENV['NEZHA_SERVER'], ENV['NEZHA_PORT'], ENV['NEZHA_KEY']]):
            tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
            nezha_tls = '--tls' if ENV['NEZHA_PORT'] in tls_ports else ''
            
            cmd = f'./{file_map["npm"]} -s {ENV["NEZHA_SERVER"]}:{ENV["NEZHA_PORT"]} -p {ENV["NEZHA_KEY"]} {nezha_tls}'
            run_service_with_retry(cmd, file_map['npm'])
        else:
            console.print("\n[bold yellow]NEZHA variable is empty, skipping NEZHA[/bold yellow]")
    time.sleep(1)

    # 运行 web
    if os.path.exists(file_map['web']):
        cmd = f'./{file_map["web"]} run -c config.json'
        run_service_with_retry(cmd, file_map['web'])
    time.sleep(1)

    # 运行 bot
    if os.path.exists(file_map['bot']):
        if re.match(r'^[A-Z0-9a-z=]{120,250}$', ENV['ARGO_AUTH']):
            args = f'tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {ENV["ARGO_AUTH"]}'
        elif 'TunnelSecret' in ENV['ARGO_AUTH']:
            args = 'tunnel --edge-ip-version auto --config tunnel.yml run'
        else:
            args = f'tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile boot.log --loglevel info --url http://localhost:{ENV["ARGO_PORT"]}'
        
        cmd = f'./{file_map["bot"]} {args}'
        run_service_with_retry(cmd, file_map['bot'])
    time.sleep(3)
    
    # 删除文件
    for name in ['npm', 'web', 'bot']:
        if name in file_map and os.path.exists(file_map[name]):
            os.remove(file_map[name])        
            
def get_ip_and_isp():
    ip = None
    try:
        ip = subprocess.check_output(['curl', '-s', 'ip.eooce.com'], timeout=2).decode().strip()
        if ip.startswith('{'): 
            ip = json.loads(ip).get('ip')
            if ':' in ip:
                ip = f'[{ip}]'
    except:
        pass
    
    if not ip:
        try:
            ip = subprocess.check_output(['curl', '-s', 'ip.sb'], timeout=2).decode().strip()
            if ':' in ip:
                ip = f'[{ip}]'
        except:
            ip = "ip not found"
    
    if not ip or ip.startswith('<'):
        ip = "ip not found"
    
    try:
        meta = requests.get('https://speed.cloudflare.com/meta', timeout=2).json()
        isp = f"{meta['colo']}-{meta['asOrganization']}".replace(' ', '_')
    except:
        isp = "unknown"
    
    return ip, isp

def get_argodomain():
    if ENV['ARGO_AUTH']:
        return ENV['ARGO_DOMAIN']
    
    for _ in range(5):
        if os.path.exists('boot.log'):
            with open('boot.log', 'r') as f:
                content = f.read()
                match = re.search(r'https://[0-9a-z.-]+\.trycloudflare\.com', content)
                if match:
                    return match.group(0).replace('https://', '')
        time.sleep(2)
    return ''

def generate_subscription(argodomain, ip, isp, public_key):
    vless = f"vless://{ENV['UUID']}@{ENV['CFIP']}:{ENV['CFPORT']}?encryption=none&security=tls&sni={argodomain}&allowInsecure=1&type=ws&host={argodomain}&path=%2Fvless%3Fed%3D2048#{ENV['NAME']}-{isp}"
    
    with open('list.txt', 'w') as f:
        f.write(vless + '\n')
        
        if ENV['HY2_PORT'] != '50000':
            hysteria2 = f"hysteria2://{ENV['UUID']}@{ip}:{ENV['HY2_PORT']}/?sni=www.bing.com&alpn=h3&insecure=1#{ENV['NAME']}-{isp}"
            f.write(hysteria2 + '\n')
        
        if ENV['TUIC_PORT'] != '40000':
            tuic = f"tuic://{ENV['UUID']}:admin@{ip}:{ENV['TUIC_PORT']}?sni=www.bing.com&alpn=h3&congestion_control=bbr#{ENV['NAME']}-{isp}"
            f.write(tuic + '\n')
        
        if ENV['REALITY_PORT'] != '60000':
            reality = f"vless://{ENV['UUID']}@{ip}:{ENV['REALITY_PORT']}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=who.cx&fp=chrome&pbk={public_key}&type=tcp&headerType=none#{ENV['NAME']}-{isp}"
            f.write(reality + '\n')
    
    with open('list.txt', 'rb') as f:
        content = f.read()
    with open(f"{ENV['FILE_PATH']}/sub.txt", 'wb') as f:
        f.write(base64.b64encode(content))
    
    console.print(f"[bold green]{ENV['FILE_PATH']}/sub.txt saved successfully[/bold green]")
    
    with open(f"{ENV['FILE_PATH']}/sub.txt", 'r') as f:
        sub_content = f.read()
    console.print(sub_content)
   
    send_telegram()  # 发送 Telegram 消息

def main():
    os.makedirs(ENV['FILE_PATH'], exist_ok=True)
    for f in ['boot.log', 'config.json', 'tunnel.json', 'tunnel.yml', f"{ENV['FILE_PATH']}/sub.txt"]:
        if os.path.exists(f):
            os.remove(f)
    
    configure_argo()
    generate_cert()
    file_map = download_files()
    public_key = generate_config(file_map)
    run_services(file_map)
    
    argodomain = get_argodomain()
    console.print(f"[bold green]ArgoDomain:[/bold green] [bold cyan]{argodomain}[/bold cyan]")
    
    ip, isp = get_ip_and_isp()
    generate_subscription(argodomain, ip, isp, public_key)
    console.print("[bold green]Running done![/bold green]")
    
    time.sleep(5) 
    
    cleanup_files = ['boot.log', 'config.json', 'sb.log', 
                    'list.txt', 'core', 'fake_useragent_0.2.0.json']
    for f in cleanup_files:
        if os.path.exists(f):
            os.remove(f)
            # console.print(f"[bold green]Removed {f}[/bold green]")

    os.system('cls' if os.name == 'nt' else 'clear')
    
    # 启动http服务
    port = int(ENV['PORT'])
    server = HTTPServer(('', port), RequestHandler)
    console.print(f"\n[bold green]Started HTTP server is running on port {port}[/bold green]")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

if __name__ == '__main__':
    main()
