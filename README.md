# 1：vps一键命令，已集成到ssh工具箱中
* 一键四协议安装脚本，支持纯v6，支持订阅，默认解锁GPT和奈飞
* 最好用的四协议组合vless-reality|vmess-ws-tls(argo)|hysteria2|tuic5
* 支持的系统：Ubuntu/Debian/CentOS/Alpine/Fedora/Rocky/Almalinux/kail
* 注意nat小鸡安装完一键脚本之后需手动更改订阅端口和节点端口在允许范围内的端口，否则节点不通
* 可在脚本前添加PORT变量，随脚本一起运行，即可定义端口，需确保PORT端口后面的3个端口可用，否则节点不通

## VPS一键四协议安装脚本
```
bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sing-box.sh)
```

## ssh综合工具箱一键脚本
```
curl -fsSL https://raw.githubusercontent.com/eooce/ssh_tool/main/ssh_tool.sh -o ssh_tool.sh && chmod +x ssh_tool.sh && ./ssh_tool.sh
```

# 2：Serv00|CT8一键安装脚本,集成哪吒探针
* 一键四协议安装脚本，vmess-ws|vmess-ws-tls(argo)|hy2|tuic5默认解锁GPT和奈飞
* 支持自定义哪吒参数，Argo参数随脚本一起运行，
* 列如：UUID=123456 NEZHA_SERVER=nz.abcd.com NEZHA_PORT=5555 NEZHA_KEY=123ABC ARGO_DOMAIN=2go.admin.com ARGO_AUTH=abc123  
* 注意：面板开的端口必须符合脚本中提示的要求，并且与输入的对应，面板运行应用程序的权限必须打开，个别服务器ip被墙换到新增加的服务器即可，客户端跳过证书验证需设置为true，否则hy2和tuic不通
* 详细图文教程地址：https://linux.do/t/topic/169670

## Serv00|CT8一键四协议安装脚本vmess-ws|vmess-ws-tls(argo)|hy2|tuic5
```
bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sb_serv00.sh)
```

## Serv00|CT8一键四协议无交互安装脚本vmess-ws|vmess-ws-tls(argo)|hy2|tuic5，需设置环境变量
* 必填环境变量：VMESS_PORT HY2_PORT TUIC_PORT
* 可选环境变量：UUID NEZHA_SERVER NEZHA_PORT NEZHA_KEY ARGO_DOMAIN ARGO_AUTH CFIP CFPORT
* ARGO_AUTH变量使用json时，ARGO_AUTH=‘json’  需用英文输入状态下的单引号包裹，例如：ARGO_AUTH='{"AccountTag":"123","TunnelSecret":"123","TunnelID":"123"}' 
```
VMESS_PORT=tcp端口 HY2_PORT=udp端口 TUIC_PORT=udp端口 bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sb_00.sh)
```

## Serv00|CT8一键三协议安装脚本vless-reality|hy2|tuic5 
```
bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/test/sb_00.sh)
```

## Serv00|CT8一键三协议无交互安装脚本vless-reality|vmess-splithttp|vmess-splithttp-tls(argo) 
* 必填环境变量：VLESS_PORT ARGO_PORT
* 可选环境变量：UUID CFIP CFPORT NEZHA_SERVER NEZHA_PORT NEZHA_KEY ARGO_DOMAIN ARGO_AUTH
* ARGO_AUTH变量使用json时，ARGO_AUTH=‘json’ 需英文输入状态下的单引号包裹，例如：ARGO_AUTH='{"AccountTag":"123","TunnelSecret":"123","TunnelID":"123"}' 
```
VLESS_PORT=TCP端口 ARGO_PORT=TCP端口 bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/test/x00.sh)
```

## Serv00|CT8 hysteria2无交互一键安装脚本
* 必填变量：PORT=UDP端口
* 可选变量：UUID  NEZHA_SERVER  NEZHA_PORT  NEZHA_KEY
```
PORT=UDP端口 bash <(curl -Ls https://00.2go.us.kg/2.sh)
```
或
```
PORT=UDP端口 bash <(curl -Ls https://github.com/eooce/Sing-box/releases/download/00/2.sh)
```

## Serv00|CT8 tuic无交互一键安装脚本
* 必填变量：PORT=UDP端口
* 可选变量：UUID  NEZHA_SERVER  NEZHA_PORT  NEZHA_KEY

```
PORT=UDP端口 bash <(curl -Ls https://00.2go.us.kg/tu.sh)
```
或
```
PORT=UDP端口 bash <(curl -Ls https://github.com/eooce/Sing-box/releases/download/00/tu.sh)
```

## Serv00|CT8 vmess-ws-tls(argo)一键脚本
* 必填变量：PORT=TCP端口
* 可选变量：UUID  NEZHA_SERVER  NEZHA_PORT  NEZHA_KEY  CFIP CFPORT ARGO_DOMAIN  ARGO_AUTH

```
PORT=TCP端口 bash <(curl -Ls https://raw.githubusercontent.com/eooce/scripts/master/containers-shell/00_vmess.sh)
```




# 3：游戏机hosting
## sing-box玩具四合一，默认解锁GPT和奈飞
* node,python,java,go环境的游戏玩具搭建singbox节点，集成哪吒探针服务
* 玩具默认vmess-argo + hy2，支持多端口的玩具可自行添加端口变量同时开启4协议节点
* 对应文件夹即对应环境请下载对应文件夹里的文件上传并赋予权限，修改变量后运行
* ARGO_DOMAIN和ARGO_AUTH两个变量其中之一为空即启用临时隧道，反之则使用固定隧道
* 无需设置NEZHA_TLS,当哪吒端口为{443,8443,2096,2087,2083,2053}其中之一时，自动开启tls

## 游戏机hosting可选变量
  | 变量名        | 是否必须 | 默认值 | 备注 |
  | ------------ | ------ | ------ | ------ |
  | PORT         | 否 |  3000  |http订阅端口，对应的主运行文件中修改，列如：index.js,app.py中 |
  | ARGO_PORT    | 否 |  8001  |argo隧道端口，固定隧道token需和cloudflare后台设置的一致      |
  | UUID         | 否 | bc97f674-c578-4940-9234-0a1da46041b9|节点UUID                     |
  | NEZHA_SERVER | 否 |        | 哪吒服务端域名，例如nz.aaa.com                             |
  | NEZHA_PORT   | 否 |  5555  | 哪吒端口为{443,8443,2096,2087,2083,2053}其中之一时，开启tls|
  | NEZHA_KEY    | 否 |        | 哪吒客户端KEY                                             |
  | ARGO_DOMAIN  | 否 |        | argo固定隧道域名，留空即启用临时隧道                        |
  | ARGO_AUTH    | 否 |        | argo固定隧道json或token，留空即启用临时隧道                 |
  | CFIP         | 否 |skk.moe | 节点优选域名或ip                                           |
  | CFPORT       | 否 |  8443  |节点端口                                                   |
  | SERVER_PORT  | 否 |自动获取 | 玩具分配端口，自动获取，无需填写，hy2端口                    |
  | REALITY_PORT | 否 |        | vless-reality端口，支持多端口的玩具可以填写，不填写该节点不通 |
  | TUIC_PORT    | 否 |        | tuic-v5端口，支持多端口的玩具可以填写，不填写该节点不通       |

## 游戏机hostong节点输出
* 输出sub.txt节点文件，可直接导入V2ray，nekbox，小火箭等代理软中
* 订阅：默认不开启，多端口玩具可开启：分配的域名:http端口/sub,前缀不是https，而是http，例如http://www.google.com:1234/sub

# 免责声明
* 本程序仅供学习了解, 非盈利目的，请于下载后 24 小时内删除, 不得用作任何商业用途, 文字、数据及图片均有所属版权, 如转载须注明来源。
* 使用本程序必循遵守部署免责声明，使用本程序必循遵守部署服务器所在地、所在国家和用户所在国家的法律法规, 程序作者不对使用者任何不当行为负责。
