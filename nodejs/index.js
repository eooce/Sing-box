const express = require("express");
const app = express();
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const { execSync } = require('child_process');
const projectPageURL = process.env.URL || '';         // 填写项目域名可开启自动访问保活,例如：https://google.com   
const intervalInseconds = process.env.TIME || 120;    // 自动访问间隔时间，120s
const SUB_PATH = process.env.SUB_PATH || '/sub';      // sub订阅访问路径，默认为"/sub",例如：https://google.com:1234/sub 
const FILE_PATH = process.env.FILE_PATH || './.npm';  // sub.txt订阅文件路径
const UUID = process.env.UUID || '9afd1229-b893-40c1-84dd-51e7ce204913';  // UUID
const NEZHA_SERVER = process.env.NEZHA_SERVER || 'nz.abc.cn';  // 哪吒面板地址
const NEZHA_PORT = process.env.NEZHA_PORT || '5555';           // 哪吒agent端口，当端口为{443,8443,2087,2083,2053,2096}时，自动开启tls
const NEZHA_KEY = process.env.NEZHA_KEY || '';                 // 哪吒agwnt密钥 
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';             // argo固定隧道域名,留空即使用临时隧道
const ARGO_AUTH = process.env.ARGO_AUTH || '';                 // argo固定隧道token或json,留空即使用临时隧道
const ARGO_PORT = process.env.ARGO_PORT || 8080;               // argo固定隧道端口,使用token需在cloudflare控制台设置和这里一致，否则节点不通
const HY2_PORT = process.env.HY2_PORT || 40000;                // hy2端口，支持多端口的可以填写，否则保持默认不动
const TUIC_PORT = process.env.TUIC_PORT || 50000;              // tuic端口，支持多端口的可以填写，否则保持默认不动
const REAL_PORT = process.env.REAL_PORT || 60000;              // reality端口，支持多端口的可以填写，否则保持默认不动
const CFIP = process.env.CFIP || 'www.visa.com.tw';            // 优选域名或优选IP
const CFPORT = process.env.CFPORT || 443;                      // 优选域名或优选IP对应端口
const PORT = process.env.PORT || 3000;                         // http订阅端口    
const NAME = process.env.NAME || 'Vls';                        // 节点名称

//创建运行文件夹
if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
  console.log(`${FILE_PATH} is created`);
} else {
  console.log(`${FILE_PATH} already exists`);
}

//清理历史文件
const pathsToDelete = [ 'web', 'bot', 'npm', 'sub.txt', 'boot.log'];
function cleanupOldFiles() {
  pathsToDelete.forEach((file) => {
    const filePath = path.join(FILE_PATH, file);
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error(`Skip Delete ${filePath}`);
      } else {
        console.log(`${filePath} deleted`);
      }
    });
  });
}
cleanupOldFiles();

// 根路由
app.get("/", function(req, res) {
  res.send("Hello world!");
});

let privateKey = '';
let publicKey = ''; 

// 判断系统架构
function getSystemArchitecture() {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  } else {
    return 'amd';
  }
}

// 下载对应系统架构的依赖文件
function downloadFile(fileName, fileUrl, callback) {
  const filePath = path.join(FILE_PATH, fileName);
  const writer = fs.createWriteStream(filePath);

  axios({
    method: 'get',
    url: fileUrl,
    responseType: 'stream',
  })
    .then(response => {
      response.data.pipe(writer);

      writer.on('finish', () => {
        writer.close();
        console.log(`Download ${fileName} successfully`);
        callback(null, fileName);
      });

      writer.on('error', err => {
        fs.unlink(filePath, () => { });
        const errorMessage = `Download ${fileName} failed: ${err.message}`;
        console.error(errorMessage); // 下载失败时输出错误消息
        callback(errorMessage);
      });
    })
    .catch(err => {
      const errorMessage = `Download ${fileName} failed: ${err.message}`;
      console.error(errorMessage); // 下载失败时输出错误消息
      callback(errorMessage);
    });
}

// 下载并运行依赖文件
async function downloadFilesAndRun() {
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);

  if (filesToDownload.length === 0) {
    console.log(`Can't find a file for the current architecture`);
    return;
  }

  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl, (err, fileName) => {
        if (err) {
          reject(err);
        } else {
          resolve(fileName);
        }
      });
    });
  });

  try {
    await Promise.all(downloadPromises); // 等待所有文件下载完成
  } catch (err) {
    console.error('Error downloading files:', err);
    return;
  }

  // 授权文件
  function authorizeFiles(filePaths) {
    const newPermissions = 0o775;

    filePaths.forEach(relativeFilePath => {
      const absoluteFilePath = path.join(FILE_PATH, relativeFilePath);

      fs.chmod(absoluteFilePath, newPermissions, (err) => {
        if (err) {
          console.error(`Empowerment failed for ${absoluteFilePath}: ${err}`);
        } else {
          console.log(`Empowerment success for ${absoluteFilePath}: ${newPermissions.toString(8)}`);
        }
      });
    });
  }
  const filesToAuthorize = ['./npm', './web', './bot'];
  authorizeFiles(filesToAuthorize);

  // 生成 reality-keypair
  exec(`${path.join(FILE_PATH, 'web')} generate reality-keypair`, async (err, stdout, stderr) => {
    if (err) {
      console.error(`Error generating reality-keypair: ${err.message}`);
      return;
    }
    // 提取 private_key 和 public_key
    const privateKeyMatch = stdout.match(/PrivateKey:\s*(.*)/);
    const publicKeyMatch = stdout.match(/PublicKey:\s*(.*)/);

    privateKey = privateKeyMatch ? privateKeyMatch[1] : '';
    publicKey = publicKeyMatch ? publicKeyMatch[1] : ''; // 赋值给全局变量

    if (!privateKey || !publicKey) {
      console.error('Failed to extract privateKey or publicKey from output.');
      return;
    }

    console.log('Private Key:', privateKey);
    console.log('Public Key:', publicKey);

    // 生成 private.key 文件
    exec('openssl ecparam -genkey -name prime256v1 -out "private.key"', (err, stdout, stderr) => {
      if (err) {
        console.error(`Error generating private.key: ${err.message}`);
        return;
      }
    // console.log('private.key has been generated successfully.');

      // 生成 cert.pem 文件
      exec('openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=bing.com"', async (err, stdout, stderr) => {
        if (err) {
          console.error(`Error generating cert.pem: ${err.message}`);
          return;
        }
      // console.log('cert.pem has been generated successfully.');

        // 确保 privateKey 和 publicKey 已经被正确赋值
        if (!privateKey || !publicKey) {
          console.error('PrivateKey or PublicKey is missing, retrying...');
          return;
        }

        // 生成sb配置文件
        const config = {
          "log": {
            "disabled": true,
            "level": "info",
            "timestamp": true
          },
          "dns": {
            "servers": [
              {
                "tag": "google",
                "address": "tls://8.8.8.8",
                "strategy": "prefer_ipv4",
                "detour": "direct"
              }
            ],
            "rules": [
              {
                "rule_set": ["geosite-openai"],
                "server": "wireguard"
              },
              {
                "rule_set": ["geosite-netflix"],
                "server": "wireguard"
              }
            ],
            "final": "google",
            "strategy": "",
            "disable_cache": false,
            "disable_expire": false
          },
          "inbounds": [
            {
              "tag": "vmess-ws-in",
              "type": "vmess",
              "listen": "::",
              "listen_port": ARGO_PORT,
              "users": [
                {
                  "uuid": UUID
                }
              ],
              "transport": {
                "type": "ws",
                "path": "/vmess-argo",
                "early_data_header_name": "Sec-WebSocket-Protocol"
              }
            },
            {
              "tag": "vless-in",
              "type": "vless",
              "listen": "::",
              "listen_port": REAL_PORT,
              "users": [
                {
                  "uuid": UUID,
                  "flow": "xtls-rprx-vision"
                }
              ],
              "tls": {
                "enabled": true,
                "server_name": "www.iij.ad.jp",
                "reality": {
                  "enabled": true,
                  "handshake": {
                    "server": "www.iij.ad.jp",
                    "server_port": 443
                  },
                  "private_key": privateKey, 
                  "short_id": [""]
                }
              }
            },
            {
              "tag": "hysteria-in",
              "type": "hysteria2",
              "listen": "::",
              "listen_port": HY2_PORT,
              "users": [
                {
                  "password": UUID
                }
              ],
              "masquerade": "https://bing.com",
              "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "cert.pem",
                "key_path": "private.key"
              }
            },
            {
              "tag": "tuic-in",
              "type": "tuic",
              "listen": "::",
              "listen_port": TUIC_PORT,
              "users": [
                {
                  "uuid": UUID
                }
              ],
              "congestion_control": "bbr",
              "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "cert.pem",
                "key_path": "private.key"
              }
            }
          ],
          "outbounds": [
            {
              "type": "direct",
              "tag": "direct"
            },
            {
              "type": "block",
              "tag": "block"
            },
            {
              "type": "dns",
              "tag": "dns-out"
            },
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
              "reserved": [26, 21, 228]
            }
          ],
          "route": {
            "rules": [
              {
                "protocol": "dns",
                "outbound": "dns-out"
              },
              {
                "ip_is_private": true,
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
            "rule_set": [
              {
                "tag": "geosite-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
                "download_detour": "direct"
              },
              {
                "tag": "geosite-openai",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
                "download_detour": "direct"
              }
            ],
            "final": "direct"
          },
          "experimental": {
            "cache_file": {
              "path": "cache.db",
              "cache_id": "mycacheid",
              "store_fakeip": true
            }
          }
        };
        fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));

        // 运行ne-zha
        let NEZHA_TLS = '';
        if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
          const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
          if (tlsPorts.includes(NEZHA_PORT)) {
            NEZHA_TLS = '--tls';
          } else {
            NEZHA_TLS = '';
          }
          const command = `nohup ${path.join(FILE_PATH, 'npm')} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &`;
          try {
            await execPromise(command);
            console.log('npm is running');
            await new Promise((resolve) => setTimeout(resolve, 1000));
          } catch (error) {
            console.error(`npm running error: ${error}`);
          }
        } else {
          console.log('NEZHA variable is empty, skipping running');
        }

        // 运行sb
        const command1 = `nohup ${path.join(FILE_PATH, 'web')} run -c ${path.join(FILE_PATH, 'config.json')} >/dev/null 2>&1 &`;
        try {
          await execPromise(command1);
          console.log('web is running');
          await new Promise((resolve) => setTimeout(resolve, 1000));
        } catch (error) {
          console.error(`web running error: ${error}`);
        }

        // 运行cloud-fared
        if (fs.existsSync(path.join(FILE_PATH, 'bot'))) {
          let args;

          if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
            args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
          } else if (ARGO_AUTH.match(/TunnelSecret/)) {
            args = `tunnel --edge-ip-version auto --config ${path.join(FILE_PATH, 'tunnel.yml')} run`;
          } else {
            args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${path.join(FILE_PATH, 'boot.log')} --loglevel info --url http://localhost:${ARGO_PORT}`;
          }

          try {
            await execPromise(`nohup ${path.join(FILE_PATH, 'bot')} ${args} >/dev/null 2>&1 &`);
            console.log('bot is running');
            await new Promise((resolve) => setTimeout(resolve, 2000));
          } catch (error) {
            console.error(`Error executing command: ${error}`);
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 5000));

        // 提取域名并生成sub.txt文件
        await extractDomains();
      });
    });
  });
}

// 执行命令的Promise封装
function execPromise(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout || stderr);
      }
    });
  });
}

// 根据系统架构返回对应的url
function getFilesForArchitecture(architecture) {
  if (architecture === 'arm') {
    return [
      { fileName: "npm", fileUrl: "https://github.com/eooce/test/releases/download/arm64/swith" },
      { fileName: "web", fileUrl: "https://github.com/eooce/test/releases/download/arm64/sbx" },
      { fileName: "bot", fileUrl: "https://github.com/eooce/test/releases/download/arm64/bot" },
    ];
  } else if (architecture === 'amd') {
    return [
      { fileName: "npm", fileUrl: "https://github.com/eooce/test/raw/refs/heads/main/swith" },
      { fileName: "web", fileUrl: "https://github.com/eooce/test/releases/download/amd64/sbx" },
      { fileName: "bot", fileUrl: "https://github.com/eooce/test/raw/refs/heads/main/server" },
    ];
  }
  return [];
}

// 获取固定隧道json
function argoType() {
  if (!ARGO_AUTH || !ARGO_DOMAIN) {
    console.log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels");
    return;
  }

  if (ARGO_AUTH.includes('TunnelSecret')) {
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
    const tunnelYaml = `
  tunnel: ${ARGO_AUTH.split('"')[11]}
  credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
  protocol: http2
  
  ingress:
    - hostname: ${ARGO_DOMAIN}
      service: http://localhost:${ARGO_PORT}
      originRequest:
        noTLSVerify: true
    - service: http_status:404
  `;
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
  } else {
    console.log("ARGO_AUTH mismatch TunnelSecret,use token connect to tunnel");
  }
}
argoType();

// 获取临时隧道domain
async function extractDomains() {
  let argoDomain;

  if (ARGO_AUTH && ARGO_DOMAIN) {
    argoDomain = ARGO_DOMAIN;
    console.log('ARGO_DOMAIN:', argoDomain);
    await generateLinks(argoDomain);
  } else {
    try {
      const fileContent = fs.readFileSync(path.join(FILE_PATH, 'boot.log'), 'utf-8');
      const lines = fileContent.split('\n');
      const argoDomains = [];
      lines.forEach((line) => {
        const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (domainMatch) {
          const domain = domainMatch[1];
          argoDomains.push(domain);
        }
      });

      if (argoDomains.length > 0) {
        argoDomain = argoDomains[0];
        console.log('ArgoDomain:', argoDomain);
        await generateLinks(argoDomain);
      } else {
        console.log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
          // 删除 boot.log 文件，等待 2s 重新运行 server 以获取 ArgoDomain
          fs.unlinkSync(path.join(FILE_PATH, 'boot.log'));
          await new Promise((resolve) => setTimeout(resolve, 2000));
          const args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${ARGO_PORT}`;
          try {
            await exec(`nohup ${path.join(FILE_PATH, 'bot')} ${args} >/dev/null 2>&1 &`);
            console.log('bot is running.');
            await new Promise((resolve) => setTimeout(resolve, 3000));
            await extractDomains(); // 重新提取域名
          } catch (error) {
            console.error(`Error executing command: ${error}`);
          }
        }
      } catch (error) {
        console.error('Error reading boot.log:', error);
      }
    }
  
  // 生成 list 和 sub 信息
  async function generateLinks(argoDomain) {
    let SERVER_IP = '';
    try {
      SERVER_IP = execSync('curl -s --max-time 2 ipv4.ip.sb').toString().trim();
    } catch (err) {
      try {
        SERVER_IP = `[${execSync('curl -s --max-time 1 ipv6.ip.sb').toString().trim()}]`;
      } catch (ipv6Err) {
        console.error('Failed to get IP address:', ipv6Err.message);
      }
    }

    const metaInfo = execSync(
      'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
      { encoding: 'utf-8' }
    );
    const ISP = metaInfo.trim();

    return new Promise((resolve) => {
      setTimeout(() => {
        const vmessNode = `vmess://${Buffer.from(JSON.stringify({ v: '2', ps: `${NAME}-${ISP}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2048', tls: 'tls', sni: argoDomain, alpn: '' })).toString('base64')}`;

        let subTxt = vmessNode; // 始终生成vmess节点

        // 根据端口是否改变按需生成其他节点
        if (HY2_PORT !== 40000) {
          const hysteriaNode = `\nhysteria2://${UUID}@${SERVER_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${NAME}-${ISP}`;
          subTxt += hysteriaNode; 
        }

        if (TUIC_PORT !== 50000) {
          const tuicNode = `\ntuic://${UUID}:@${SERVER_IP}:${TUIC_PORT}?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#${NAME}-${ISP}`;
          subTxt += tuicNode; 
        }

        if (REAL_PORT !== 60000) {
          const vlessNode = `\nvless://${UUID}@${SERVER_IP}:${REAL_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=${publicKey}&type=tcp&headerType=none#${NAME}-${ISP}`;
          subTxt += vlessNode; 
        }

        // 打印 sub.txt 内容到控制台
        console.log(Buffer.from(subTxt).toString('base64')); 
        const filePath = path.join(FILE_PATH, 'sub.txt');
        fs.writeFileSync(filePath, Buffer.from(subTxt).toString('base64'));
        console.log(`${FILE_PATH}/sub.txt saved successfully`);

        // 将内容进行 base64 编码并写入 SUB_PATH 路由
        app.get(SUB_PATH, (req, res) => {
          const encodedContent = Buffer.from(subTxt).toString('base64');
          res.set('Content-Type', 'text/plain; charset=utf-8');
          res.send(encodedContent);
        });
        resolve(subTxt);
      }, 2000);
    });
  }
}
  
// 1分钟后删除list,boot,config文件
const npmPath = path.join(FILE_PATH, 'npm');
const webPath = path.join(FILE_PATH, 'web');
const botPath = path.join(FILE_PATH, 'bot');
const bootLogPath = path.join(FILE_PATH, 'boot.log');
const configPath = path.join(FILE_PATH, 'config.json');
function cleanFiles() {
setTimeout(() => {
    exec(`rm -rf ${bootLogPath} ${configPath} ${npmPath} ${webPath} ${botPath}`, (error, stdout, stderr) => {
    if (error) {
        console.error(`Error while deleting files: ${error}`);
        return;
    }
    console.clear()
    console.log('App is running');
    console.log('Thank you for using this script, enjoy!');
    });
}, 60000); // 60 秒
}
cleanFiles();
  
// 自动访问项目URL
let hasLoggedEmptyMessage = false;
async function visitProjectPage() {
try {
    // 如果URL和TIME变量为空时跳过访问项目URL
  if (!projectPageURL || !intervalInseconds) {
    if (!hasLoggedEmptyMessage) {
      console.log("URL or TIME variable is empty,skip visit url");
      hasLoggedEmptyMessage = true;
    }
    return;
    } else {
      hasLoggedEmptyMessage = false;
    }

    await axios.get(projectPageURL);
    // console.log(`Visiting project page: ${projectPageURL}`);
    console.log('Page visited successfully');
    console.clear()
} catch (error) {
    console.error('Error visiting project page:', error.message);
  }
}
setInterval(visitProjectPage, intervalInseconds * 1000);
  
// 回调运行
async function startserver() {
await downloadFilesAndRun();
visitProjectPage();
}
startserver();
  
app.listen(PORT, () => console.log(`Http server is running on port:${PORT}!`));
