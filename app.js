const os = require('os');
const http = require('http');
const { spawn } = require('child_process');

process.env.NEZHA_SERVER = "nz.f4i.cn:5555";
process.env.NEZHA_KEY = "tkKHKi5piddSKFLq7F";
const port= process.env.PORT||3000;

// 运行哪吒
const command1 = `./swith -s ${process.env.NEZHA_SERVER} -p ${process.env.NEZHA_KEY}`;
const process1 = spawn('bash', ['-c', command1]);

// 打印哪吒进程PID和输出
console.log(`PID: ${process1.pid}`);
console.log("nezha已运行:");
process1.stdout.on('data', (data) => {
  console.log(data.toString().trim());
});

// 运行xray
const command2 = './web -c ./config.json';
const process2 = spawn('bash', ['-c', command2]);

// 打印xray进程PID和输出
console.log(`PID: ${process2.pid}`);
console.log("xray已运行:");
process2.stdout.on('data', (data) => {
  console.log(data.toString().trim());
});

// 创建HTTP服务器
const server = http.createServer((req, res) => {
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Hello, world');
  } else if (req.url === '/list') {
    try {
      const content = fs.readFileSync('./list.txt', 'utf-8');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(content);
    } catch (error) {
      res.writeHead(500);
      res.end('Error reading file');
    }
  } else if (req.url === '/sub') {
    try {
      const content = fs.readFileSync('./sub.txt', 'utf-8');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(content);
    } catch (error) {
      res.writeHead(500);
      res.end('Error reading file');
    }
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});

// 启动HTTP服务器
server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
