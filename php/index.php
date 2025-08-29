<?php
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

$SUB_PATH = 'sub';      // 订阅路径
$CHECK_NEZHA = false;   // 控制是否检测哪吒进程，false关闭，true开启，默认关闭

// 命令执行函数
function executeScript($script) {

    chmod($script, 0755);
    
    $command = "bash $script > /dev/null 2>&1 &";
    
    // 尝试多种执行方式
    if (function_exists('exec')) {
        exec($command);
        return "start.sh is running (exec)";
    } elseif (function_exists('shell_exec')) {
        shell_exec($command);
        return "start.sh is running (shell_exec)";
    } elseif (function_exists('system')) {
        system($command);
        return "start.sh is running (system)";
    } elseif (function_exists('passthru')) {
        passthru($command);
        return "start.sh is running (passthru)";
    } elseif (function_exists('popen')) {
        $handle = popen($command, 'r');
        if ($handle) {
            pclose($handle);
            return "start.sh is running (popen)";
        }
    } elseif (function_exists('proc_open')) {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w']
        ];
        $process = proc_open($command, $descriptors, $pipes);
        if (is_resource($process)) {
            fclose($pipes[0]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
            return "start.sh is running (proc_open)";
        }
    }
    
    return "Error: No available command execution function";
}

// 订阅路由
if ($path === "/$SUB_PATH") {
    header("Content-Type: text/plain; charset=utf-8");
    $subFile = __DIR__ . "/.tmp/sub.txt";
    if (file_exists($subFile)) {
        $sub = file_get_contents($subFile);
        echo $sub;
    } else {
        echo "sub.txt file not found at: $subFile";
    }
    exit;
}

// 控制路由
switch ($path) {
    case '/':
        header("Content-Type: text/plain; charset=utf-8");
        echo "Hello world\n";
        break;

    case '/start':
        $script = __DIR__ . "/start.sh";
        echo executeScript($script);
        break;

    case '/restart': 
        $script = __DIR__ . "/start.sh";
        echo executeScript($script) . " (restart)";
        break;

    case '/check':
        $checkFile = __DIR__ . "/check.php";
        if (file_exists($checkFile)) {
            include $checkFile;
        } else {
            http_response_code(404);
            echo "check.php file not found";
        }
        break;
        
    case '/status':
        header("Content-Type: text/plain; charset=utf-8");
        $processStatus = checkProcesses();
        
        if (empty($processStatus['not_running'])) {
            echo "All services are running";
        } else {
            echo "Services not running: " . implode(", ", $processStatus['not_running']) . "\n";
            echo "Starting services...\n";
            $script = __DIR__ . "/start.sh";
            echo executeScript($script);
        }
        break;
        
    case '/list':
        header("Content-Type: text/plain; charset=utf-8");
        echo "所有进程列表：\n\n";
        $allProcesses = shell_exec("ps aux");
        echo $allProcesses . "\n\n";
        break;
        
    // case '/debug':
    //     header("Content-Type: text/plain; charset=utf-8");
    //     echo "=== 进程匹配测试 ===\n\n";
        
    //     global $CHECK_NEZHA;
    //     echo "CHECK_NEZHA 设置: " . ($CHECK_NEZHA ? 'true' : 'false') . "\n\n";
        
    //     // 测试各个匹配模式
    //     $patterns = [
    //         'cloudflared' => 'tunnel.*--edge-ip-version auto', 
    //         'sing-box' => 'run -c.*config\.json'  // sing-box: run -c /路径/config.json
    //     ];
        
    //     // 只在启用时测试nezha
    //     if ($CHECK_NEZHA) {
    //         $patterns['nezha v0'] = ':[0-9].* -p';  // nezha v0: 更精确的匹配 - 端口和-p参数组合
    //         $patterns['nezha v1'] = '-c.*config\.yaml';
    //     }
        
    //     foreach ($patterns as $service => $pattern) {
    //         echo "$service 模式: $pattern\n";
    //         $output = [];
    //         exec("ps aux | grep '$pattern' | grep -v grep", $output);
    //         if (empty($output)) {
    //             echo "结果: 未找到\n\n";
    //         } else {
    //             echo "结果: 找到 " . count($output) . " 个匹配项\n";
    //             foreach ($output as $line) {
    //                 echo "  $line\n";
    //             }
    //             echo "\n";
    //         }
    //     }
        
    //     echo "3. checkProcesses() 函数结果：\n";
    //     $result = checkProcesses();
    //     echo "运行中: " . implode(", ", $result['running']) . "\n";
    //     echo "未运行: " . implode(", ", $result['not_running']) . "\n";
    //     break;
        
    default:
        http_response_code(404);
        echo "404 Not Found";
        break;
}

// 进程检查函数
function checkProcess($pattern) {
    $command = "ps aux | grep '$pattern' | grep -v grep";
    $output = [];
    exec($command, $output);
    return count($output) > 0;
}

// 检查nezha进程（兼容v0和v1）
function checkNezhaProcess() {
    // 检查 nezha v0
    if (checkProcess(':[0-9].* -p')) {
        return true;
    }
    // 检查 nezha v1
    if (checkProcess('-c.*config\.yaml')) {
        return true;
    }
    return false;
}

// 检查所有服务状态
function checkProcesses() {
    global $CHECK_NEZHA;
    
    $processes = [
        'cloudflared' => 'tunnel.*--edge-ip-version auto', 
        'sing-box' => 'run -c.*config\.json'  
    ];
    
    $runningProcesses = [];
    $notRunningProcesses = [];
    
    // 根据变量决定是否检测nezha
    if ($CHECK_NEZHA) {
        if (checkNezhaProcess()) {
            $runningProcesses[] = 'nezha';
        } else {
            $notRunningProcesses[] = 'nezha';
        }
    }
    
    foreach ($processes as $serviceName => $pattern) {
        if (checkProcess($pattern)) {
            $runningProcesses[] = $serviceName;
        } else {
            $notRunningProcesses[] = $serviceName;
        }
    }
    
    return [
        'running' => $runningProcesses,
        'not_running' => $notRunningProcesses
    ];
}
