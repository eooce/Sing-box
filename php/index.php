<?php
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

$SUB_PATH = 'sub';   // 订阅路径

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
        
    default:
        http_response_code(404);
        echo "404 Not Found";
        break;
}