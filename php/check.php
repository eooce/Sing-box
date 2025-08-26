<?php
if (!isset($_SERVER['HTTP_USER_AGENT']) && php_sapi_name() !== 'cli') {
    die("请在浏览器中访问或通过命令行运行");
}

// 设置内容类型为HTML
header('Content-Type: text/html; charset=utf-8');

// 检测PHP命令执行函数
function checkPhpFunctions() {
    $functions = [
        'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open'
    ];
    
    $available = [];
    $unavailable = [];
    
    foreach ($functions as $func) {
        if (function_exists($func)) {
            $testResult = @call_user_func($func, 'echo "test"');
            if ($testResult !== false && $testResult !== null) {
                $available[] = $func;
            } else {
                $unavailable[] = $func . " (存在但被禁用)";
            }
        } else {
            $unavailable[] = $func;
        }
    }
    
    return [
        'available' => $available,
        'unavailable' => $unavailable
    ];
}

// 检测外部程序
function checkProgram($program, $versionCommand = '--version') {
    $result = [
        'available' => false,
        'version' => '不可用',
        'raw_output' => ''
    ];
    
    // 使用escapeshellarg确保安全
    $command = escapeshellcmd($program) . ' ' . $versionCommand . ' 2>&1';
    $output = [];
    $returnCode = 0;
    
    // 尝试多种执行方式
    if (function_exists('exec')) {
        @exec($command, $output, $returnCode);
        if ($returnCode === 0 && !empty($output) && !containsCommandNotFound($output)) {
            $result['available'] = true;
            $result['raw_output'] = implode("\n", $output);
            $result['version'] = $output[0];
            return $result;
        }
    }
    
    if (function_exists('shell_exec')) {
        $output = @shell_exec($command);
        if (!empty($output) && !containsCommandNotFound($output)) {
            $result['available'] = true;
            $result['raw_output'] = $output;
            $result['version'] = strtok($output, "\n");
            return $result;
        }
    }
    
    if (function_exists('system')) {
        ob_start();
        @system($command, $returnCode);
        $output = ob_get_clean();
        if ($returnCode === 0 && !empty($output) && !containsCommandNotFound($output)) {
            $result['available'] = true;
            $result['raw_output'] = $output;
            $result['version'] = strtok($output, "\n");
            return $result;
        }
    }
    
    if (!empty($output)) {
        if (is_array($output)) {
            $result['raw_output'] = implode("\n", $output);
            $result['version'] = $output[0] ?? '未知错误';
        } else {
            $result['raw_output'] = $output;
            $result['version'] = strtok($output, "\n");
        }
    }
    
    return $result;
}

function containsCommandNotFound($output) {
    if (is_array($output)) {
        $output = implode(' ', $output);
    }
    return stripos($output, 'command not found') !== false || 
           stripos($output, 'not recognized') !== false;
}

// 执行检测
$phpFunctions = checkPhpFunctions();
$python3 = checkProgram('python3', '--version');
$nodejs = checkProgram('node', '--version');
$npm = checkProgram('npm', '--version');

if ($python3['available']) {
    $primaryPython = $python3;
    $primaryPython['name'] = 'python3';
} else {
    $primaryPython = [
        'available' => false,
        'version' => '不可用',
        'name' => 'python3',
        'raw_output' => ''
    ];
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>服务器环境检测</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eaeaea;
        }
        .header h1 {
            color: #2c3e50;
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        .header p {
            color: #7f8c8d;
            font-size: 1.1rem;
        }
        .section {
            margin-bottom: 40px;
            padding: 25px;
            background: #f8f9fa;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
        }
        .section h2 {
            color: #3498db;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eaeaea;
            display: flex;
            align-items: center;
        }
        .section h2 i {
            margin-right: 10px;
        }
        .status {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            margin-right: 8px;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }
        .available {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .unavailable {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .function-list {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
        }
        .raw-output {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            display: none;
            margin-top: 15px;
            line-height: 1.5;
        }
        .toggle-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background 0.3s;
            display: inline-flex;
            align-items: center;
        }
        .toggle-btn i {
            margin-right: 5px;
        }
        .toggle-btn:hover {
            background: #2980b9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
        }
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #eaeaea;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .note {
            background-color: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #ffeeba;
            margin: 20px 0;
            font-size: 0.95rem;
        }
        .summary {
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
            flex-wrap: wrap;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            text-align: center;
            flex: 1;
            min-width: 200px;
            margin: 10px;
        }
        .summary-card h3 {
            color: #7f8c8d;
            margin-bottom: 10px;
        }
        .summary-card .count {
            font-size: 2.5rem;
            font-weight: bold;
            color: #3498db;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eaeaea;
            color: #7f8c8d;
            font-size: 0.9rem;
        }
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            .header h1 {
                font-size: 2rem;
            }
            table {
                display: block;
                overflow-x: auto;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>服务器环境检测报告</h1>
            <p>全面检测服务器PHP、Python和Node.js环境状态</p>
        </div>
        
        <div class="note">
            <i class="fas fa-exclamation-circle"></i>
            <strong>注意：</strong> 此脚本仅用于检测服务器环境，使用后请及时删除。
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>可用PHP函数</h3>
                <div class="count"><?php echo count($phpFunctions['available']); ?></div>
            </div>
            <div class="summary-card">
                <h3>Python3可用</h3>
                <div class="count"><?php echo ($python3['available']) ? '是' : '否'; ?></div>
            </div>
            <div class="summary-card">
                <h3>Node.js可用</h3>
                <div class="count"><?php echo ($nodejs['available']) ? '是' : '否'; ?></div>
            </div>
        </div>
        
        <div class="section">
            <h2><i class="fas fa-code"></i> PHP命令执行函数检测</h2>
            <div class="function-list">
                <p><strong>可用函数:</strong> 
                    <?php if (!empty($phpFunctions['available'])): ?>
                        <?php foreach ($phpFunctions['available'] as $func): ?>
                            <span class="status available"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($func); ?></span>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <span class="status unavailable"><i class="fas fa-times-circle"></i> 无可用函数</span>
                    <?php endif; ?>
                </p>
                
                <p><strong>不可用函数:</strong> 
                    <?php if (!empty($phpFunctions['unavailable'])): ?>
                        <?php foreach ($phpFunctions['unavailable'] as $func): ?>
                            <span class="status unavailable"><i class="fas fa-times-circle"></i> <?php echo htmlspecialchars($func); ?></span>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <span>无</span>
                    <?php endif; ?>
                </p>
            </div>
        </div>
        
        <div class="section">
            <h2><i class="fab fa-python"></i> Python环境检测</h2>
            <table>
                <tr>
                    <th>程序</th>
                    <th>状态</th>
                    <th>版本信息</th>
                    <th>操作</th>
                </tr>
                <tr>
                    <td>Python3 (python3)</td>
                    <td>
                        <?php if ($python3['available']): ?>
                            <span class="status available"><i class="fas fa-check-circle"></i> 可用</span>
                        <?php else: ?>
                            <span class="status unavailable"><i class="fas fa-times-circle"></i> 不可用</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo htmlspecialchars($python3['version']); ?></td>
                    <td>
                        <?php if (!empty($python3['raw_output'])): ?>
                            <button class="toggle-btn" onclick="toggleOutput('python3-output')"><i class="fas fa-terminal"></i> 显示原始输出</button>
                        <?php endif; ?>
                    </td>
                </tr>
            </table>
            
            <?php if (!empty($python3['raw_output'])): ?>
                <pre id="python3-output" class="raw-output"><?php echo htmlspecialchars($python3['raw_output']); ?></pre>
            <?php endif; ?>
            
            <p><strong>Python版本:</strong> 
                <?php if ($primaryPython['available']): ?>
                    <span class="status available"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($primaryPython['name'] . ' ' . $primaryPython['version']); ?></span>
                <?php else: ?>
                    <span class="status unavailable"><i class="fas fa-times-circle"></i> 未检测到Python3</span>
                <?php endif; ?>
            </p>
        </div>
        
        <div class="section">
            <h2><i class="fab fa-node-js"></i> Node.js环境检测</h2>
            <table>
                <tr>
                    <th>程序</th>
                    <th>状态</th>
                    <th>版本信息</th>
                    <th>操作</th>
                </tr>
                <tr>
                    <td>Node.js (node)</td>
                    <td>
                        <?php if ($nodejs['available']): ?>
                            <span class="status available"><i class="fas fa-check-circle"></i> 可用</span>
                        <?php else: ?>
                            <span class="status unavailable"><i class="fas fa-times-circle"></i> 不可用</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo htmlspecialchars($nodejs['version']); ?></td>
                    <td>
                        <?php if (!empty($nodejs['raw_output'])): ?>
                            <button class="toggle-btn" onclick="toggleOutput('node-output')"><i class="fas fa-terminal"></i> 显示原始输出</button>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td>NPM (npm)</td>
                    <td>
                        <?php if ($npm['available']): ?>
                            <span class="status available"><i class="fas fa-check-circle"></i> 可用</span>
                        <?php else: ?>
                            <span class="status unavailable"><i class="fas fa-times-circle"></i> 不可用</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo htmlspecialchars($npm['version']); ?></td>
                    <td>
                        <?php if (!empty($npm['raw_output'])): ?>
                            <button class="toggle-btn" onclick="toggleOutput('npm-output')"><i class="fas fa-terminal"></i> 显示原始输出</button>
                        <?php endif; ?>
                    </td>
                </tr>
            </table>
            
            <?php if (!empty($nodejs['raw_output'])): ?>
                <pre id="node-output" class="raw-output"><?php echo htmlspecialchars($nodejs['raw_output']); ?></pre>
            <?php endif; ?>
            
            <?php if (!empty($npm['raw_output'])): ?>
                <pre id="npm-output" class="raw-output"><?php echo htmlspecialchars($npm['raw_output']); ?></pre>
            <?php endif; ?>
        </div>
        
        <div class="footer">
            <p>检测时间: <?php echo date('Y-m-d H:i:s'); ?></p>
            <p>服务器IP: <?php echo $_SERVER['SERVER_ADDR'] ?? '未知'; ?></p>
        </div>
    </div>

    <script>
        function toggleOutput(id) {
            const output = document.getElementById(id);
            const buttons = document.querySelectorAll('.toggle-btn');
            let button = null;
            
            buttons.forEach(btn => {
                if (btn.getAttribute('onclick') === `toggleOutput('${id}')`) {
                    button = btn;
                }
            });
            
            if (output.style.display === 'block') {
                output.style.display = 'none';
                if (button) {
                    button.innerHTML = '<i class="fas fa-terminal"></i> 显示原始输出';
                }
            } else {
                output.style.display = 'block';
                if (button) {
                    button.innerHTML = '<i class="fas fa-terminal"></i> 隐藏原始输出';
                }
            }
        }
    </script>
</body>
</html>