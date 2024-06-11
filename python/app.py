import sys
import os
import subprocess
import http.server
import socketserver
import threading

PORT = int(os.environ.get('PORT') or 3000) # http port

class MyHandler(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Hello, world')
        elif self.path == '/sub':
            try:
                with open("./sub.txt", 'rb') as file:
                    content = file.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'Error reading file')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')
httpd = socketserver.TCPServer(('', PORT), MyHandler)
server_thread = threading.Thread(target=httpd.serve_forever)
server_thread.daemon = True
server_thread.start()

shell_command = "chmod +x start.sh && ./start.sh"

try:
    completed_process = subprocess.run(['bash', '-c', shell_command], stdout=sys.stdout, stderr=subprocess.PIPE, text=True, check=True)

    print("App is running")

except subprocess.CalledProcessError as e:
    print(f"Error: {e.returncode}")
    print("Standard Output:")
    print(e.stdout)
    print("Standard Error:")
    print(e.stderr)
    sys.exit(1)

server_thread.join()
