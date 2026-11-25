"""
PromptWars Sentinel - Production HTTP Server
Zero-dependency, cloud-ready HTTP service with REST API endpoints,
security headers, CORS support, and static asset serving.
Compatible with Google Cloud Run (reads PORT environment variable, defaults to 8080).
"""

import os
import sys
import json
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from core.analyzer import analyze_prompt
from core.adversary import conduct_prompt_battle
from core.optimizer import optimize_prompt
from core.security import sanitize_input

STATIC_DIR = BASE_DIR / "static"

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class PromptWarsHandler(BaseHTTPRequestHandler):
    server_version = "PromptWarsSentinel/1.0"

    def _set_headers(self, status_code: int = 200, content_type: str = "application/json"):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        # Security Headers
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def _read_json_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length).decode("utf-8")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None

    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            index_path = STATIC_DIR / "index.html"
            if index_path.exists():
                self._set_headers(200, "text/html; charset=utf-8")
                with open(index_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self._set_headers(404, "text/plain")
                self.wfile.write(b"Index file not found.")
            return

        elif path == "/health":
            self._set_headers(200, "application/json")
            self.wfile.write(json.dumps({
                "status": "healthy",
                "service": "PromptWars Sentinel",
                "version": "1.0.0",
                "environment": "cloud_run_ready"
            }).encode("utf-8"))
            return

        elif path.startswith("/static/"):
            file_rel = path.replace("/static/", "", 1)
            target_path = (STATIC_DIR / file_rel).resolve()
            if target_path.exists() and str(target_path).startswith(str(STATIC_DIR.resolve())):
                mime_type, _ = mimetypes.guess_type(target_path)
                self._set_headers(200, mime_type or "application/octet-stream")
                with open(target_path, "rb") as f:
                    self.wfile.write(f.read())
                return
            else:
                self._set_headers(404, "text/plain")
                self.wfile.write(b"File not found.")
                return

        self._set_headers(404, "application/json")
        self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode("utf-8"))

    def do_POST(self):
        path = self.path.split("?")[0]
        data = self._read_json_body()

        if data is None:
            self._set_headers(400, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid JSON payload"}).encode("utf-8"))
            return

        prompt = sanitize_input(data.get("prompt", ""))
        persona = data.get("persona", "developer")

        if path == "/api/analyze":
            result = analyze_prompt(prompt, persona)
            self._set_headers(200, "application/json")
            self.wfile.write(json.dumps(result).encode("utf-8"))
            return

        elif path == "/api/battle":
            result = conduct_prompt_battle(prompt)
            self._set_headers(200, "application/json")
            self.wfile.write(json.dumps(result).encode("utf-8"))
            return

        elif path == "/api/optimize":
            result = optimize_prompt(prompt, persona)
            self._set_headers(200, "application/json")
            self.wfile.write(json.dumps(result).encode("utf-8"))
            return

        self._set_headers(404, "application/json")
        self.wfile.write(json.dumps({"error": "Unknown API route"}).encode("utf-8"))

    def log_message(self, format, *args):
        # Clean logging format
        sys.stderr.write(f"[PromptWars] {self.address_string()} - {format % args}\n")

def run(port: int = 8080):
    server_address = ("0.0.0.0", port)
    httpd = ThreadedHTTPServer(server_address, PromptWarsHandler)
    print(f"🚀 PromptWars Sentinel online at http://0.0.0.0:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down PromptWars Sentinel...")
        httpd.server_close()

if __name__ == "__main__":
    port_env = int(os.environ.get("PORT", 8080))
    run(port=port_env)
