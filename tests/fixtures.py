"""Local test fixtures — a tiny vulnerable web app for integration tests."""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

# Global state
_challenges: dict[str, str] = {}


class VulnerableHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that模拟 vulnerable endpoints for testing."""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # silence logs

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/":
            self._respond(200, "text/html", self._index_html())
        elif path == "/api/users":
            self._respond_json(200, [
                {"id": 1, "name": "admin", "role": "admin"},
                {"id": 2, "name": "user", "role": "user"},
            ])
        elif path == "/api/secret":
            self._respond_json(403, {"error": "forbidden"})
        elif path == "/api/config":
            self._respond_json(200, {
                "database": "sqlite:///app.db",
                "api_key": "sk-1234567890abcdef",
                "debug": True,
            })
        elif path == "/login":
            self._respond(200, "text/html", self._login_html())
        elif path == "/search":
            query = self._get_query_param("q")
            self._respond(200, "text/html", f"<html><body>Results for: {query}</body></html>")
        elif path == "/admin":
            self._respond(401, "text/html", "Unauthorized")
        elif path == "/api/v1/items" or path.startswith("/api/v1/items/"):
            item_id = path.split("/")[-1] if path.count("/") > 4 else None
            if item_id:
                self._respond_json(200, {"id": int(item_id), "name": f"item{item_id}", "secret": "internal_note"})
            else:
                self._respond_json(200, [
                    {"id": 1, "name": "item1"},
                    {"id": 2, "name": "item2"},
                ])
        elif path == "/static/app.js":
            self._respond(200, "application/javascript", self._js_content())
        elif path == "/health":
            self._respond_json(200, {"status": "ok"})
        elif path == "/cookies":
            self._respond_with_cookies(200)
        elif path == "/cors-test":
            self._respond_cors(200, self.headers.get("Origin", "*"))
        elif path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", "https://evil.example.com")
            self.end_headers()
        else:
            self._respond(404, "text/html", "Not Found")

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        if self.path == "/login":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            username = data.get("username", "")
            password = data.get("password", "")
            if username == "admin" and password == "password123":
                self._respond_json(200, {"token": "jwt-admin-token-abc123"})
            else:
                self._respond_json(401, {"error": "invalid credentials"})
        elif self.path == "/api/echo":
            self._respond_json(200, {"echo": body})
        else:
            self._respond(404, "text/plain", "Not Found")

    def _respond(self, code: int, content_type: str, body: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "TestServer/1.0")
        self.send_header("X-Powered-By", "Express")
        self.end_headers()
        self.wfile.write(body.encode())

    def _respond_json(self, code: int, data: Any) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "TestServer/1.0")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _respond_with_cookies(self, code: int) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=abc123; HttpOnly")
        self.send_header("Set-Cookie", "tracker=xyz; Path=/")
        self.send_header("Set-Cookie", "prefs=dark; Secure; SameSite=Strict")
        self.end_headers()
        self.wfile.write(b"<html><body>Cookies set</body></html>")

    def _respond_cors(self, code: int, origin: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(b'{"cors": "enabled"}')

    def _get_query_param(self, param: str) -> str:
        if "?" in self.path:
            for pair in self.path.split("?", 1)[1].split("&"):
                if pair.startswith(param + "="):
                    return pair.split("=", 1)[1]
        return ""

    def _index_html(self) -> str:
        return """<!DOCTYPE html>
<html>
<head><title>Test App</title></head>
<body>
<h1>Vulnerable Test Application</h1>
<nav>
  <a href="/login">Login</a>
  <a href="/api/users">Users API</a>
  <a href="/search?q=test">Search</a>
  <a href="/admin">Admin</a>
  <a href="/api/v1/items">Items API</a>
</nav>
<script src="/static/app.js"></script>
</body>
</html>"""

    def _login_html(self) -> str:
        return """<!DOCTYPE html>
<html>
<body>
<form method="POST" action="/login">
  <input name="username" />
  <input name="password" type="password" />
  <button type="submit">Login</button>
</form>
</body>
</html>"""

    def _js_content(self) -> str:
        return """
const API_KEY = "sk-test-key-12345";
const AWS_ACCESS = "AKIAIOSFODNN7EXAMPLE";
fetch('/api/users', {
    headers: { 'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.test' }
});
"""


class TestServer:
    """Threaded HTTP test server."""

    __test__ = False  # pytest: never collect this helper as a test class

    def __init__(self, port: int = 0) -> None:
        self.port = port
        self._httpd: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        self._httpd = HTTPServer(("127.0.0.1", self.port), VulnerableHandler)
        actual_port = self._httpd.server_address[1]
        self.port = actual_port
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return actual_port

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
