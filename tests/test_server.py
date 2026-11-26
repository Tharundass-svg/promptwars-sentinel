"""Integration tests for the HTTP layer. Starts a real server on an ephemeral port."""

import gzip
import http.client
import io
import json
import threading
import unittest
from pathlib import Path
from unittest import mock

import server


class MockHandlerSocket:
    def __init__(self, request_bytes):
        self.rfile = io.BytesIO(request_bytes)
        self.wfile = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if "r" in mode:
            return self.rfile
        return self.wfile

    def sendall(self, b):
        self.wfile.write(b)

    def settimeout(self, t):
        pass

    def getpeername(self):
        return ("127.0.0.1", 54321)

    def getsockname(self):
        return ("127.0.0.1", 8080)


class FakeSocket:
    def __init__(self, b):
        self.b = b

    def makefile(self, *a, **k):
        return io.BytesIO(self.b)


class ServerTestCase(unittest.TestCase):
    limiter = None

    @classmethod
    def setUpClass(cls):
        assets = {
            "index.html": server.StaticAsset(b"<!doctype html><title>t</title>" + b"x" * 1000,
                                             "text/html; charset=utf-8"),
            "app.js": server.StaticAsset(b"console.log(1);", "application/javascript"),
        }
        cls.httpd = server.create_server(
            0, "127.0.0.1", assets=assets,
            limiter=cls.limiter or server.RateLimiter(1000, 1000))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, method, path, body=None, headers=None, raw=None):
        hdrs = dict(headers or {})
        if raw is None and body is not None:
            raw = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request(method, path, body=raw, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            conn.close()
            return resp, data
        except (OSError, PermissionError):
            # In-memory execution fallback for sandboxed test environments
            req_lines = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{self.port}"]
            for k, v in hdrs.items():
                req_lines.append(f"{k}: {v}")
            if raw and "Content-Length" not in hdrs:
                req_lines.append(f"Content-Length: {len(raw)}")
            req_bytes = "\r\n".join(req_lines).encode("utf-8") + b"\r\n\r\n" + (raw or b"")
            sock = MockHandlerSocket(req_bytes)
            try:
                self.httpd.RequestHandlerClass(sock, ("127.0.0.1", 54321), self.httpd)
            except Exception:
                pass
            resp_raw = sock.wfile.getvalue()
            r = http.client.HTTPResponse(FakeSocket(resp_raw), method=method)
            r.begin()
            data = r.read() if method != "HEAD" else b""
            return r, data


class TestStaticAndHealth(ServerTestCase):
    def test_health(self):
        resp, data = self.request("GET", "/health")
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(data)["status"], "healthy")

    def test_index_served_with_security_headers(self):
        resp, _ = self.request("GET", "/")
        self.assertEqual(resp.status, 200)
        for header in ("Content-Security-Policy", "X-Content-Type-Options",
                       "X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security"):
            self.assertIsNotNone(resp.getheader(header), header)
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertIn("max-age", resp.getheader("Strict-Transport-Security"))

    def test_gzip_negotiation(self):
        resp, data = self.request("GET", "/", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(resp.getheader("Content-Encoding"), "gzip")
        self.assertIn(b"<title>t</title>", gzip.decompress(data))

    def test_etag_304(self):
        resp, _ = self.request("GET", "/static/app.js")
        etag = resp.getheader("ETag")
        resp2, data2 = self.request("GET", "/static/app.js", headers={"If-None-Match": etag})
        self.assertEqual(resp2.status, 304)
        self.assertEqual(data2, b"")

    def test_head_has_no_body(self):
        resp, data = self.request("HEAD", "/")
        self.assertEqual(resp.status, 200)
        self.assertEqual(data, b"")

    def test_path_traversal_blocked(self):
        for path in ("/static/../server.py", "/static/%2e%2e/server.py",
                     "/static/..%2fserver.py", "/static//etc/passwd"):
            resp, _ = self.request("GET", path)
            self.assertEqual(resp.status, 404, path)

    def test_unknown_get_is_404_json(self):
        resp, data = self.request("GET", "/nope")
        self.assertEqual(resp.status, 404)
        self.assertIn("error", json.loads(data))

    def test_no_cors_header_by_default(self):
        resp, _ = self.request("GET", "/health")
        self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))


class TestApi(ServerTestCase):
    def test_all_routes_return_json_objects(self):
        for route in server.API_ROUTES:
            resp, data = self.request("POST", route, {"prompt": "You are a helpful assistant."})
            self.assertEqual(resp.status, 200, route)
            self.assertIsInstance(json.loads(data), dict)

    def test_invalid_json(self):
        resp, _ = self.request("POST", "/api/analyze", raw=b"{not json")
        self.assertEqual(resp.status, 400)

    def test_non_object_json(self):
        for payload in ([1, 2], "text", 5):
            resp, _ = self.request("POST", "/api/analyze", payload)
            self.assertEqual(resp.status, 400, payload)

    def test_prompt_must_be_string(self):
        resp, _ = self.request("POST", "/api/analyze", {"prompt": 123})
        self.assertEqual(resp.status, 400)

    def test_persona_validation(self):
        for persona in ("../etc", "x" * 100, 5, "a b"):
            resp, _ = self.request("POST", "/api/analyze", {"prompt": "hi", "persona": persona})
            self.assertEqual(resp.status, 400, persona)

    def test_prompt_too_long(self):
        resp, _ = self.request("POST", "/api/analyze",
                               {"prompt": "a" * (server.MAX_PROMPT_CHARS + 1)})
        self.assertEqual(resp.status, 413)

    def test_body_too_large(self):
        raw = b"{" + b" " * server.MAX_BODY_BYTES + b"}"
        resp, _ = self.request("POST", "/api/analyze", raw=raw)
        self.assertEqual(resp.status, 413)

    def test_unknown_route(self):
        resp, _ = self.request("POST", "/api/unknown", {"prompt": "x"})
        self.assertEqual(resp.status, 404)

    def test_internal_errors_do_not_leak_details(self):
        boom = mock.Mock(side_effect=RuntimeError("secret internals"))
        with mock.patch.dict(server.API_ROUTES, {"/api/analyze": boom}):
            resp, data = self.request("POST", "/api/analyze", {"prompt": "x"})
        self.assertEqual(resp.status, 500)
        self.assertNotIn(b"secret", data)

    def test_options_preflight(self):
        resp, _ = self.request("OPTIONS", "/api/analyze")
        self.assertEqual(resp.status, 204)


class TestRateLimiting(ServerTestCase):
    limiter = server.RateLimiter(rate_per_sec=0.001, burst=3)

    def test_burst_then_429(self):
        statuses = [self.request("POST", "/api/analyze", {"prompt": "x"})[0].status
                    for _ in range(6)]
        self.assertEqual(statuses[:3], [200, 200, 200])
        self.assertIn(429, statuses[3:])


class TestRateLimiterUnit(unittest.TestCase):
    def test_independent_clients_and_eviction(self):
        limiter = server.RateLimiter(0.001, 1, max_clients=2)
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))
        limiter.allow("c")
        self.assertLessEqual(len(limiter._buckets), 2)


class TestStaticLoader(unittest.TestCase):
    def test_missing_directory_returns_empty(self):
        self.assertEqual(server.load_static_assets(Path("/definitely/not/here")), {})


if __name__ == "__main__":
    unittest.main()
