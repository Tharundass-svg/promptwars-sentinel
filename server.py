"""PromptWars Sentinel - production HTTP server.

Standard-library only. Features:
  * REST API (/api/analyze, /api/battle, /api/optimize) driven by a route table
  * Static assets preloaded into memory (ETag, gzip, Cache-Control, 304 support)
  * Strict input validation, body-size cap, per-IP rate limiting
  * Hardened security headers (CSP, nosniff, frame denial, referrer/permissions policy)
  * HTTP/1.1 keep-alive, bounded worker threads, graceful SIGTERM shutdown (Cloud Run)

Configuration (environment variables):
  PORT                 listen port (default 8080)
  LOG_LEVEL            logging level (default INFO)
  ALLOWED_ORIGIN       CORS origin to allow; unset = same-origin only
  RATE_LIMIT_PER_SEC   sustained requests/second per client for the API (default 5)
  RATE_LIMIT_BURST     burst size per client for the API (default 20)
  MAX_THREADS          maximum concurrent worker threads (default 64)
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import mimetypes
import os
import re
import signal
import sys
import threading
import time
from collections import OrderedDict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Callable, Dict, Optional, Tuple

from core.adversary import conduct_prompt_battle
from core.analyzer import analyze_prompt
from core.optimizer import optimize_prompt
from core.security import sanitize_input

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
SERVICE_NAME = "PromptWars Sentinel"
VERSION = "1.1.0"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

DEFAULT_PORT = 8080
MAX_BODY_BYTES = 64 * 1024          # hard cap on request bodies
MAX_PROMPT_CHARS = 20_000           # hard cap on prompt length
MAX_STATIC_FILE_BYTES = 2 * 1024 * 1024
GZIP_MIN_BYTES = 512
SOCKET_TIMEOUT_SECONDS = 15         # frees idle keep-alive / slowloris connections
DEFAULT_PERSONA = "developer"
PERSONA_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")

COMPRESSIBLE_PREFIXES = ("text/", "application/json", "application/javascript",
                         "image/svg+xml")

SECURITY_HEADERS: Dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
}

logger = logging.getLogger("promptwars")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Thread-safe token-bucket limiter keyed by client id, with bounded memory."""

    def __init__(self, rate_per_sec: float, burst: int, max_clients: int = 10_000):
        self.rate = rate_per_sec
        self.burst = float(burst)
        self.max_clients = max_clients
        self._buckets: "OrderedDict[str, Tuple[float, float]]" = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._buckets[key] = (tokens, now)
            self._buckets.move_to_end(key)
            while len(self._buckets) > self.max_clients:
                self._buckets.popitem(last=False)
            return allowed


class StaticAsset:
    """An in-memory static file with precomputed ETag and gzip variant."""

    __slots__ = ("body", "gzipped", "etag", "content_type")

    def __init__(self, body: bytes, content_type: str):
        self.body = body
        self.content_type = content_type
        self.etag = '"%s"' % hashlib.sha256(body).hexdigest()[:20]
        self.gzipped: Optional[bytes] = None
        if _is_compressible(content_type) and len(body) >= GZIP_MIN_BYTES:
            self.gzipped = gzip.compress(body, compresslevel=9, mtime=0)


def _is_compressible(content_type: str) -> bool:
    return content_type.startswith(COMPRESSIBLE_PREFIXES)


def load_static_assets(directory: Path) -> Dict[str, StaticAsset]:
    """Read every file under *directory* once. Lookups are then dict hits, so
    request paths never touch the filesystem (no traversal surface)."""
    assets: Dict[str, StaticAsset] = {}
    if not directory.is_dir():
        logger.warning("Static directory %s not found", directory)
        return assets
    root = directory.resolve()
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > MAX_STATIC_FILE_BYTES:
            continue
        mime, _ = mimetypes.guess_type(path.name)
        mime = mime or "application/octet-stream"
        if mime.startswith("text/") or mime in ("application/javascript", "application/json"):
            mime += "; charset=utf-8"
        assets[path.relative_to(root).as_posix()] = StaticAsset(path.read_bytes(), mime)
    logger.info("Preloaded %d static assets", len(assets))
    return assets


class ValidationError(Exception):
    """Raised for client errors; carries the HTTP status and message."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --------------------------------------------------------------------------- #
# API routes
# --------------------------------------------------------------------------- #
ApiFunc = Callable[[str, str], Any]

API_ROUTES: Dict[str, ApiFunc] = {
    "/api/analyze": lambda prompt, persona: analyze_prompt(prompt, persona),
    "/api/battle": lambda prompt, persona: conduct_prompt_battle(prompt),
    "/api/optimize": lambda prompt, persona: optimize_prompt(prompt, persona),
}


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #
class BoundedThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded server with a hard cap on concurrent worker threads."""

    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, handler, *, max_threads: int, limiter: RateLimiter,
                 assets: Dict[str, StaticAsset], allowed_origin: Optional[str]):
        self._slots = threading.BoundedSemaphore(max_threads)
        self.limiter = limiter
        self.assets = assets
        self.allowed_origin = allowed_origin
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        self._slots.acquire()  # back-pressure: excess connections wait in the listen queue
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class PromptWarsHandler(BaseHTTPRequestHandler):
    """Request handler. Every response carries Content-Length (keep-alive safe)."""

    protocol_version = "HTTP/1.1"
    server_version = "PromptWarsSentinel/" + VERSION
    timeout = SOCKET_TIMEOUT_SECONDS

    def version_string(self) -> str:
        return self.server_version

    # ---- response plumbing ------------------------------------------------- #
    def _client_id(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:  # Cloud Run appends the real client IP last; earlier hops are spoofable
            return forwarded.split(",")[-1].strip()
        return self.client_address[0]

    def _send(self, status: int, body: bytes = b"", content_type: str = "application/json",
              extra: Optional[Dict[str, str]] = None, head_only: bool = False,
              compress: bool = True, pre_gzipped: Optional[bytes] = None) -> None:
        headers: Dict[str, str] = dict(SECURITY_HEADERS)
        if extra:
            headers.update(extra)

        if status not in (204, 304):
            wants_gzip = "gzip" in self.headers.get("Accept-Encoding", "").lower()
            if compress and _is_compressible(content_type):
                headers["Vary"] = "Accept-Encoding"
                if wants_gzip:
                    if pre_gzipped is not None:
                        body = pre_gzipped
                        headers["Content-Encoding"] = "gzip"
                    elif len(body) >= GZIP_MIN_BYTES:
                        body = gzip.compress(body, compresslevel=5, mtime=0)
                        headers["Content-Encoding"] = "gzip"
            headers["Content-Type"] = content_type

        origin = self.server.allowed_origin
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Methods"] = "GET, POST, HEAD, OPTIONS"
            headers["Access-Control-Allow-Headers"] = "Content-Type"
            headers["Access-Control-Max-Age"] = "600"
            headers["Vary"] = (headers.get("Vary", "") + ", Origin").lstrip(", ")

        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", "0" if status in (204, 304) else str(len(body)))
        self.end_headers()
        if not head_only and status not in (204, 304):
            self.wfile.write(body)

    def _send_json(self, status: int, payload: Any, extra: Optional[Dict[str, str]] = None,
                   head_only: bool = False) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        merged = {"Cache-Control": "no-store"}
        if extra:
            merged.update(extra)
        self._send(status, body, "application/json", merged, head_only)

    def _send_error_json(self, status: int, message: str, *, close: bool = False,
                         extra: Optional[Dict[str, str]] = None) -> None:
        if close:
            self.close_connection = True
            extra = dict(extra or {}, Connection="close")
        self._send_json(status, {"error": message}, extra)

    # ---- request parsing --------------------------------------------------- #
    def _read_json_body(self) -> Dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValidationError(HTTPStatus.LENGTH_REQUIRED, "Content-Length header required")
        try:
            length = int(raw_length)
        except ValueError:
            raise ValidationError(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
        if length < 0:
            raise ValidationError(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
        if length > MAX_BODY_BYTES:
            raise ValidationError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                                  "Request body exceeds %d bytes" % MAX_BODY_BYTES)
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValidationError(HTTPStatus.BAD_REQUEST, "Invalid JSON payload")
        if not isinstance(data, dict):
            raise ValidationError(HTTPStatus.BAD_REQUEST, "JSON body must be an object")
        return data

    @staticmethod
    def _extract_fields(data: Dict[str, Any]) -> Tuple[str, str]:
        prompt = data.get("prompt", "")
        persona = data.get("persona", DEFAULT_PERSONA)
        if not isinstance(prompt, str):
            raise ValidationError(HTTPStatus.BAD_REQUEST, "'prompt' must be a string")
        if len(prompt) > MAX_PROMPT_CHARS:
            raise ValidationError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                                  "'prompt' exceeds %d characters" % MAX_PROMPT_CHARS)
        if not isinstance(persona, str) or not PERSONA_PATTERN.match(persona):
            raise ValidationError(HTTPStatus.BAD_REQUEST, "'persona' is invalid")
        return sanitize_input(prompt), persona

    # ---- HTTP verbs -------------------------------------------------------- #
    def do_OPTIONS(self) -> None:
        self._send(HTTPStatus.NO_CONTENT)

    def do_HEAD(self) -> None:
        self._handle_get(head_only=True)

    def do_GET(self) -> None:
        self._handle_get(head_only=False)

    def _handle_get(self, head_only: bool) -> None:
        path = self.path.split("?", 1)[0].split("#", 1)[0]

        if path == "/health":
            self._send_json(200, {"status": "healthy", "service": SERVICE_NAME,
                                  "version": VERSION}, head_only=head_only)
            return

        key = "index.html" if path in ("/", "/index.html") else (
            path[len("/static/"):] if path.startswith("/static/") else None)
        asset = self.server.assets.get(key) if key else None
        if asset is None:
            self._send_error_json(404, "Not found")
            return

        cache = "no-cache" if key == "index.html" else "public, max-age=3600"
        headers = {"ETag": asset.etag, "Cache-Control": cache}
        if self.headers.get("If-None-Match") == asset.etag:
            self._send(HTTPStatus.NOT_MODIFIED, extra=headers)
            return
        self._send(200, asset.body, asset.content_type, headers, head_only,
                   pre_gzipped=asset.gzipped)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        route = API_ROUTES.get(path)
        if route is None:
            self._send_error_json(404, "Unknown API route", close=True)
            return

        if not self.server.limiter.allow(self._client_id()):
            self._send_error_json(429, "Too many requests", close=True,
                                  extra={"Retry-After": "1"})
            return

        try:
            data = self._read_json_body()
            prompt, persona = self._extract_fields(data)
        except ValidationError as exc:
            # Body may be unread (413/411), so don't reuse the connection.
            self._send_error_json(int(exc.status), exc.message, close=True)
            return

        try:
            result = route(prompt, persona)
        except Exception:  # noqa: BLE001 - never leak internals to the client
            logger.exception("Unhandled error in %s", path)
            self._send_error_json(500, "Internal server error")
            return
        self._send_json(200, result)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        logger.info("%s - %s", self.address_string(), format % args)


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #
def create_server(port: int = DEFAULT_PORT, host: str = "0.0.0.0", *,
                  limiter: Optional[RateLimiter] = None,
                  assets: Optional[Dict[str, StaticAsset]] = None,
                  allowed_origin: Optional[str] = None,
                  max_threads: Optional[int] = None) -> BoundedThreadingHTTPServer:
    """Build (but don't start) a server. Used by main() and by the tests."""
    if limiter is None:
        limiter = RateLimiter(float(os.environ.get("RATE_LIMIT_PER_SEC", "5")),
                              int(os.environ.get("RATE_LIMIT_BURST", "20")))
    if assets is None:
        assets = load_static_assets(STATIC_DIR)
    return BoundedThreadingHTTPServer(
        (host, port), PromptWarsHandler,
        max_threads=max_threads or int(os.environ.get("MAX_THREADS", "64")),
        limiter=limiter, assets=assets,
        allowed_origin=allowed_origin or os.environ.get("ALLOWED_ORIGIN") or None,
    )


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        stream=sys.stdout,
    )
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    httpd = create_server(port)

    def _graceful_stop(signum, _frame):
        logger.info("Signal %s received, shutting down", signum)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _graceful_stop)
    signal.signal(signal.SIGINT, _graceful_stop)

    logger.info("%s v%s listening on 0.0.0.0:%d", SERVICE_NAME, VERSION, port)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
        logger.info("Server stopped")


if __name__ == "__main__":
    main()
