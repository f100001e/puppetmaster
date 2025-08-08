#!/usr/bin/env python
"""
ua_sniffer.py – mitmproxy addon

• Run:  mitmdump -s mitm/ua_sniffer.py -p 9999 --listen-host 127.0.0.1 \
                 --ssl-insecure --set tls_version_client_min=TLS1_2 \
                 --set tls_version_server_min=TLS1_2
• Captures proxied requests, extracts User-Agent + URL,
  posts to backend /log_ua, and emits Socket.IO events to /scanner.
• Skips localhost and a small allowlist of noisy/external domains.
"""

from mitmproxy import http, ctx
import socketio, requests, os, time, hashlib, json, threading
from threading import Lock
from collections import deque
from typing import Dict, Any
from dotenv import load_dotenv
import uuid, socket, sys
from pathlib import Path

# ────────────────────────────────────────────────
# 0) env, paths, constants
# ────────────────────────────────────────────────
load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))

LOG_DIR = Path(os.getenv("GTAG_LOG_DIR", "~/WebstormProjects/Puppetmaster/gtag_logs")).expanduser()
LOG_DIR.mkdir(parents=True, exist_ok=True)

BACKEND_HTTP_URL   = os.getenv("BACKEND_HTTP_URL",  "http://localhost:3000/log_ua")
BACKEND_SOCKET_URL = os.getenv("BACKEND_URL",       "http://localhost:3000").rstrip("/")
NAMESPACE          = "/scanner"

MAX_UA_LENGTH = 1024

BYPASS_SUFFIXES = {
    "google.com",
    "cloudflare.com",
    "mitm.it",
    "spotify.com",
    "spclient.wg.spotify.com",
    "guc3-spclient.spotify.com",
}
BYPASS_HOSTS = {"localhost", "127.0.0.1", "::1"}

# ────────────────────────────────────────────────
# 1) logging helper
# ────────────────────────────────────────────────
def _safe_log(payload: Dict[str, Any]) -> None:
    try:
        fname = LOG_DIR / f"mitm_{int(time.time())}_{uuid.uuid4().hex[:6]}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(), "data": payload}, f, ensure_ascii=False, indent=2)
    except Exception as e:
        sys.stderr.write(f"EMERG-LOG-FAIL {e}\n")

# ────────────────────────────────────────────────
# 2) helpers
# ────────────────────────────────────────────────
def host_in_bypass(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    if h in BYPASS_HOSTS:
        return True
    for s in BYPASS_SUFFIXES:
        s = s.lower()
        if h == s or h.endswith("." + s):
            return True
    return False

def _probe_scanner_async():
    """Optionally ping your scanner UI so you see quick activity on startup."""
    def _hit():
        try:
            scheme = "https" if os.getenv("SCANNER_HTTPS_ENABLED", "true").lower() in ("1", "true", "yes") else "http"
            host   = os.getenv("SCANNER_HOST", "localhost")
            port   = int(os.getenv("SCANNER_LISTEN_PORT", "8888"))
            requests.get(
                f"{scheme}://{host}:{port}/generate_204",
                timeout=1, verify=False,
                proxies={"http": None, "https": None},
                allow_redirects=False,
            )
        except Exception:
            pass
    threading.Thread(target=_hit, daemon=True).start()

def _http_post_ua(ua: str, url: str) -> None:
    try:
        r = requests.post(
            BACKEND_HTTP_URL,
            json={"ua": ua, "url": url},
            timeout=2,
            headers={"Content-Type": "application/json"},
            proxies={"http": None, "https": None},  # avoid proxy loop
        )
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
    except Exception as e:
        ctx.log.error(f"POST /log_ua failed: {e}")
        _safe_log({"type": "http_fail", "ua": ua[:80], "url": url, "err": str(e)})

# ────────────────────────────────────────────────
# 3) Socket.IO client
# ────────────────────────────────────────────────
class SockClient:
    def __init__(self):
        self.sio = socketio.Client(
            reconnection=True,
            reconnection_attempts=5,
            reconnection_delay=1,
            reconnection_delay_max=30,
            logger=bool(os.getenv("DEBUG"))
        )
        self.lock = Lock()
        self.connected = False
        self._bind_events()
        self._connect()

    def _bind_events(self):
        @self.sio.event
        def connect():
            self.connected = True
            ctx.log.info("Socket.IO ✓ connected")

        @self.sio.event
        def disconnect():
            self.connected = False
            ctx.log.warn("Socket.IO ✕ disconnected")

    def _connect(self):
        for n in range(3):
            if self.connected:
                return
            try:
                ctx.log.info(f"Socket.IO connect attempt {n + 1}/3")
                self.sio.connect(
                    BACKEND_SOCKET_URL,
                    namespaces=[NAMESPACE],
                    transports=['websocket'],
                    headers={'Origin': BACKEND_SOCKET_URL, 'X-MITM-Node': socket.gethostname()}
                )
                return  # success
            except Exception as e:
                ctx.log.error(f"connect fail: {e}")
                time.sleep(2 ** n)

    def emit(self, event: str, data: Any):
        with self.lock:
            if self.connected:
                try:
                    self.sio.emit(event, data, namespace=NAMESPACE)
                except Exception as e:
                    self.connected = False
                    ctx.log.error(f"emit fail: {e}")

sock = SockClient()

# ────────────────────────────────────────────────
# 4) mitmproxy lifecycle & hooks
# ────────────────────────────────────────────────
def load(loader):
    """Called by mitmproxy once on addon load."""
    _probe_scanner_async()
    ctx.log.info("ua_sniffer loaded")

def request(flow: http.HTTPFlow):
    try:
        if host_in_bypass(flow.request.host):
            return

        ua  = (flow.request.headers.get("User-Agent", "") or "NO_UA")[:MAX_UA_LENGTH]
        url = flow.request.pretty_url

        def handle():
            _http_post_ua(ua, url)
            # dedupe by UA hash (small, per-process)
            h = hashlib.sha256(ua.encode()).hexdigest()
            # simple de-dupe buffer
            # (global small deque for "seen" hashes)
            if h not in UA_QUEUE:
                UA_QUEUE.append(h)
                sock.emit("uaUpdate", {
                    "ua": ua,
                    "url": url,
                    "ts": int(time.time() * 1000),
                    "src_ip": flow.client_conn.peername[0] if flow.client_conn else None
                })

        threading.Thread(target=handle, daemon=True).start()

    except Exception as e:
        ctx.log.error(f"request hook error: {e}")
        _safe_log({"type": "hook_error", "err": str(e)})

# state for UA de-duplication
UA_QUEUE = deque(maxlen=100)
