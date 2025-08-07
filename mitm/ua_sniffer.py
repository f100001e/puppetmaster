#!/usr/bin/env python
"""
ua_sniffer.py  –  mitmproxy addon
• Listens (mitmproxy -p 9999 -s ua_sniffer.py)
• Rewrites all traffic → scanner/UI at localhost:8888
• Posts UA + URL to backend /log_ua  &  emits over Socket-IO
"""
from mitmproxy import http, ctx
import socketio, requests, os, time, hashlib, json, threading
from threading import Lock
from collections   import deque
from typing        import Dict, Any, Optional
from dotenv        import load_dotenv
import uuid, socket, sys, traceback

# ────────────────────────────────────────────────
# 0)  env & constants
# ────────────────────────────────────────────────
load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))

PROXY_TARGET        = os.getenv("PROXY_HOST",   "localhost")   # scanner/UI host
PROXY_PORT          = int(os.getenv("PROXY_PORT", 8888))       # scanner/UI port
BACKEND_HTTP_URL    = os.getenv("BACKEND_HTTP_URL",   "http://localhost:3000/log_ua")
BACKEND_SOCKET_URL  = os.getenv("BACKEND_URL",        "http://localhost:3000").rstrip("/")
NAMESPACE           = "/scanner"

MAX_REQUESTS_PER_SEC = 50
MAX_UA_LENGTH        = 1024
BYPASS_DOMAINS       = {"google.com", "cloudflare.com", "mitm.it"}

# ────────────────────────────────────────────────
# 1)  state
# ────────────────────────────────────────────────
UA_QUEUE       = deque(maxlen=100)
UA_LOCK        = Lock()

# ────────────────────────────────────────────────
# 2)  helpers
# ────────────────────────────────────────────────
def _forward_to_scanner(flow: http.HTTPFlow) -> None:
    """Re-target request to the scanner UI on localhost:8888"""
    flow.request.host = PROXY_TARGET
    flow.request.port = PROXY_PORT
    ctx.log.info(f"→ forward → {PROXY_TARGET}:{PROXY_PORT}")

def _http_post_ua(ua: str, url: str) -> None:
    try:
        r = requests.post(
            BACKEND_HTTP_URL,
            json={"ua": ua, "url": url},
            timeout=2,
            headers={"Content-Type": "application/json"}
        )
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
    except Exception as e:
        ctx.log.error(f"POST /log_ua failed: {e}")
        _safe_log({"type":"http_fail","ua":ua[:80],"url":url,"err":str(e)})

def _safe_log(payload: Dict[str, Any]) -> None:
    """Atomic fallback log—never throws"""
    try:
        logdir = os.path.expanduser("~/WebstormProjects/Puppetmaster/gtag_logs")
        os.makedirs(logdir, exist_ok=True)
        fname = os.path.join(
            logdir, f"mitm_{int(time.time())}_{uuid.uuid4().hex[:6]}.json")
        with open(fname, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(), "data": payload}, f, indent=2)
    except Exception as e:
        sys.stderr.write(f"EMERG-LOG-FAIL {e}\n")

# ────────────────────────────────────────────────
# 3)  Socket-IO (backend push)
# ────────────────────────────────────────────────
class SockClient:
    def __init__(self):
        self.sio = socketio.Client(
            reconnection=True, reconnection_attempts=5,
            reconnection_delay=1, reconnection_delay_max=30,
            logger=bool(os.getenv("DEBUG")))
        self.lock = Lock()
        self.connected = False
        self._bind_events()
        self._connect()

    def _bind_events(self):
        @self.sio.event
        def connect():    self.connected=True;  ctx.log.info("Socket.IO ✓ connected")
        @self.sio.event
        def disconnect(): self.connected=False; ctx.log.warn("Socket.IO ✕ disconnected")

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
                headers={
                    'Origin': BACKEND_SOCKET_URL,
                    'X-MITM-Node': socket.gethostname()
                }
            )
            return  # success
        except Exception as e:
            ctx.log.error(f"connect fail: {e}")
            time.sleep(2 ** n)      # exponential back-off

    def emit(self, event: str, data: Any):
        with self.lock:
            if self.connected:
                try:    self.sio.emit(event, data, namespace=NAMESPACE)
                except Exception as e:
                    self.connected=False; ctx.log.error(f"emit fail: {e}")

sock = SockClient()

# ────────────────────────────────────────────────
# 4)  mitmproxy hooks
# ────────────────────────────────────────────────
def request(flow: http.HTTPFlow):
    try:
        # bypass certain hosts
        if (any(d in flow.request.host for d in BYPASS_DOMAINS)
                or flow.request.host in {"localhost","127.0.0.1"}):
            return

        # always forward to scanner
        _forward_to_scanner(flow)

        ua  = (flow.request.headers.get("User-Agent","") or "NO_UA")[:MAX_UA_LENGTH]
        url = flow.request.pretty_url

        def handle():
            _http_post_ua(ua, url)
            with UA_LOCK:
                h = hashlib.sha256(ua.encode()).hexdigest()
                if h not in UA_QUEUE:
                    UA_QUEUE.append(h)
                    sock.emit("ua_data", {
                        "ua": ua, "url": url,
                        "ts": int(time.time()*1000),
                        "src_ip": flow.client_conn.peername[0]
                                  if flow.client_conn else None
                    })
        threading.Thread(target=handle, daemon=True).start()

    except Exception as e:
        ctx.log.error(f"request hook error: {e}")
        _safe_log({"type":"hook_error","err":str(e)})

# ────────────────────────────────────────────────
# 5)  TLS prefs (optional hardening)
# ────────────────────────────────────────────────
def configure_tls(settings):
    settings.tls_version_client_min = "TLS1_2"
    settings.tls_version_server_min = "TLS1_2"

addons = [configure_tls]
