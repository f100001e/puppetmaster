#!/usr/bin/env python
"""
ua_sniffer.py – mitmproxy addon

- Run:  mitmdump -s mitm/ua_sniffer.py -p 9999 --listen-host 127.0.0.1 \
                 --ssl-insecure --set tls_version_client_min=TLS1_2 \
                 --set tls_version_server_min=TLS1_2
- Captures proxied requests, extracts User-Agent + URL,
  posts to backend /log_ua, and emits Socket.IO events to /scanner.
- Skips localhost and a small allowlist of noisy/external domains.
- Analyzes certificate validation behavior for threat detection.
"""

from mitmproxy import http, ctx
import socketio, requests, os, time, hashlib, json, threading
from threading import Lock
from collections import deque
from typing import Dict, Any, Tuple
from dotenv import load_dotenv
import uuid, socket, sys, ssl
from pathlib import Path

# ────────────────────────────────────────────────
# 0) env, paths, constants
# ────────────────────────────────────────────────
load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))

LOG_DIR = Path(os.getenv("GTAG_LOG_DIR", "~/WebstormProjects/Puppetmaster/gtag_logs")).expanduser()
LOG_DIR.mkdir(parents=True, exist_ok=True)

SCANNER_HTTP_URL   = os.getenv("SCANNER_HTTP_URL",  "https://localhost:8888/analyze")
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

# Certificate validation behavior scoring
CERT_BEHAVIOR_SCORES = {
    "validates_certs": 0,        # Normal, security-conscious behavior
    "ignores_certs": 30,         # Suspicious, potential automated tool
    "connection_failed": 15,     # Network issue, moderate suspicion
    "cert_expired": 20,          # Accepts expired certs, concerning
    "cert_self_signed": 25,      # Accepts self-signed, very suspicious
    "cert_hostname_mismatch": 35 # Ignores hostname validation, very bad
}

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

def _analyze_cert_behavior(ua: str, url: str) -> Tuple[str, int]:
    """
    Test certificate validation behavior to detect potentially malicious clients.
    Returns (behavior_type, additional_risk_score)
    """
    if not url.startswith("https://"):
        return "non_https", 0

    behavior = "unknown"
    additional_risk = 0

    try:
        # First: Try with proper certificate verification
        r = requests.head(
            "https://httpbin.org/status/200",  # Known good endpoint for testing
            timeout=3,
            verify=True,
            headers={"User-Agent": ua},
            proxies={"http": None, "https": None}
        )
        if r.status_code == 200:
            behavior = "validates_certs"
            additional_risk = CERT_BEHAVIOR_SCORES[behavior]

    except requests.exceptions.SSLError as ssl_err:
        ssl_error_str = str(ssl_err).lower()

        # Categorize different types of SSL errors
        if "certificate verify failed" in ssl_error_str:
            if "certificate has expired" in ssl_error_str:
                behavior = "cert_expired"
            elif "self signed certificate" in ssl_error_str:
                behavior = "cert_self_signed"
            elif "hostname" in ssl_error_str or "doesn't match" in ssl_error_str:
                behavior = "cert_hostname_mismatch"
            else:
                behavior = "cert_validation_failed"

        # Now test if client would accept invalid certificates
        try:
            r = requests.head(
                "https://httpbin.org/status/200",
                timeout=3,
                verify=False,  # Disable certificate verification
                headers={"User-Agent": ua},
                proxies={"http": None, "https": None}
            )
            if r.status_code == 200:
                # Client accepts invalid certificates - suspicious
                behavior = "ignores_certs"
                additional_risk = CERT_BEHAVIOR_SCORES[behavior]
        except Exception:
            behavior = "connection_failed"
            additional_risk = CERT_BEHAVIOR_SCORES[behavior]

    except requests.exceptions.ConnectTimeout:
        behavior = "connection_timeout"
        additional_risk = 5
    except requests.exceptions.ConnectionError:
        behavior = "connection_failed"
        additional_risk = CERT_BEHAVIOR_SCORES[behavior]
    except Exception as e:
        behavior = f"unknown_error_{type(e).__name__}"
        additional_risk = 10

    return behavior, additional_risk

def _http_post_ua(ua: str, url: str) -> None:
    """Send UA data to scanner for analysis instead of directly to backend."""
    try:
        # Analyze certificate validation behavior
        cert_behavior, cert_risk = _analyze_cert_behavior(ua, url)

        # Prepare enhanced payload for scanner
        payload = {
            "ua": ua,
            "url": url,
            "cert_behavior": cert_behavior,
            "cert_risk_bonus": cert_risk,
            "analysis_timestamp": time.time()
        }

        r = requests.post(
            SCANNER_HTTP_URL,  # Send to scanner instead of backend
            json=payload,
            timeout=2,
            headers={"Content-Type": "application/json"},
            proxies={"http": None, "https": None},
            verify=False  # Scanner uses self-signed cert
        )
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")

        # Log certificate behavior for analysis
        if cert_behavior != "validates_certs":
            ctx.log.warn(f"Suspicious cert behavior: {cert_behavior} for UA: {ua[:50]}...")

    except Exception as e:
        ctx.log.error(f"POST to scanner failed: {e}")
        _safe_log({
            "type": "scanner_fail",
            "ua": ua[:80],
            "url": url,
            "cert_behavior": cert_behavior if 'cert_behavior' in locals() else "unknown",
            "err": str(e)
        })

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
    ctx.log.info("ua_sniffer loaded with certificate behavior analysis")

def request(flow: http.HTTPFlow):
    try:
        if host_in_bypass(flow.request.host):
            return

        ua  = (flow.request.headers.get("User-Agent", "") or "NO_UA")[:MAX_UA_LENGTH]
        url = flow.request.pretty_url

        # Extract additional connection metadata
        client_conn = flow.client_conn
        client_ip = client_conn.peername[0] if client_conn else "unknown"

        # Check for suspicious TLS characteristics
        tls_suspicious = False
        tls_info = {}

        if client_conn and hasattr(client_conn, 'tls_established') and client_conn.tls_established:
            try:
                # Extract TLS version and cipher info
                if hasattr(client_conn, 'cipher'):
                    tls_info["cipher"] = client_conn.cipher
                if hasattr(client_conn, 'tls_version'):
                    tls_info["tls_version"] = client_conn.tls_version
                    # Flag very old TLS versions as suspicious
                    if client_conn.tls_version in ["TLSv1", "TLSv1.1"]:
                        tls_suspicious = True
            except:
                pass

        def handle():
            # Perform certificate behavior analysis
            _http_post_ua(ua, url)

            # Enhanced deduplication with certificate behavior
            h = hashlib.sha256(f"{ua}:{url}:{client_ip}".encode()).hexdigest()

            if h not in UA_QUEUE:
                UA_QUEUE.append(h)

                # Enhanced Socket.IO event with additional metadata
                sock.emit("uaUpdate", {
                    "ua": ua,
                    "url": url,
                    "ts": int(time.time() * 1000),
                    "src_ip": client_ip,
                    "tls_info": tls_info,
                    "tls_suspicious": tls_suspicious,
                    "request_method": flow.request.method,
                    "content_type": flow.request.headers.get("Content-Type", ""),
                    "host": flow.request.host,
                    "scheme": flow.request.scheme
                })

        threading.Thread(target=handle, daemon=True).start()

    except Exception as e:
        ctx.log.error(f"request hook error: {e}")
        _safe_log({"type": "hook_error", "err": str(e)})

def response(flow: http.HTTPFlow):
    """Analyze response patterns for additional threat intelligence."""
    try:
        if host_in_bypass(flow.request.host):
            return

        ua = (flow.request.headers.get("User-Agent", "") or "NO_UA")[:MAX_UA_LENGTH]

        # Check for suspicious response patterns
        response_suspicious = False
        response_indicators = []

        if flow.response:
            status_code = flow.response.status_code

            # Flag unusual status code patterns
            if status_code in [418, 444, 999]:  # Unusual codes sometimes used by security tools
                response_suspicious = True
                response_indicators.append(f"unusual_status_{status_code}")

            # Check response headers for automation indicators
            headers = flow.response.headers
            server_header = headers.get("Server", "").lower()

            # Common automation/scanning tool server headers
            automation_indicators = ["python", "curl", "wget", "scanner", "bot", "crawler"]
            for indicator in automation_indicators:
                if indicator in server_header:
                    response_suspicious = True
                    response_indicators.append(f"automation_server_{indicator}")
                    break

        # Log suspicious response patterns
        if response_suspicious:
            _safe_log({
                "type": "suspicious_response",
                "ua": ua[:80],
                "url": flow.request.pretty_url,
                "indicators": response_indicators,
                "status_code": flow.response.status_code if flow.response else None,
                "ts": time.time()
            })

    except Exception as e:
        ctx.log.error(f"response hook error: {e}")

# ────────────────────────────────────────────────
# 5) state management
# ────────────────────────────────────────────────
UA_QUEUE = deque(maxlen=100)

# Statistics tracking
STATS = {
    "total_requests": 0,
    "cert_validators": 0,
    "cert_ignorers": 0,
    "connection_failures": 0,
    "suspicious_responses": 0
}

def get_stats() -> Dict[str, Any]:
    """Return current statistics for monitoring."""
    return dict(STATS)

# Add stats tracking to the main request handler
def _original_handle():
    STATS["total_requests"] += 1

ctx.log.info("Enhanced ua_sniffer ready with certificate behavior analysis")