from mitmproxy import http, ctx  # type: ignore
import socketio
import requests
import os
import time
import hashlib
import json
from collections import deque
import threading
from threading import Lock
from typing import Dict, Any, Optional
from dotenv import load_dotenv
import uuid
import socket
import sys
import traceback

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../.env'))

# --------------------------------------------------------------------------- #
# 0) Critical Constants                                                       #
# --------------------------------------------------------------------------- #
PROXY_TARGET = os.getenv("PROXY_HOST", "192.168.0.215")
PROXY_PORT = int(os.getenv("PROXY_PORT", 8081))
BACKEND_HTTP_URL = os.getenv("BACKEND_HTTP_URL", "http://localhost:3000/log_ua")
BACKEND_SOCKET_URL = os.getenv("BACKEND_URL", "http://localhost:3000").rstrip("/")
NAMESPACE = "/scanner"
MAX_REQUESTS_PER_SECOND = 50
MAX_UA_LENGTH = 1024
BYPASS_DOMAINS = {'google.com', 'cloudflare.com', 'mitm.it'}

# --------------------------------------------------------------------------- #
# 1) State Management                                                         #
# --------------------------------------------------------------------------- #
UA_QUEUE = deque(maxlen=100)
UA_LOCK = Lock()
LAST_EMIT_TIME = 0
HEARTBEAT_THREAD: Optional[threading.Thread] = None

# --------------------------------------------------------------------------- #
# 2) Core Utilities                                                           #
# --------------------------------------------------------------------------- #
def _forward_to_scanner(flow: http.HTTPFlow) -> None:
    """Rewrite destination to scanner"""
    if any(domain in flow.request.host for domain in BYPASS_DOMAINS):
        return

    flow.request.host = PROXY_TARGET
    flow.request.port = PROXY_PORT
    ctx.log.info(f"Forwarding to scanner at {PROXY_TARGET}:{PROXY_PORT}")

def _http_post_ua(ua: str, url: str) -> None:
    """HTTP POST to backend"""
    try:
        response = requests.post(
            BACKEND_HTTP_URL,
            json={"ua": ua, "url": url},
            timeout=2,
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}")
    except Exception as e:
        ctx.log.error(f"HTTP POST failed: {str(e)}")
        _fallback_log({"type": "http_fail", "ua": ua[:50], "url": url, "error": str(e)})

def _fallback_log(payload: Dict[str, Any]) -> None:
    """Guaranteed atomic logging with rotation handling"""
    log_dir = os.path.expanduser("~/WebstormProjects/Puppetmaster/gtag_logs")
    try:
        # 1. Ensure directory exists with proper permissions
        os.makedirs(log_dir, exist_ok=True)
        os.chmod(log_dir, 0o755)  # Explicit permissions

        # 2. Atomic write pattern
        temp_path = os.path.join(log_dir, f"temp_{os.getpid()}.json")
        final_path = os.path.join(log_dir, f"mitm_{int(time.time())}_{uuid.uuid4().hex[:8]}.json")

        # 3. Structured data with error context
        log_data = {
            "timestamp": time.time(),
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "data": payload
        }

        # 4. Write to temporary file first
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        # 5. Atomic rename
        os.rename(temp_path, final_path)

        # 6. Verify write
        if not os.path.exists(final_path):
            raise IOError("Atomic write failed")

    except Exception as e:
        # 7. Last-resort logging
        sys.stderr.write(f"CRITICAL LOG FAILURE: {str(e)}\n")
        sys.stderr.flush()

        # 8. Emergency fallback
        with open("/tmp/mitm_emergency.log", "a") as ef:
            ef.write(f"{time.time()}|{json.dumps(payload)}\n")
def _connect() -> None:
    """Robust Socket.IO connection with retry logic"""
    max_retries = 3
    backoff_factor = 1.5

    for attempt in range(max_retries):
        try:
            if not sio.connected:
                ctx.log.info(f"Connection attempt {attempt + 1}/{max_retries}")
                sio.connect(
                    BACKEND_SOCKET_URL,
                    namespaces=[NAMESPACE],
                    transports=['websocket'],
                    headers={
                        'Origin': BACKEND_SOCKET_URL,
                        'X-MITM-Node': socket.gethostname()
                    },
                    wait_timeout=10 + attempt * 2  # Increasing timeout
                )
                return  # Success

        except socketio.exceptions.ConnectionError as ce:
            ctx.log.error(f"Socket.IO connection error: {str(ce)}")
            if attempt == max_retries - 1:
                _fallback_log({
                    "type": "socketio_connect_fail",
                    "error": str(ce),
                    "attempt": attempt,
                    "backoff": f"{backoff_factor ** attempt:.1f}s"
                })
            time.sleep(backoff_factor ** attempt)

        except Exception as e:
            ctx.log.error(f"Unexpected connection error: {str(e)}")
            _fallback_log({
                "type": "socketio_unexpected_error",
                "error": str(e),
                "stack": traceback.format_exc()
            })
            break
# --------------------------------------------------------------------------- #
# 3) Socket.IO Setup                                                          #
# --------------------------------------------------------------------------- #
sio = socketio.Client(
    reconnection=True,
    reconnection_attempts=5,
    reconnection_delay=1,
    reconnection_delay_max=30,
    randomization_factor=0.5,
    logger=bool(os.getenv("DEBUG"))
)

@sio.event
def connect():
    ctx.log.info("Connected to Socket.IO server")

@sio.event
def disconnect():
    ctx.log.warn("Disconnected from Socket.IO server")

def _heartbeat() -> None:
    """Maintain Socket.IO connection"""
    retry_count = 0
    max_retries = 10

    while retry_count < max_retries:
        if not sio.connected:
            try:
                _connect()
                time.sleep(min(30, 2 ** retry_count))
                retry_count += 1
            except Exception as e:
                ctx.log.error(f"Reconnect failed: {str(e)}")
        else:
            time.sleep(30)
            retry_count = 0

    if retry_count >= max_retries:
        ctx.log.error("Max reconnection attempts reached")

# --------------------------------------------------------------------------- #
# 4) mitmproxy Hooks                                                         #
# --------------------------------------------------------------------------- #
def request(flow: http.HTTPFlow) -> None:
    try:
        if any(domain in flow.request.host for domain in BYPASS_DOMAINS):
            return

        _forward_to_scanner(flow)
        ua = (flow.request.headers.get("User-Agent", "") or "NO_UA").strip()[:MAX_UA_LENGTH]
        url = flow.request.pretty_url

        _http_post_ua(ua, url)

        with UA_LOCK:
            ua_hash = hashlib.sha256(ua.encode()).hexdigest()
            if ua_hash not in UA_QUEUE:
                UA_QUEUE.append(ua_hash)
                sio.emit('ua_data', {
                    "ua": ua,
                    "url": url,
                    "ts": int(time.time() * 1000),
                    "src_ip": flow.client_conn.peername[0] if flow.client_conn else None
                }, namespace=NAMESPACE)

    except Exception as e:
        ctx.log.error(f"Request processing failed: {str(e)}")
        _fallback_log({"type": "request_error", "error": str(e)})

def load(loader) -> None:
    """Initialize on startup"""
    if not all([PROXY_PORT, BACKEND_HTTP_URL, BACKEND_SOCKET_URL]):
        raise ValueError("Missing critical environment variables")

    global HEARTBEAT_THREAD
    HEARTBEAT_THREAD = threading.Thread(target=_heartbeat, daemon=True)
    HEARTBEAT_THREAD.start()

def done() -> None:
    """Cleanup on shutdown"""
    if sio.connected:
        sio.disconnect()
    if HEARTBEAT_THREAD:
        HEARTBEAT_THREAD.join(timeout=1)

# --------------------------------------------------------------------------- #
# 5) TLS Configuration                                                        #
# --------------------------------------------------------------------------- #
def configure_tls(settings):
    settings.tls_version_client_min = "TLS1_2"
    settings.tls_version_server_min = "TLS1_2"
    settings.ciphers_client = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    settings.ciphers_server = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"

addons = [configure_tls]