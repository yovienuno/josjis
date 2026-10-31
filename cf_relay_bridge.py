#!/usr/bin/env python3
"""TCP -> WebSocket bridge for a Cloudflare stratum relay.

Seine (and most stratum miners) only understands raw TCP. This script listens
on a local TCP port and forwards each miner connection to a Cloudflare Worker
over WebSocket. The Worker opens the real TCP connection to the pool.

It uses only the Python standard library.

Examples:
    # Run the bridge (normally started by a.sh)
    python3 cf_relay_bridge.py \
        --listen 127.0.0.1:33333 \
        --relay wss://worker.example.workers.dev/bntpool \
        --target bntpool.com:3333

    # Verify that the Worker can reach the pool, without mining
    python3 cf_relay_bridge.py --check \
        --relay wss://worker.example.workers.dev/bntpool \
        --target bntpool.com:3333

The Worker must expose a ?probe=1 mode for --check (relay-worker.js does).
"""

import argparse
import base64
import hashlib
import json
import os
import re
import select
import signal
import socket
import ssl
import struct
import sys
import threading
import time

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_HTTP_HEADER_BYTES = 64 * 1024


def log(message):
    print(f"[{time.strftime('%F %T')}] [bridge] {message}", flush=True)


def log_error(message):
    print(f"[{time.strftime('%F %T')}] [bridge] ERROR: {message}", file=sys.stderr, flush=True)


class ConnectionClosed(Exception):
    pass


class ProtocolError(Exception):
    pass


def parse_target(value):
    """Parse host:port, [v6]:port, or stratum+tcp://host:port."""
    text = value.strip()
    if text.startswith("stratum+tcp://"):
        text = text[len("stratum+tcp://"):]

    match = re.match(r"^(\[[^\]]+\]|[^:]+):(\d+)$", text)
    if not match:
        raise argparse.ArgumentTypeError(
            f"expected host:port or stratum+tcp://host:port, got {value!r}"
        )

    host = match.group(1)
    port = int(match.group(2))
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"invalid target {value!r}")
    return host, port


def parse_listen(value):
    """Parse host:port. A bare port binds 127.0.0.1."""
    text = value.strip()
    if text.isdigit():
        text = f"127.0.0.1:{text}"

    match = re.match(r"^(\[[^\]]+\]|[^:]+):(\d+)$", text)
    if not match:
        raise argparse.ArgumentTypeError(
            f"expected host:port (for example 127.0.0.1:33333), got {value!r}"
        )

    host = match.group(1)
    port = int(match.group(2))
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"invalid listen address {value!r}")
    return host, port


def parse_ws_url(value):
    """Parse ws:// or wss:// URL into (scheme, host, port, path_with_query)."""
    match = re.match(
        r"^(ws|wss)://(\[[^\]]+\]|[^:/]+)(?::(\d+))?(/[^\s]*)?$",
        value.strip(),
        re.IGNORECASE,
    )
    if not match:
        raise argparse.ArgumentTypeError(f"invalid WebSocket URL {value!r}")

    scheme = match.group(1).lower()
    host = match.group(2)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    port = int(match.group(3)) if match.group(3) else (443 if scheme == "wss" else 80)
    path = match.group(4) or "/"
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"invalid port in {value!r}")
    return scheme, host, port, path


def add_query(url, key, value):
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{key}={value}"


def close_socket(sock, shutdown=False):
    if sock is None:
        return
    if shutdown:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    try:
        sock.close()
    except OSError:
        pass


class WSConn:
    """Minimal RFC 6455 client connection."""

    def __init__(self, sock, initial=b""):
        self.sock = sock
        self.buffer = bytearray(initial)
        self.send_lock = threading.Lock()

    def _recv_exact(self, count):
        while len(self.buffer) < count:
            try:
                chunk = self.sock.recv(max(4096, count - len(self.buffer)))
            except ssl.SSLError as exc:
                raise ConnectionError(f"TLS read failed: {exc}") from exc
            if not chunk:
                raise ConnectionClosed("WebSocket closed by peer")
            self.buffer.extend(chunk)

        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def _read_frame(self):
        header = self._recv_exact(2)
        first, second = header[0], header[1]

        fin = bool(first & 0x80)
        if first & 0x70:
            raise ProtocolError("reserved WebSocket bits are set")
        opcode = first & 0x0F

        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_exact(8))[0]
            if length & (1 << 63):
                raise ProtocolError("invalid WebSocket payload length")

        if length > MAX_FRAME_BYTES:
            raise ProtocolError(f"WebSocket frame too large ({length} bytes)")

        if opcode >= 0x8:
            if not fin:
                raise ProtocolError("fragmented control frame")
            if length > 125:
                raise ProtocolError("control frame payload too large")

        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(length) if length else b""
        if mask:
            payload = bytes(byte ^ mask[index & 3] for index, byte in enumerate(payload))

        return fin, opcode, payload

    def recv_message(self):
        fragments = []
        message_opcode = None
        total = 0

        while True:
            fin, opcode, payload = self._read_frame()

            if opcode == 0x9:  # ping
                self.send_frame(payload, 0xA)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode == 0x8:  # close
                code = None
                reason = ""
                if len(payload) >= 2:
                    code = struct.unpack(">H", payload[:2])[0]
                    reason = payload[2:].decode("utf-8", "replace")
                try:
                    self.send_frame(payload[:125], 0x8)
                except Exception:
                    pass
                detail = f"WebSocket closed (code={code}, reason={reason!r})"
                raise ConnectionClosed(detail)

            if opcode in (0x1, 0x2):
                if message_opcode is not None:
                    raise ProtocolError("new data frame while a message was fragmented")
                message_opcode = opcode
                fragments = [payload]
                total = len(payload)
            elif opcode == 0x0:
                if message_opcode is None:
                    raise ProtocolError("unexpected continuation frame")
                fragments.append(payload)
                total += len(payload)
                if total > MAX_FRAME_BYTES:
                    raise ProtocolError(f"WebSocket message too large ({total} bytes)")
            else:
                raise ProtocolError(f"unsupported WebSocket opcode 0x{opcode:x}")

            if fin:
                return message_opcode, b"".join(fragments)

    def send_frame(self, payload, opcode=0x2):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        length = len(payload)
        header = bytearray([0x80 | opcode])

        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack(">H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack(">Q", length))

        mask = os.urandom(4)
        header.extend(mask)
        masked = bytes(byte ^ mask[index & 3] for index, byte in enumerate(payload))

        with self.send_lock:
            self.sock.sendall(bytes(header) + masked)

    def send_binary(self, payload):
        self.send_frame(payload, 0x2)

    def close(self):
        try:
            self.send_frame(b"", 0x8)
        except Exception:
            pass
        close_socket(self.sock)


def ws_connect(relay_url, target, connect_timeout=10.0, insecure=False):
    """Open a WebSocket to the Worker and send the JSON target handshake."""
    scheme, host, port, path = parse_ws_url(relay_url)
    target_host, target_port = target

    raw = socket.create_connection((host, port), timeout=connect_timeout)
    try:
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass

    if scheme == "wss":
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            sock = context.wrap_socket(raw, server_hostname=host)
        except Exception:
            close_socket(raw)
            raise
    else:
        sock = raw

    try:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        host_header = host if port in (80, 443) else f"{host}:{port}"
        if ":" in host and not host.startswith("["):
            host_header = f"[{host}]" if port in (80, 443) else f"[{host}]:{port}"

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"User-Agent: seine-cf-relay/1.0\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode("ascii"))

        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("WebSocket handshake failed: connection closed")
            response.extend(chunk)
            if len(response) > MAX_HTTP_HEADER_BYTES:
                raise ConnectionError("WebSocket handshake failed: response headers too large")

        header_bytes, leftover = bytes(response).split(b"\r\n\r\n", 1)
        lines = header_bytes.split(b"\r\n")
        status_line = lines[0].decode("latin-1", "replace")
        if " 101 " not in f"{status_line} ":
            body = leftover.decode("latin-1", "replace").strip()
            detail = f"{status_line} {body}".strip()
            raise ConnectionError(f"WebSocket handshake rejected: {detail}")

        headers = {}
        for line in lines[1:]:
            if b":" not in line:
                continue
            name, value = line.split(b":", 1)
            headers[name.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()

        expected = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            raise ConnectionError("WebSocket handshake failed: bad Sec-WebSocket-Accept")

        conn = WSConn(sock, initial=leftover)
        payload = json.dumps(
            {"host": target_host, "port": target_port},
            separators=(",", ":"),
        ).encode("utf-8")
        conn.send_frame(payload, 0x1)
        return conn
    except Exception:
        close_socket(sock)
        raise


def run_check(args):
    url = add_query(args.relay, "probe", "1")
    log(f"checking relay: {args.relay} -> {args.target[0]}:{args.target[1]}")
    conn = None
    try:
        conn = ws_connect(
            url,
            args.target,
            connect_timeout=args.connect_timeout,
            insecure=args.insecure,
        )
        conn.sock.settimeout(args.check_timeout)

        while True:
            opcode, payload = conn.recv_message()
            if opcode == 0x1:
                text = payload.decode("utf-8", "replace").strip()
                if text == "[RELAY] connected":
                    log("relay check OK: Worker reached the pool")
                    return 0
                if text.startswith("[RELAY]"):
                    log_error(f"relay check FAILED: {text}")
                    return 1
                if text:
                    log(f"relay said: {text}")
                continue

            # Any pool bytes also prove the TCP path works.
            log(f"relay check OK: pool sent {len(payload)} bytes")
            return 0
    except socket.timeout:
        log_error(
            "relay check FAILED: timed out waiting for the Worker. "
            "Is relay-worker.js deployed with ?probe=1 support?"
        )
        return 1
    except Exception as exc:
        log_error(f"relay check FAILED: {exc}")
        return 1
    finally:
        if conn is not None:
            conn.close()


def configure_tcp(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


def handle_client(client_sock, args):
    try:
        peer = client_sock.getpeername()
    except OSError:
        peer = "unknown"

    configure_tcp(client_sock)
    log(f"client {peer} -> {args.target[0]}:{args.target[1]} via {args.relay}")

    conn = None
    last_error = None
    for attempt in range(1, args.retries + 1):
        try:
            conn = ws_connect(
                args.relay,
                args.target,
                connect_timeout=args.connect_timeout,
                insecure=args.insecure,
            )
            # create_connection() leaves its connect timeout on the socket.
            # A live stratum connection can be idle for more than that between
            # jobs, so clear it or the bridge drops the pool every timeout.
            conn.sock.settimeout(None)
            break
        except Exception as exc:
            last_error = exc
            log_error(f"relay connect {attempt}/{args.retries} failed: {exc}")
            if attempt < args.retries:
                time.sleep(args.retry_delay)

    if conn is None:
        log_error(f"giving up on {peer}: {last_error}")
        close_socket(client_sock)
        return

    stop = threading.Event()

    def relay_to_tcp():
        try:
            while not stop.is_set():
                opcode, payload = conn.recv_message()
                if opcode == 0x1:
                    text = payload.decode("utf-8", "replace").strip()
                    if text:
                        log(f"relay: {text}")
                    if text.startswith("[RELAY]"):
                        break
                    continue
                if payload:
                    client_sock.sendall(payload)
        except Exception as exc:
            if not stop.is_set():
                log_error(f"relay -> tcp: {exc}")
        finally:
            stop.set()
            close_socket(conn.sock)
            close_socket(client_sock, shutdown=True)

    reader_thread = threading.Thread(target=relay_to_tcp, daemon=True)
    reader_thread.start()

    try:
        while not stop.is_set():
            data = client_sock.recv(65536)
            if not data:
                break
            conn.send_binary(data)
    except Exception as exc:
        if not stop.is_set():
            log_error(f"tcp -> relay: {exc}")
    finally:
        stop.set()
        close_socket(client_sock, shutdown=True)
        close_socket(conn.sock)
        reader_thread.join(timeout=2)
        log(f"client {peer} closed")


def serve(args):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(args.listen)
        listener.listen(128)
        listener.settimeout(1.0)
    except OSError:
        close_socket(listener)
        raise

    stop = threading.Event()

    def request_stop(signum, _frame):
        log(f"received signal {signum}; stopping")
        stop.set()
        close_socket(listener)

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    log(
        f"listening on {args.listen[0]}:{args.listen[1]} -> "
        f"{args.target[0]}:{args.target[1]} via {args.relay}"
    )

    while not stop.is_set():
        try:
            client_sock, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            if stop.is_set():
                break
            raise

        thread = threading.Thread(
            target=handle_client,
            args=(client_sock, args),
            daemon=True,
        )
        thread.start()

    close_socket(listener)
    log("stopped")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="TCP <-> WebSocket bridge for a Cloudflare stratum relay.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--relay",
        required=True,
        help="Cloudflare Worker WebSocket URL, e.g. wss://worker.dev/bntpool",
    )
    parser.add_argument(
        "--target",
        required=True,
        type=parse_target,
        help="pool host:port behind the Worker, e.g. bntpool.com:3333",
    )
    parser.add_argument(
        "--listen",
        type=parse_listen,
        default=("127.0.0.1", 33333),
        help="local TCP listen address",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="probe the Worker -> pool path and exit",
    )
    parser.add_argument(
        "--check-timeout",
        type=float,
        default=15.0,
        help="seconds to wait for the check result",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=10.0,
        help="seconds for TCP/TLS/WebSocket setup",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="WebSocket connect attempts per miner connection",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=1.0,
        help="seconds between WebSocket connect attempts",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS certificate verification (testing only)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.retries < 1:
        parser.error("--retries must be at least 1")
    if args.retry_delay < 0:
        parser.error("--retry-delay cannot be negative")
    if args.check_timeout <= 0 or args.connect_timeout <= 0:
        parser.error("timeouts must be positive")

    try:
        if args.check:
            return run_check(args)
        return serve(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        log_error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
