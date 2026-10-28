"""Black-box protocol tests; all traffic and backends stay on loopback."""
import base64
import concurrent.futures
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest


BINARY = Path(os.environ.get("GOST_C_BINARY", "build/gost-c")).resolve()


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError(f"Expected {count} bytes, received {len(data)}")
        data.extend(part)
    return bytes(data)


def address(host, port, domain=False):
    if domain:
        return b"\x03" + bytes([len(host)]) + host.encode() + struct.pack("!H", port)
    try:
        raw = socket.inet_pton(socket.AF_INET, host)
        return b"\x01" + raw + struct.pack("!H", port)
    except OSError:
        pass
    try:
        raw = socket.inet_pton(socket.AF_INET6, host)
        return b"\x04" + raw + struct.pack("!H", port)
    except OSError:
        return b"\x03" + bytes([len(host)]) + host.encode() + struct.pack("!H", port)


def read_address(sock, kind):
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, exact(sock, 4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
    elif kind == 3:
        host = exact(sock, exact(sock, 1)[0]).decode()
    else:
        raise AssertionError(f"Bad SOCKS address type {kind}")
    return host, struct.unpack("!H", exact(sock, 2))[0]


def socks_request(sock, host, port, credentials=None, cmd=1, fragmented=False):
    greeting = b"\x05\x01" + (b"\x02" if credentials else b"\x00")
    sock.sendall(greeting)
    expected = 2 if credentials else 0
    if exact(sock, 2) != bytes([5, expected]):
        raise AssertionError("SOCKS negotiation failed")
    if credentials:
        user, password = (s.encode() for s in credentials)
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        if exact(sock, 2) != b"\x01\x00":
            raise PermissionError("SOCKS authentication failed")
    request = bytes([5, cmd, 0]) + address(host, port)
    if fragmented:
        for c in request:
            sock.sendall(bytes([c]))
    else:
        sock.sendall(request)
    reply = exact(sock, 4)
    bound = read_address(sock, reply[3])
    return reply[1], bound


class Proxy:
    def __init__(self, *args, listeners=1):
        self.args = args
        self.listeners = listeners
        self.ports = []

    def __enter__(self):
        self.log = tempfile.TemporaryFile()
        self.process = subprocess.Popen([str(BINARY), *self.args], stdout=subprocess.DEVNULL, stderr=self.log)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.log.seek(0)
            text = self.log.read().decode(errors="replace")
            self.ports = [int(p) for p in re.findall(r"Listening \w+ on \[.*?\]:(\d+)", text)]
            if len(self.ports) == self.listeners:
                return self
            if self.process.poll() is not None:
                self.log.close()
                raise AssertionError(f"Proxy exited at startup: {text}")
            time.sleep(0.01)
        self.process.kill()
        self.process.wait()
        self.log.close()
        raise AssertionError("Proxy did not report readiness")

    def connect(self, index=0, host="127.0.0.1"):
        return socket.create_connection((host, self.ports[index]), timeout=5)

    def __exit__(self, typ, value, tb):
        self.process.terminate()
        try:
            result = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            self.log.close()
            raise AssertionError("Proxy failed to stop")
        self.log.seek(0)
        log = self.log.read().decode(errors="replace")
        self.log.close()
        if result != 0 or "ERROR: AddressSanitizer" in log or "runtime error:" in log:
            raise AssertionError(f"Proxy exited {result}: {log}")


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    max_packet_size = 65535


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except (OSError, TimeoutError):
            pass


class HalfClose(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        data = bytearray()
        while part := self.request.recv(65536):
            data.extend(part)
        self.request.sendall(bytes(data)[::-1])


class CaptureHTTP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(0.15)
        data = bytearray()
        try:
            while part := self.request.recv(65536):
                data.extend(part)
        except socket.timeout:
            pass
        self.request.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)


class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.reply(b"")

    def do_POST(self):
        if self.headers.get("Transfer-Encoding") == "chunked":
            body = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0], 16)
                if not size:
                    while self.rfile.readline() != b"\r\n":
                        pass
                    break
                body.extend(self.rfile.read(size))
                if self.rfile.read(2) != b"\r\n":
                    return
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.reply(body)

    def reply(self, body):
        payload = json.dumps({"path": self.path, "headers": dict(self.headers),
                              "body": base64.b64encode(body).decode()}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True


@contextlib.contextmanager
def backend(cls, handler, host="127.0.0.1"):
    server = cls((host, 0), handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def response(sock):
    result = http.client.HTTPResponse(sock)
    result.begin()
    return result, result.read()


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = contextlib.ExitStack()
        cls.http = cls.stack.enter_context(backend(http.server.ThreadingHTTPServer, HTTPHandler))
        cls.echo = cls.stack.enter_context(backend(TCPServer, Echo))
        cls.udp = cls.stack.enter_context(backend(UDPServer, UDPEcho))

    @classmethod
    def tearDownClass(cls):
        cls.stack.close()

    def test_http_absolute_uri_and_header_sanitization(self):
        with Proxy("-L", "http://user:pass@127.0.0.1:0") as proxy, proxy.connect() as sock:
            auth = base64.b64encode(b"user:pass").decode()
            sock.sendall((f"GET http://127.0.0.1:{self.http}/hello?q=yes HTTP/1.1\r\n"
                          f"Host: wrong.example\r\nProxy-Authorization: Basic {auth}\r\n"
                          "Proxy-Connection: keep-alive\r\nConnection: X-Hop, keep-alive\r\n"
                          "X-Hop: private\r\nX-End: public\r\n\r\n").encode())
            res, data = response(sock)
            self.assertEqual(res.status, 200)
            data = json.loads(data)
            self.assertEqual(data["path"], "/hello?q=yes")
            self.assertEqual(data["headers"]["Host"], f"127.0.0.1:{self.http}")
            for field in ("Proxy-Authorization", "Proxy-Connection", "X-Hop"):
                self.assertNotIn(field, data["headers"])
            self.assertEqual(data["headers"]["X-End"], "public")

    def test_http_auth_rejected(self):
        with Proxy("-L", "http://user:pass@127.0.0.1:0") as proxy:
            for header in ("", "Proxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n"):
                with proxy.connect() as sock:
                    sock.sendall((f"GET http://127.0.0.1:{self.http}/ HTTP/1.1\r\n{header}\r\n").encode())
                    res, _ = response(sock)
                    self.assertEqual(res.status, 407)
                    self.assertIn("Basic", res.getheader("Proxy-Authenticate"))

    def test_http_connect_preserves_early_payload(self):
        payload = bytes(range(256)) * 1024
        with Proxy("-L", "http://127.0.0.1:0") as proxy, proxy.connect() as sock:
            sock.sendall(f"CONNECT 127.0.0.1:{self.echo} HTTP/1.1\r\n\r\n".encode() + payload)
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(exact(sock, 1))
            self.assertIn(b"200 Connection Established", header)
            self.assertEqual(exact(sock, len(payload)), payload)

    def test_http_content_length_large_upload(self):
        payload = os.urandom(512 * 1024)
        with Proxy("-L", "http://127.0.0.1:0") as proxy, proxy.connect() as sock:
            sock.sendall((f"POST http://127.0.0.1:{self.http}/upload HTTP/1.1\r\n"
                          f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload)
            res, data = response(sock)
            self.assertEqual(res.status, 200)
            self.assertEqual(base64.b64decode(json.loads(data)["body"]), payload)

    def test_http_chunked_fragmented_upload(self):
        with Proxy("-L", "http://127.0.0.1:0") as proxy, proxy.connect() as sock:
            sock.sendall((f"POST http://127.0.0.1:{self.http}/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").encode())
            chunks = b"3;foo=bar\r\nabc\r\n5\r\ndefgh\r\n0\r\nX-Trailer: fine\r\n\r\n"
            for c in chunks:
                sock.sendall(bytes([c]))
            res, data = response(sock)
            self.assertEqual(res.status, 200)
            self.assertEqual(base64.b64decode(json.loads(data)["body"]), b"abcdefgh")

    def test_http_expect_continue(self):
        with Proxy("-L", "http://127.0.0.1:0") as proxy, proxy.connect() as sock:
            sock.sendall((f"POST http://127.0.0.1:{self.http}/ HTTP/1.1\r\n"
                          "Content-Length: 5\r\nExpect: 100-continue\r\n\r\n").encode())
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(exact(sock, 1))
            self.assertIn(b"100 Continue", header)
            sock.sendall(b"hello")
            res, data = response(sock)
            self.assertEqual(res.status, 200)
            self.assertEqual(base64.b64decode(json.loads(data)["body"]), b"hello")

    def test_http_origin_form_and_query_without_path(self):
        with Proxy("-L", "http://127.0.0.1:0") as proxy:
            for target, expected in (("/origin", "/origin"), (f"http://127.0.0.1:{self.http}?x=1", "/?x=1")):
                with proxy.connect() as sock:
                    sock.sendall(f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{self.http}\r\n\r\n".encode())
                    res, data = response(sock)
                    self.assertEqual(res.status, 200)
                    self.assertEqual(json.loads(data)["path"], expected)

    def test_http_rejects_ambiguous_framing(self):
        bad_headers = ["Content-Length: 1\r\nContent-Length: 1\r\n",
                       "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
                       "Content-Length: -1\r\n", "Transfer-Encoding: gzip\r\n",
                       "X-Fold: value\r\n continuation\r\n", "Host: one\r\nHost: two\r\n",
                       "Connection: Content-Length\r\nContent-Length: 1\r\n"]
        with Proxy("-L", "http://127.0.0.1:0") as proxy:
            for headers in bad_headers:
                with self.subTest(headers=headers), proxy.connect() as sock:
                    sock.sendall(f"POST http://127.0.0.1:{self.http}/ HTTP/1.1\r\n{headers}\r\n".encode())
                    res, _ = response(sock)
                    self.assertEqual(res.status, 400)

    def test_http_header_limit(self):
        with Proxy("-L", "http://127.0.0.1:0") as proxy, proxy.connect() as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nX-Large: " + b"a" * 33000 + b"\r\n\r\n")
            res, _ = response(sock)
            self.assertEqual(res.status, 431)

    def test_http_forwards_only_one_framed_request(self):
        with backend(TCPServer, CaptureHTTP) as port, Proxy("-L", "http://127.0.0.1:0") as proxy:
            for framing, payload, expected in (("Content-Length: 3", b"abc", b"abc"),
                                                ("Transfer-Encoding: chunked", b"3\r\nabc\r\n0\r\n\r\n", b"3\r\nabc\r\n0\r\n\r\n")):
                with self.subTest(framing=framing), proxy.connect() as sock:
                    sock.sendall(f"POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{framing}\r\n\r\n".encode()
                                 + payload + b"GET /must-not-leak HTTP/1.1\r\nProxy-Authorization: secret\r\n\r\n")
                    res, data = response(sock)
                    self.assertEqual(res.status, 200)
                    self.assertTrue(data.endswith(expected))
                    self.assertNotIn(b"must-not-leak", data)
                    self.assertNotIn(b"secret", data)

    def test_socks_connect_ipv4_domain_fragmented(self):
        with Proxy("-L", "socks5://127.0.0.1:0") as proxy:
            for host in ("127.0.0.1", "localhost"):
                with proxy.connect() as sock:
                    code, _ = socks_request(sock, host, self.echo, fragmented=True)
                    self.assertEqual(code, 0)
                    sock.sendall(b"socks-data\x00\xff")
                    self.assertEqual(exact(sock, 12), b"socks-data\x00\xff")

    def test_socks_auth_percent_encoded(self):
        with Proxy("-L", "socks5://u%40ser:p%3Ass@127.0.0.1:0") as proxy:
            with proxy.connect() as sock:
                code, _ = socks_request(sock, "127.0.0.1", self.echo, ("u@ser", "p:ss"))
                self.assertEqual(code, 0)
                sock.sendall(b"ok")
                self.assertEqual(exact(sock, 2), b"ok")
            with proxy.connect() as sock:
                with self.assertRaises(PermissionError):
                    socks_request(sock, "127.0.0.1", self.echo, ("u@ser", "wrong"))
            with proxy.connect() as sock:
                sock.sendall(b"\x05\x01\x00")
                self.assertEqual(exact(sock, 2), b"\x05\xff")

    def test_socks_unsupported_and_unreachable(self):
        with Proxy("-L", "socks5://127.0.0.1:0") as proxy:
            with proxy.connect() as sock:
                code, _ = socks_request(sock, "127.0.0.1", self.echo, cmd=2)
                self.assertEqual(code, 7)
            with socket.socket() as occupied:
                occupied.bind(("127.0.0.1", 0))
                port = occupied.getsockname()[1]
                with proxy.connect() as sock:
                    code, _ = socks_request(sock, "127.0.0.1", port)
                    self.assertEqual(code, 5)

    def test_auto_http_and_socks(self):
        with Proxy("-L", "127.0.0.1:0") as proxy:
            with proxy.connect() as sock:
                sock.sendall(f"GET http://127.0.0.1:{self.http}/auto HTTP/1.0\r\n\r\n".encode())
                res, _ = response(sock)
                self.assertEqual(res.status, 200)
            with proxy.connect() as sock:
                self.assertEqual(socks_request(sock, "127.0.0.1", self.echo)[0], 0)

    def test_tcp_large_half_close(self):
        payload = os.urandom(1024 * 1024)
        with backend(TCPServer, HalfClose) as port:
            with Proxy("-L", f"tcp://127.0.0.1:0/127.0.0.1:{port}") as proxy, proxy.connect() as sock:
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(sock, len(payload)), payload[::-1])
                self.assertEqual(sock.recv(1), b"")

    def test_multiple_listeners_and_concurrent_clients(self):
        with Proxy("-L", f"tcp://127.0.0.1:0/127.0.0.1:{self.echo}",
                   "-L", "socks5://127.0.0.1:0", listeners=2) as proxy:
            def exchange(index):
                payload = os.urandom(32768)
                with proxy.connect(index % 2) as sock:
                    if index % 2:
                        self.assertEqual(socks_request(sock, "127.0.0.1", self.echo)[0], 0)
                    sock.sendall(payload)
                    self.assertEqual(exact(sock, len(payload)), payload)
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(exchange, range(32)))

    def test_mixed_authenticated_chain(self):
        with Proxy("-L", "http://user:pass@127.0.0.1:0") as first:
            with Proxy("-L", "socks5://alice:secret@127.0.0.1:0") as second:
                with Proxy("-L", "http://127.0.0.1:0",
                           "-F", f"http://user:pass@127.0.0.1:{first.ports[0]}",
                           "-F", f"socks5://alice:secret@127.0.0.1:{second.ports[0]}") as proxy:
                    with proxy.connect() as sock:
                        sock.sendall(f"GET http://localhost:{self.http}/chained HTTP/1.1\r\n\r\n".encode())
                        res, data = response(sock)
                        self.assertEqual(res.status, 200)
                        self.assertEqual(json.loads(data)["path"], "/chained")
                        self.assertNotIn("Proxy-Authorization", json.loads(data)["headers"])

    def test_tcp_chain_and_wrong_hop_auth(self):
        with Proxy("-L", "socks5://u:p@127.0.0.1:0") as upstream:
            with Proxy("-L", f"tcp://127.0.0.1:0/127.0.0.1:{self.echo}",
                       "-F", f"socks5://u:p@127.0.0.1:{upstream.ports[0]}") as proxy:
                with proxy.connect() as sock:
                    sock.sendall(b"chain")
                    self.assertEqual(exact(sock, 5), b"chain")
            with Proxy("-L", "http://127.0.0.1:0",
                       "-F", f"socks5://u:bad@127.0.0.1:{upstream.ports[0]}") as proxy:
                with proxy.connect() as sock:
                    sock.sendall(f"GET http://127.0.0.1:{self.http}/ HTTP/1.1\r\n\r\n".encode())
                    self.assertEqual(response(sock)[0].status, 502)

    def test_udp_forward_multiple_clients_and_empty_datagrams(self):
        with Proxy("-L", f"udp://127.0.0.1:0/127.0.0.1:{self.udp}") as proxy:
            with contextlib.ExitStack() as stack:
                clients = [stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) for _ in range(8)]
                for i, sock in enumerate(clients):
                    sock.settimeout(3)
                    sock.sendto(bytes([i]) * 30000, ("127.0.0.1", proxy.ports[0]))
                for i, sock in enumerate(clients):
                    self.assertEqual(sock.recv(65536), bytes([i]) * 30000)
                clients[0].sendto(b"", ("127.0.0.1", proxy.ports[0]))
                self.assertEqual(clients[0].recv(1), b"")

    def test_socks_udp_multiple_targets_fragment_and_source_pinning(self):
        with backend(UDPServer, UDPEcho) as second_port:
            with Proxy("-L", "socks5://u:p@127.0.0.1:0") as proxy, proxy.connect() as control:
                code, relay = socks_request(control, "0.0.0.0", 0, ("u", "p"), cmd=3)
                self.assertEqual(code, 0)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2)
                    for port, payload, domain in ((self.udp, b"udp\x00\xff", False),
                                                   (second_port, b"", True)):
                        sock.sendto(b"\x00\x00\x00" + address("127.0.0.1", port, domain=domain) + payload, relay)
                        received = sock.recv(65536)
                        self.assertEqual(received[:4], b"\x00\x00\x00\x01")
                        self.assertEqual(struct.unpack("!H", received[8:10])[0], port)
                        self.assertEqual(received[10:], payload)
                    sock.settimeout(0.15)
                    sock.sendto(b"\x00\x00\x01" + address("127.0.0.1", self.udp) + b"fragment", relay)
                    with self.assertRaises(socket.timeout):
                        sock.recv(1024)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
                        other.settimeout(0.15)
                        other.sendto(b"\x00\x00\x00" + address("127.0.0.1", self.udp) + b"spoof", relay)
                        with self.assertRaises(socket.timeout):
                            other.recv(1024)

    def test_socks_udp_rejects_chaining(self):
        with Proxy("-L", "socks5://127.0.0.1:0", "-F", "http://127.0.0.1:1") as proxy:
            with proxy.connect() as sock:
                self.assertEqual(socks_request(sock, "0.0.0.0", 0, cmd=3)[0], 7)

    def test_udp_association_control_lifetime_and_client_port(self):
        with Proxy("-L", "socks5://127.0.0.1:0") as proxy, proxy.connect() as control:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", 0))
                sock.settimeout(0.3)
                code, relay = socks_request(control, "127.0.0.1", sock.getsockname()[1], cmd=3)
                self.assertEqual(code, 0)
                packet = b"\x00\x00\x00" + address("127.0.0.1", self.udp) + b"alive"
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
                    other.settimeout(0.15)
                    other.sendto(packet, relay)
                    with self.assertRaises(socket.timeout):
                        other.recv(1024)
                sock.sendto(packet, relay)
                self.assertTrue(sock.recv(1024).endswith(b"alive"))
                control.shutdown(socket.SHUT_RDWR)
                time.sleep(0.05)
                sock.sendto(packet, relay)
                with self.assertRaises(socket.timeout):
                    sock.recv(1024)

    def test_udp_forward_expired_flow_is_recreated(self):
        with Proxy("-L", f"udp://127.0.0.1:0/127.0.0.1:{self.udp}", "--timeout", "1") as proxy:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                for data in (b"before", b"after"):
                    sock.sendto(data, ("127.0.0.1", proxy.ports[0]))
                    self.assertEqual(sock.recv(1024), data)
                    if data == b"before":
                        time.sleep(1.3)

    @unittest.skipUnless(shutil.which("curl"), "curl not installed")
    def test_curl_http_and_socks5_interoperability(self):
        with Proxy("-L", "auto://u:p@127.0.0.1:0") as proxy:
            for scheme in ("http", "socks5h"):
                result = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--max-time", "3",
                                         "--noproxy", "", "--proxy", f"{scheme}://u:p@127.0.0.1:{proxy.ports[0]}",
                                         f"http://localhost:{self.http}/curl"], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(json.loads(result.stdout)["path"], "/curl")

    def test_client_limit_and_bind_conflict(self):
        with Proxy("-L", "socks5://127.0.0.1:0", "--max-clients", "1") as proxy:
            with proxy.connect() as first:
                self.assertEqual(socks_request(first, "127.0.0.1", self.echo)[0], 0)
                with proxy.connect() as second:
                    self.assertEqual(second.recv(1), b"")
                first.sendall(b"still-active")
                self.assertEqual(exact(first, 12), b"still-active")
            result = subprocess.run([str(BINARY), "-L", f"http://127.0.0.1:{proxy.ports[0]}"],
                                    capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"Cannot bind", result.stderr)

    def test_shutdown_with_live_tcp_and_udp_association(self):
        with Proxy("-L", "socks5://127.0.0.1:0") as proxy:
            with proxy.connect() as control, proxy.connect() as idle:
                self.assertEqual(socks_request(control, "0.0.0.0", 0, cmd=3)[0], 0)
                start = time.monotonic()
                proxy.process.terminate()
                self.assertEqual(proxy.process.wait(timeout=3), 0)
                self.assertLess(time.monotonic() - start, 2)
                self.assertEqual(idle.recv(1), b"")

    def test_idle_timeout(self):
        with Proxy("-L", "socks5://127.0.0.1:0", "--timeout", "1") as proxy, proxy.connect() as sock:
            self.assertEqual(socks_request(sock, "127.0.0.1", self.echo)[0], 0)
            self.assertEqual(sock.recv(1), b"")

    def test_ipv6_listener_and_target(self):
        class TCP6(TCPServer):
            address_family = socket.AF_INET6
        try:
            server = TCP6(("::1", 0), Echo)
        except OSError as exc:
            self.skipTest(f"IPv6 unavailable: {exc}")
        with server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
            thread.start()
            try:
                with Proxy("-L", "socks5://[::1]:0") as proxy, proxy.connect(host="::1") as sock:
                    self.assertEqual(socks_request(sock, "::1", server.server_address[1])[0], 0)
                    sock.sendall(b"ipv6")
                    self.assertEqual(exact(sock, 4), b"ipv6")
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def test_invalid_cli_fails_before_startup(self):
        for args in (("-L", "quic://127.0.0.1:0"), ("-L", "http://127.0.0.1:65536"),
                     ("-L", "socks5://u%00:p@127.0.0.1:0"),
                     ("-L", "udp://127.0.0.1:0/127.0.0.1:9", "-F", "http://127.0.0.1:9"),
                     ("-L", "http://::1:80"), ("-C", "config.yaml"),
                     ("-L", "http://127.0.0.1:0", "--timeout", "0")):
            with self.subTest(args=args):
                result = subprocess.run([str(BINARY), *args], capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
