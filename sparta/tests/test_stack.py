import base64
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "tests"))
from test_proxy import backend, TCPServer, UDPServer, Echo, UDPEcho, exact, address, socks_request

BIN = ROOT / "build/sparta"
PROBE = ROOT / "build/probe"
FIXTURE = ROOT / "build/node-fixture"
TOKEN = "test-plugin-token-000000000000000000000000"
KEY = "test-node-key"


def state(rate=0, access="allow", version=1):
    return {"version": version, "users": [{"id": "alice", "pass_sha256": hashlib.sha256(b"secret").hexdigest(),
            "access": access, "rate_kbps": rate}], "blacklist": {"global": ["blocked.example"], "users": {"alice": ["own.example"]}}}


class Process:
    def __init__(self, args, pattern=r"Listening \w+ on \[.*?\]:(\d+)", env=None):
        self.args, self.pattern, self.env = args, pattern, env

    def __enter__(self):
        self.log = tempfile.TemporaryFile()
        self.p = subprocess.Popen([str(x) for x in self.args], stdout=subprocess.DEVNULL, stderr=self.log,
                                  env=self.env)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            log = os.pread(self.log.fileno(), 100000, 0).decode(errors="replace")
            match = re.search(self.pattern, log)
            if match:
                self.port = int(match[1])
                return self
            if self.p.poll() is not None:
                self.log.close()
                raise AssertionError(f"Process exited {self.p.returncode}: {log}")
            time.sleep(0.01)
        self.p.kill(); self.p.wait(); self.log.close()
        raise AssertionError("No readiness message")

    def __exit__(self, *_):
        self.p.terminate()
        try:
            code = self.p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.p.kill(); self.p.wait(); self.log.close()
            raise AssertionError("Shutdown timed out")
        log = os.pread(self.log.fileno(), 100000, 0).decode(errors="replace")
        self.log.close()
        if code or "runtime error:" in log or "ERROR: AddressSanitizer" in log:
            raise AssertionError(f"Process exited {code}: {log}")


class WS:
    def __init__(self, sock, client):
        self.sock, self.client, self.buffer = sock, client, bytearray()

    def write(self, data, opcode=2, fin=True):
        header = bytes([(0x80 if fin else 0) | opcode])
        maskbit = 0x80 if self.client else 0
        if len(data) < 126:
            header += bytes([maskbit | len(data)])
        elif len(data) <= 65535:
            header += bytes([maskbit | 126]) + struct.pack("!H", len(data))
        else:
            header += bytes([maskbit | 127]) + struct.pack("!Q", len(data))
        if self.client:
            key = os.urandom(4)
            data = bytes(c ^ key[i % 4] for i, c in enumerate(data))
            header += key
        self.sock.sendall(header + data)

    def frame(self):
        head = exact(self.sock, 2)
        opcode, masked, n = head[0] & 15, head[1] & 128, head[1] & 127
        if bool(masked) == self.client:
            raise AssertionError("Incorrect WebSocket mask direction")
        if n == 126:
            n = struct.unpack("!H", exact(self.sock, 2))[0]
        elif n == 127:
            n = struct.unpack("!Q", exact(self.sock, 8))[0]
        key = exact(self.sock, 4) if masked else bytes(4)
        data = exact(self.sock, n)
        return opcode, bytes(c ^ key[i % 4] for i, c in enumerate(data))

    def read(self, count):
        while len(self.buffer) < count:
            opcode, data = self.frame()
            if opcode in (0, 2):
                self.buffer.extend(data)
            elif opcode == 9:
                self.write(data, 10)
            elif opcode == 8:
                raise EOFError("WS closed")
        data = bytes(self.buffer[:count]); del self.buffer[:count]
        return data


def ws_connect(port, path="/secret"):
    sock = socket.create_connection(("127.0.0.1", port), timeout=4)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        header.extend(exact(sock, 1))
    if b"101 Switching Protocols" not in header:
        sock.close()
        raise PermissionError(header)
    expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
    if expected not in header:
        sock.close()
        raise AssertionError("Bad WebSocket accept key")
    return sock, WS(sock, True)


def relay_request(host, port, password="secret", udp=False):
    auth = b"\x05alice" + bytes([len(password)]) + password.encode()
    dest = address(host, port)
    features = b"\x01" + struct.pack("!H", len(auth)) + auth
    features += b"\x02" + struct.pack("!H", len(dest)) + dest
    features += b"\x04\x00\x02\x00" + bytes([int(udp)])
    return bytes([1, 0x82 if udp else 1]) + struct.pack("!H", len(features)) + features


def verdict(ws):
    head = ws.read(4)
    if head[0] != 1:
        raise AssertionError("Bad relay version")
    ws.read(struct.unpack("!H", head[2:])[0])
    return head[1]


class QuietServer(TCPServer):
    def handle_error(self, *_):
        pass


@contextlib.contextmanager
def tls_gateway(cert, key, node_port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["http/1.1"])
    class Gateway(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with ctx.wrap_socket(self.request, server_side=True) as incoming:
                    with socket.create_connection(("127.0.0.1", node_port), timeout=4) as outgoing:
                        incoming.settimeout(4)
                        outgoing.settimeout(4)
                        while True:
                            readable, _, _ = select.select([incoming, outgoing], [], [], 0.05)
                            if incoming.pending() and incoming not in readable:
                                readable.append(incoming)
                            for source in readable:
                                data = source.recv(65536)
                                if not data:
                                    return
                                (outgoing if source is incoming else incoming).sendall(data)
            except (OSError, ssl.SSLError):
                pass
    with backend(QuietServer, Gateway) as port:
        yield port


class CheckHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def do_GET(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


class StackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = Path(cls.temp.name) / "cert.pem", Path(cls.temp.name) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", str(cls.key), "-out", str(cls.cert)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)

    def config(self, name="node", snapshot=True, **extra):
        directory = self.path / (name + "-state")
        directory.mkdir(exist_ok=True)
        if snapshot:
            (directory / "state.json").write_text(json.dumps(state()))
        cfg = {"listen": "127.0.0.1:0", "ws_path": "/secret", "state_dir": str(directory),
               "plugin_listen": "127.0.0.1:0", **extra}
        file = self.path / (name + ".json")
        file.write_text(json.dumps(cfg))
        return file, directory

    def profile(self, port=443, **extra):
        value = {"v": 1, "name": "test", "host": "localhost", "port": port, "path": "/secret",
                 "user": "alice", "password": "secret", "fingerprint": "native", **extra}
        file = self.path / "profile.json"
        file.write_text(json.dumps(value))
        return file

    def test_profile_validation_and_secret_redaction(self):
        valid = self.profile()
        result = subprocess.run([BIN, "profile", "--profile", valid], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for field, value in (("path", "/secret\r\nInjected: yes"), ("port", 0), ("user", "u" * 256),
                             ("fingerprint", "unknown"), ("host", "host/evil"), ("name", "x" * 41)):
            with self.subTest(field=field):
                path = self.profile(**{field: value})
                result = subprocess.run([BIN, "profile", "--profile", path], capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(b"secret", result.stderr)
        path = self.profile()
        path.write_text(path.read_text().replace('"v": 1', '"v": 1, "v": 1'))
        self.assertEqual(subprocess.run([BIN, "profile", "--profile", path], capture_output=True).returncode, 2)

    def test_import_link_and_embedded_nul(self):
        raw = self.profile().read_bytes()
        link = "sparta://import/v1/" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
        result = subprocess.run([BIN, "profile", "--link", link], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        path = self.profile(user="alice\x00other")
        self.assertEqual(subprocess.run([BIN, "profile", "--profile", path], capture_output=True).returncode, 2)

    def test_c_api_start_stop_repeatability(self):
        result = subprocess.run([PROBE, "lifecycle", self.profile()], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([ROOT / "build/client-probe", "lifecycle", self.profile()], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dns_rebinding_uses_only_checked_numeric_addresses(self):
        cfg, _ = self.config()
        with backend(TCPServer, Echo) as echo:
            result = subprocess.run([ROOT / "build/dns-probe", cfg, str(echo)], capture_output=True, timeout=4)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rate_limit_is_shared_across_connections(self):
        cfg, directory = self.config()
        (directory / "state.json").write_text(json.dumps(state(rate=8)))
        with backend(TCPServer, Echo) as echo, Process([FIXTURE, cfg]) as node:
            clients = [ws_connect(node.port) for _ in range(2)]
            try:
                for _, ws in clients:
                    ws.write(relay_request("public.example", echo))
                    self.assertEqual(verdict(ws), 0)
                start = time.monotonic()
                for _, ws in clients:
                    ws.write(b"x" * 1500)
                for _, ws in clients:
                    self.assertEqual(ws.read(1500), b"x" * 1500)
                self.assertGreater(time.monotonic() - start, 1.5)
            finally:
                for sock, _ in clients: sock.close()

    def test_policy_private_ranges_and_patterns(self):
        for host in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "::ffff:10.0.0.1", "::1", "224.0.0.1",
                     "ff02::1", "fc00::1", "64:ff9b::a00:1", "0.0.0.0"):
            with self.subTest(host=host):
                self.assertEqual(subprocess.check_output([PROBE, "private", host]).strip(), b"yes")
        for host in ("1.1.1.1", "2606:4700:4700::1111"):
            self.assertEqual(subprocess.check_output([PROBE, "private", host]).strip(), b"no")
        cases = [("example.com", "A.Example.COM.:443", True), ("*.example.com", "example.com", True),
                 ("example.com", "badexample.com", False), ("10.0.0.0/8", "[::ffff:10.2.3.4]:80", True),
                 ("::ffff:10.0.0.0/104", "10.2.3.4", True)]
        for pattern, target, expected in cases:
            self.assertEqual(subprocess.check_output([PROBE, "match", pattern, target]).strip(), b"yes" if expected else b"no")

    def test_production_node_auth_and_private_network_denial(self):
        cfg, _ = self.config()
        with Process([BIN, "node", "--config", cfg]) as node:
            for target, password, expected in (("127.0.0.1", "secret", 3), ("localhost", "secret", 3),
                                                ("::ffff:127.0.0.1", "secret", 3), ("blocked.example", "secret", 3),
                                                ("own.example", "secret", 3), ("1.1.1.1", "wrong", 2)):
                with self.subTest(target=target, password=password):
                    sock, ws = ws_connect(node.port)
                    with sock:
                        ws.write(relay_request(target, 80, password=password))
                        self.assertEqual(verdict(ws), expected)

    def test_no_snapshot_fails_closed(self):
        cfg, _ = self.config(snapshot=False)
        with Process([BIN, "node", "--config", cfg]) as node:
            sock, ws = ws_connect(node.port)
            with sock:
                ws.write(relay_request("1.1.1.1", 80))
                self.assertEqual(verdict(ws), 2)

    def test_partial_snapshot_does_not_drop_blacklist_silently(self):
        cfg, directory = self.config()
        partial = state()
        del partial["blacklist"]
        (directory / "state.json").write_text(json.dumps(partial))
        with Process([BIN, "node", "--config", cfg]) as node:
            sock, ws = ws_connect(node.port)
            with sock:
                ws.write(relay_request("1.1.1.1", 80))
                self.assertEqual(verdict(ws), 2)

    def test_ws_wrong_path_bad_mask_and_fragmentation(self):
        cfg, _ = self.config()
        with Process([BIN, "node", "--config", cfg]) as node:
            with self.assertRaises(PermissionError):
                ws_connect(node.port, "/wrong")
            sock, ws = ws_connect(node.port)
            with sock:
                request = relay_request("127.0.0.1", 80)
                ws.write(request[:3], fin=False)
                ws.write(b"ping-payload", opcode=9)
                ws.write(request[3:], opcode=0)
                self.assertEqual(verdict(ws), 3)
            sock, _ = ws_connect(node.port)
            with sock:
                sock.sendall(b"\x82\x04\x01\x01\x00\x00")  # client frames must be masked
                self.assertEqual(sock.recv(1), b"")

    def test_client_tcp_through_tls_ws_node(self):
        cfg, _ = self.config()
        with backend(TCPServer, Echo) as echo, Process([FIXTURE, cfg]) as node:
            with tls_gateway(self.cert, self.key, node.port) as tls:
                profile = self.profile(tls)
                with Process([BIN, "client", "--profile", profile, "--ca", self.cert,
                              "--socks-port", "0", "--skip-check"]) as client:
                    with socket.create_connection(("127.0.0.1", client.port), timeout=5) as sock:
                        self.assertEqual(socks_request(sock, "public.example", echo)[0], 0)
                        payload = os.urandom(256 * 1024)
                        sock.sendall(payload)
                        self.assertEqual(exact(sock, len(payload)), payload)

    def test_check_classifies_auth_and_tls(self):
        cfg, _ = self.config()
        with backend(http.server.ThreadingHTTPServer, CheckHandler) as target, Process([FIXTURE, cfg]) as node:
            with tls_gateway(self.cert, self.key, node.port) as tls:
                for extra, ca, expected in (({}, self.cert, None), ({"password": "wrong"}, self.cert, b"auth:"),
                                             ({"path": "/wrong"}, self.cert, b"auth:"), ({}, None, b"tls:"),
                                             ({"host": "wrong.example"}, self.cert, b"tls:")):
                    with self.subTest(extra=extra, ca=ca):
                        profile = self.profile(tls, **extra)
                        args = [BIN, "client", "--profile", profile, "--socks-port", "0", "--check-only",
                                "--node-address", f"127.0.0.1:{tls}", "--check-url", f"http://public.example:{target}/check"]
                        if ca:
                            args += ["--ca", ca]
                        result = subprocess.run(args, capture_output=True, timeout=8)
                        self.assertEqual(result.returncode, int(expected is not None), result.stderr)
                        if expected:
                            self.assertIn(expected, result.stderr)

    def test_check_deadline_and_stop_cancel_tls_handshake(self):
        class Silent(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                try:
                    while self.request.recv(1024):
                        pass
                except OSError:
                    pass
        with backend(TCPServer, Silent) as port:
            for command in ("check-timeout", "cancel-check"):
                started = time.monotonic()
                result = subprocess.run([PROBE, command, self.profile(port)], capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertLess(time.monotonic() - started, 2)

    def test_subscription_status_and_redirect_do_not_leak_token(self):
        requests = []
        reply = {"status": "active", "v": 1, "credentials": {"username": "alice", "password": "secret"},
                 "nodes": [{"id": "n1", "name": "test", "host": "localhost", "port": 443, "path": "/secret", "fingerprint": "native"}]}
        class Hub(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                requests.append((self.path, self.headers.get("Authorization")))
                if self.path.startswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/must-not-follow")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    data = json.dumps(reply).encode()
                    self.send_response(200); self.send_header("Content-Length", str(len(data)))
                    self.end_headers(); self.wfile.write(data)
        with backend(http.server.ThreadingHTTPServer, Hub) as port:
            def link(path):
                data = json.dumps({"v": 1, "hub": f"http://127.0.0.1:{port}/{path}", "token": "never-print-this"}).encode()
                return "sparta://sub/v1/" + base64.urlsafe_b64encode(data).decode().rstrip("=")
            result = subprocess.run([BIN, "profile", "--subscription", link("private")], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            reply["status"] = "blocked"
            result = subprocess.run([BIN, "profile", "--subscription", link("private")], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 3)
            self.assertNotIn(b"never-print-this", result.stderr)
            result = subprocess.run([BIN, "profile", "--subscription", link("redirect")], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(any(path == "/must-not-follow" for path, _ in requests))
            self.assertTrue(all(token == "Bearer never-print-this" for _, token in requests))

    def test_client_udp_associate_and_quic_drop(self):
        cfg, _ = self.config()
        with backend(UDPServer, UDPEcho) as echo, Process([FIXTURE, cfg]) as node:
            with tls_gateway(self.cert, self.key, node.port) as tls:
                with Process([BIN, "client", "--profile", self.profile(tls), "--ca", self.cert,
                              "--socks-port", "0", "--skip-check"]) as client:
                    with socket.create_connection(("127.0.0.1", client.port), timeout=5) as control:
                        code, relay = socks_request(control, "0.0.0.0", 0, cmd=3)
                        self.assertEqual(code, 0)
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                            udp.settimeout(4)
                            for payload in (b"udp-payload\x00", b"", os.urandom(30000)):
                                udp.sendto(b"\0\0\0" + address("public.example", echo) + payload, relay)
                                self.assertEqual(udp.recv(65536)[10:], payload)
                            udp.settimeout(0.2)
                            udp.sendto(b"\0\0\0" + address("public.example", 443) + b"quic", relay)
                            with self.assertRaises(socket.timeout):
                                udp.recv(65536)

    def test_unavailable_node_never_dials_target_directly(self):
        with socket.socket() as unavailable, backend(TCPServer, Echo) as echo:
            unavailable.bind(("127.0.0.1", 0))
            with Process([BIN, "client", "--profile", self.profile(unavailable.getsockname()[1]),
                          "--socks-port", "0", "--skip-check"]) as client:
                with socket.create_connection(("127.0.0.1", client.port), timeout=3) as sock:
                    self.assertNotEqual(socks_request(sock, "127.0.0.1", echo)[0], 0)

    def test_agent_plugin_auth_limiter_bypass_and_body_validation(self):
        cfg, _ = self.config()
        env = {**os.environ, "SPARTA_PLUGIN_TOKEN": TOKEN}
        with Process([BIN, "agent", "--config", cfg], pattern=r"Agent plugins on \[.*?\]:(\d+)", env=env) as agent:
            def request(path, body, token=TOKEN):
                conn = http.client.HTTPConnection("127.0.0.1", agent.port, timeout=4)
                conn.request("POST", path, json.dumps(body), {"Authorization": f"Bearer {token}"})
                response = conn.getresponse(); data = json.loads(response.read()); conn.close()
                self.assertEqual(response.status, 200)
                return data
            self.assertEqual(request("/auth", {"username": "alice", "password": "secret"}), {"ok": True, "id": "alice"})
            self.assertEqual(request("/auth", {"username": "alice", "password": "wrong"}), {"ok": False})
            self.assertEqual(request("/auth", {"username": "alice", "password": "secret"}, token="wrong"), {"ok": False})
            for dest in ("127.0.0.1:80", "[::ffff:169.254.169.254]:80", "blocked.example:80", "agent:80", ":22"):
                self.assertEqual(request("/bypass", {"client": "alice", "addr": dest}), {"ok": True})
            self.assertEqual(request("/limiter", {"scope": "client", "client": "missing"}), {"in": 1, "out": 1})
            self.assertEqual(request("/limiter", []), {"in": 1, "out": 1})
            self.assertEqual(request("/observer", {"events": []}), {"ok": True})
            self.assertEqual(request("/observer", []), {"ok": False})

    def test_corrupt_counters_and_second_agent_refuse_startup(self):
        cfg, directory = self.config()
        env = {**os.environ, "SPARTA_PLUGIN_TOKEN": TOKEN}
        with Process([BIN, "agent", "--config", cfg], pattern=r"Agent plugins on \[.*?\]:(\d+)", env=env):
            result = subprocess.run([BIN, "agent", "--config", cfg], env=env, capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 2)
        (directory / "counters.json").write_text("broken")
        result = subprocess.run([BIN, "agent", "--config", cfg], env=env, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 2)

    def test_hub_reports_retried_identically_and_large_counts_split(self):
        reports, registrations = [], []
        hub_state = state()
        class Hub(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def reply(self, code, value):
                data = json.dumps(value).encode()
                self.send_response(code); self.send_header("Content-Length", str(len(data)))
                self.send_header("ETag", '"1"'); self.end_headers(); self.wfile.write(data)
            def do_GET(self): self.reply(200, hub_state)
            def do_PUT(self):
                registrations.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.reply(200, {"ok": True})
            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                reports.append(value)
                if len(reports) == 1:
                    self.reply(503, {})
                else:
                    self.reply(200, {"ok": True, "acked_seq": value["seq"]})
        with backend(http.server.ThreadingHTTPServer, Hub) as hub:
            cfg, directory = self.config(hub=f"http://127.0.0.1:{hub}/private", node_id="node-test", interval_seconds=1)
            maximum = 1 << 50
            (directory / "counters.json").write_text(json.dumps({"seq": "7", "unsent": {"alice": {"in": str(maximum + 12), "out": "5"}}, "batch": {}}))
            env = {**os.environ, "SPARTA_PLUGIN_TOKEN": TOKEN, "SPARTA_NODE_KEY": KEY}
            with Process([BIN, "agent", "--config", cfg], pattern=r"Agent plugins on \[.*?\]:(\d+)", env=env):
                deadline = time.monotonic() + 6
                while len(reports) < 3 and time.monotonic() < deadline:
                    time.sleep(0.03)
            self.assertGreaterEqual(len(reports), 3)
            self.assertEqual(reports[0], reports[1])
            self.assertEqual(reports[0]["users"]["alice"]["in"], maximum)
            self.assertEqual(reports[2]["users"]["alice"]["in"], 12)
            self.assertGreater(reports[2]["seq"], reports[1]["seq"])
            self.assertTrue(registrations)
            self.assertEqual((directory / "state.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((directory / "counters.json").stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(os.geteuid() == 0, "Needs an unprivileged process for filesystem permission failures")
    def test_report_waits_for_durable_pending_file(self):
        reports, fetched = [], []
        class Hub(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def reply(self, value):
                data = json.dumps(value).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(data)))
                self.end_headers(); self.wfile.write(data)
            def do_GET(self):
                fetched.append(True)
                self.reply(state())
            def do_PUT(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.reply({"ok": True})
            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                reports.append(value)
                self.reply({"ok": True, "acked_seq": value["seq"]})
        with backend(http.server.ThreadingHTTPServer, Hub) as hub:
            cfg, directory = self.config(hub=f"http://127.0.0.1:{hub}/agent", node_id="node-test", interval_seconds=1)
            (directory / ".agent.lock").touch(mode=0o600)
            (directory / "counters.json").write_text(json.dumps({"seq": "7", "unsent": {"alice": {"in": "10", "out": "0"}}, "batch": {}}))
            directory.chmod(0o500)
            env = {**os.environ, "SPARTA_PLUGIN_TOKEN": TOKEN, "SPARTA_NODE_KEY": KEY}
            try:
                with Process([BIN, "agent", "--config", cfg], pattern=r"Agent plugins on \[.*?\]:(\d+)", env=env):
                    deadline = time.monotonic() + 3
                    while not fetched and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(fetched)
                    time.sleep(1.2)
                    self.assertEqual(reports, [])
                    directory.chmod(0o700)
                    deadline = time.monotonic() + 3
                    while not reports and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(reports)
                    self.assertEqual(reports[0]["users"]["alice"]["in"], 10)
            finally:
                directory.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
