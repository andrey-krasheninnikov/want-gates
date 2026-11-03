#!/usr/bin/env python3
"""Controlled Forti TLS/HTTP peer connected to a real PPP daemon for Linux acceptance."""
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def read_exact(reader, size):
    data = bytearray()
    while len(data) < size:
        part = reader.read(size-len(data)) if hasattr(reader, 'read') else reader.recv(size-len(data))
        if not part: raise EOFError
        data.extend(part)
    return bytes(data)


def fcs(data):
    value = 0xffff
    for byte in data:
        value ^= byte
        for _ in range(8): value = (value >> 1) ^ (0x8408 if value & 1 else 0)
    return value


def encode(data):
    data = b'\xff\x03'+data
    data += struct.pack('<H', fcs(data) ^ 0xffff)
    output = bytearray(b'\x7e')
    for byte in data:
        if byte < 0x20 or byte in (0x7d, 0x7e): output.extend((0x7d, byte ^ 0x20))
        else: output.append(byte)
    return bytes(output)+b'\x7e'


def ppp_tunnel(stream, reader, mode_path):
    process = subprocess.Popen(['/usr/sbin/pppd', 'nodetach', 'notty', 'local', 'noauth', 'passive', 'noipdefault', '169.254.2.1:10.231.0.2', 'ms-dns', '10.220.0.10', 'nodefaultroute', 'noproxyarp', 'noipv6', 'nobsdcomp', 'nodeflate', 'noccp', 'novj', 'novjccomp', 'noaccomp', 'nopcomp', 'ip-up-script', '/usr/bin/true', 'ip-down-script', '/usr/bin/true', 'logfd', '2'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, start_new_session=True)
    def send():
        frame = bytearray(); escaped = False
        try:
            while True:
                block = process.stdout.read1(4096)
                if not block: break
                for byte in block:
                    if byte == 0x7e:
                        if len(frame) >= 4:
                            assert fcs(frame) == 0xf0b8, 'invalid PPP FCS'
                            assert frame[:2] == b'\xff\x03', 'PPP address/control compression was not negotiated'
                            packet = bytes(frame[2:-2])
                            if packet.startswith((b'\x00\x21',b'\x21')) and json.loads(mode_path.read_text()).get('drop_data'): continue
                            stream.sendall(struct.pack('!HHH', len(packet)+6, 0x5050, len(packet))+packet)
                        frame.clear(); escaped = False
                    elif byte == 0x7d: escaped = True
                    else:
                        frame.append(byte ^ 0x20 if escaped else byte); escaped = False
                        assert len(frame) < 65536, 'oversized PPP frame'
        except (OSError, AssertionError): pass
        finally:
            try: stream.shutdown(socket.SHUT_RDWR)
            except OSError: pass
    sender = threading.Thread(target=send, daemon=True); sender.start()
    try:
        while True:
            total, magic, size = struct.unpack('!HHH', read_exact(reader, 6))
            assert magic == 0x5050 and total == size+6 and 0 < size < 65530
            packet=read_exact(reader,size)
            if packet.startswith((b'\x00\x21',b'\x21')) and json.loads(mode_path.read_text()).get('drop_data'): continue
            process.stdin.write(encode(packet)); process.stdin.flush()
    except (OSError, EOFError, AssertionError): pass
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(timeout=2)
            except subprocess.TimeoutExpired: os.killpg(process.pid, signal.SIGKILL); process.wait()
        try: stream.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        sender.join(timeout=3)
        process.stdin.close(); process.stdout.close()
        assert not sender.is_alive(), 'PPP sender did not stop'


def main(directory, address, mode_path):
    directory, mode_path = Path(directory), Path(mode_path)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def reply(self, body=b'', cookie=False, redirect=None, status=200):
            self.send_response(302 if redirect else status, 'Authorization Required' if status==401 else None)
            self.send_header('Content-Length', str(len(body)))
            if cookie: self.send_header('Set-Cookie', 'SVPNCOOKIE=forti-cookie-marker; path=/; secure')
            if redirect: self.send_header('Location', redirect)
            self.end_headers(); self.wfile.write(body); self.wfile.flush()
        def do_POST(self):
            fields = parse_qs(read_exact(self.rfile, int(self.headers.get('Content-Length', '0'))).decode(), keep_blank_values=True)
            mode = json.loads(mode_path.read_text())
            user = fields.get('username') == ['forti-user']
            password = fields.get('credential') == ['forti-password-marker']
            if mode['mode']=='otp401' and self.path=='/remote/otp':
                self.reply(cookie=fields.get('code')==['forti-401-marker'] and fields.get('magic')==['forti-401-state']); return
            if mode.get('deny') or self.path != '/remote/logincheck': self.reply(); return
            if mode['mode']=='otp401' and user and password:
                self.reply(b'<FORM action="/remote/otp"><p>Please enter one-time password: </p><INPUT name="code" type="password"><INPUT name="magic" type="hidden" value="forti-401-state"></FORM>',status=401); return
            if mode['mode'] == 'otp' and user and password:
                self.reply(b'tokeninfo=token&grp=group&reqid=1&polid=1&portal=office&magic=forti-state-marker&peer=peer'); return
            if mode['mode'] == 'push' and user and password:
                self.reply(b'tokeninfo=ftm_push&grp=group&reqid=1&polid=1&portal=office&magic=forti-state-marker&peer=peer'); return
            accepted = (mode['mode'] in ('password','password_certificate') and user and password and (mode['mode']!='password_certificate' or bool(self.connection.getpeercert()))) or (mode['mode']=='otp' and user and fields.get('code')==['forti-otp-marker']) or (mode['mode']=='push' and user and fields.get('ftmpush')==['1'])
            self.reply(cookie=accepted)
        def do_GET(self):
            parsed = urlsplit(self.path)
            mode = json.loads(mode_path.read_text())
            if parsed.path == '/remote/saml/start': self.reply(redirect='http://127.0.0.1:8020/?id=forti-saml-marker'); return
            if parsed.path == '/remote/saml/auth_id': self.reply(cookie=not mode.get('deny') and mode['mode']=='saml' and parse_qs(parsed.query).get('id')==['forti-saml-marker']); return
            if parsed.path == '/remote/login': self.reply(cookie=mode['mode']=='certificate' and bool(self.connection.getpeercert())); return
            if 'SVPNCOOKIE=forti-cookie-marker' not in self.headers.get('Cookie', '') or mode.get('deny'):
                self.reply(); return
            if parsed.path == '/remote/fortisslvpn_xml':
                self.reply(b'<sslvpn-tunnel><assigned-addr ipv4="10.231.0.2"/><dns ip="10.220.0.10"/><dns ip="1.1.1.1"/><split-tunnel-info></split-tunnel-info></sslvpn-tunnel>'); return
            if parsed.path == '/remote/sslvpn-tunnel':
                self.close_connection = True
                ppp_tunnel(self.connection, self.rfile, mode_path); return
            self.reply()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory/'forti.crt', directory/'forti.key')
    context.load_verify_locations(directory/'ca.crt'); context.verify_mode = ssl.CERT_OPTIONAL
    server = ThreadingHTTPServer((address, 10443), Handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == '__main__': main(*sys.argv[1:])
