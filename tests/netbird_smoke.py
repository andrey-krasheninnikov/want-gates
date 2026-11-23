#!/usr/bin/env python3
"""Exercise two native NetBird accounts through the Want Gates routing stand."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

import routing_smoke as stand

COMPANIES = ('a', 'b')
PRIVATE = ('10.220.0.10', 'fd42:220::10')
EXIT = ('1.1.1.1', '2606:4700::1111')
CAPABILITIES = ('tcp_ipv4', 'udp_ipv4', 'tcp_ipv6', 'udp_ipv6')


def host(mode, family, company):
    return f'{mode}.v{family}.{company}.corp.test'


UDP_TARGETS = {
    (mode, family, company): 15400 + index
    for index, (mode, family, company) in enumerate(
        (mode, family, company)
        for mode in ('private', 'exit') for family in (4, 6) for company in COMPANIES
    )
}


def witness(company, events):
    lock = threading.Lock()

    def record(transport, name, peer):
        with lock, open(events, 'a') as file:
            file.write(json.dumps(dict(transport=transport, name=name, peer=peer)) + '\n')

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            record('tcp', self.path, self.client_address[0])
            body = json.dumps(dict(company=company, peer=self.client_address[0])).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class IPv6(ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    for server_type, address in ((ThreadingHTTPServer, '0.0.0.0'), (IPv6, '::')):
        server = server_type((address, 18080), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def dns(sock):
        while True:
            query, peer = sock.recvfrom(4096)
            end = query.find(b'\0', 12)
            if end < 12 or len(query) < end + 5:
                continue
            labels, pos = [], 12
            while pos < end and 0 < query[pos] <= 63 and pos + query[pos] < end:
                size = query[pos]
                labels.append(query[pos+1:pos+1+size].decode('ascii', errors='replace'))
                pos += size + 1
            if pos != end:
                continue
            name = '.'.join(labels)
            record('udp', name, peer[0])
            kind = struct.unpack('!H', query[end+1:end+3])[0]
            family = socket.AF_INET6 if kind == 28 else socket.AF_INET
            if name.endswith(f'.{company}.corp.test'):
                index = int(kind == 28)
                address = (EXIT if 'exit' in labels else PRIVATE)[index]
                if 'who' in labels:
                    address = f'198.18.{COMPANIES.index(company)+1}.1'
                if (index and 'v4' in labels) or (not index and 'v6' in labels):
                    address = None
            elif name.endswith('.corp.test'):
                address = None
            else:
                address = f'198.18.{COMPANIES.index(company)+1}.1'
            answer = b''
            if address and kind in (1, 28):
                packed = socket.inet_pton(family, address)
                answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(packed)) + packed
            sock.sendto(query[:2] + struct.pack('!5H', 0x8180, 1, bool(answer), 0, 0)
                        + query[12:end+5] + answer, peer)

    # Reply from the address that received the datagram, including exit aliases.
    for family, address in ((socket.AF_INET, PRIVATE[0]), (socket.AF_INET, EXIT[0]),
                            (socket.AF_INET6, PRIVATE[1]), (socket.AF_INET6, EXIT[1])):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, 15353))
        threading.Thread(target=dns, args=(sock,), daemon=True).start()
    threading.Event().wait()


def wait_for(description, read, ready=bool, seconds=35):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = read()
        if ready(value):
            return value
        time.sleep(.25)
    raise RuntimeError(f'{description} timed out')


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)



def server_config(work, address, port, geodata=()):
    cert, key = work / 'cert.pem', work / 'key.pem'
    stand.checked('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                  '-subj', f'/CN={address}', '-addext', f'subjectAltName=IP:{address}',
                  '-keyout', str(key), '-out', str(cert))
    database = work / 'server'
    database.mkdir(mode=0o700)
    for path in geodata:
        shutil.copyfile(path, database / path.name)
    url = f'https://{address}:{port}'
    config = work / 'server.yaml'
    config.write_text(json.dumps(dict(server=dict(
        listenAddress=f'{address}:{port}', exposedAddress=url,
        tls=dict(certFile=str(cert), keyFile=str(key)),
        authSecret=secrets.token_hex(32), dataDir=str(database),
        auth=dict(issuer=url + '/oauth2'), store=dict(
            engine='sqlite', encryptionKey=base64.b64encode(secrets.token_bytes(32)).decode()),
        disableAnonymousMetrics=True, disableGeoliteUpdate=True,
    ))))
    return config, dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', SSL_CERT_FILE=str(cert),
                        NB_FORCE_RELAY='true')


def geodata_files(directory):
    for pattern in ('GeoLite2-City_*.mmdb', 'geonames_*.db'):
        files = list(directory.glob(pattern))
        if len(files) != 1 or not files[0].is_file() or not files[0].stat().st_size:
            raise ValueError(f'{directory} must contain one nonempty {pattern}')
        yield files[0]


def prepare_geodata(server, destination):
    assert not destination.exists() and not destination.is_symlink()
    with tempfile.TemporaryDirectory(prefix='wgates-netbird-geo-') as temporary:
        work = Path(temporary)
        config, env = server_config(work, '127.0.0.1', 18443)
        process = subprocess.Popen([server.resolve(strict=True), '--config', config],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            def ready():
                if process.poll() is not None:
                    raise RuntimeError(f'GeoIP bootstrap server exited with {process.returncode}')
                return stand.run('curl', '--max-time', '2', '-fsS', '--noproxy', '*',
                                 '--cacert', str(work / 'cert.pem'),
                                 'https://127.0.0.1:18443/api/instance').returncode == 0

            wait_for('NetBird GeoIP bootstrap', ready, seconds=240)
            files = list(geodata_files(work / 'server'))
            destination.mkdir(mode=0o700)
            for path in files:
                shutil.copyfile(path, destination / path.name)
        finally:
            stop(process)


class Company:
    def __init__(self, context, company, bridge, client, server, geodata, cleanup):
        self.name = company
        self.client = client
        self.gateway = context['names']['gateway']
        self.bridge = bridge['namespace']
        self.router = context['names'][company]
        self.work = context['work'] / company
        self.work.mkdir(mode=0o700)
        self.events = self.work / 'events.jsonl'
        self.ip = f'10.{213 + COMPANIES.index(company)}.0.2'
        self.url = f'https://{self.ip}:18443'
        config, self.env = server_config(self.work, self.ip, 18443, geodata)
        self.token = None
        control_plane = self.spawn(self.router, [server, '--config', config], 'server', cleanup,
                                   dict(self.env, NB_SETUP_PAT_ENABLED='true'))

        def ready():
            if control_plane.poll() is not None:
                raise RuntimeError(f'{company} control plane exited with {control_plane.returncode}')
            return self.api('/instance', pending=True)

        wait_for(f'{company} control plane', ready)
        self.token = self.api('/setup', dict(email=f'owner@{company}.test', name='Stand owner',
                                            password=secrets.token_urlsafe(32), create_pat=True)
                              )['personal_access_token']
        self.lan = f'{context["prefix"]}-lan-{company}'
        stand.checked('ip', 'netns', 'add', self.lan)
        cleanup.callback(stand.checked, 'ip', 'netns', 'del', self.lan)
        slot = COMPANIES.index(company) + 1
        left, right = f'nb{slot}router', f'nb{slot}lan'
        self.run(self.router, 'ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
        self.run(self.router, 'ip', 'link', 'set', right, 'netns', self.lan)
        self.run(self.lan, 'ip', 'link', 'set', 'lo', 'up')
        for namespace, interface, v4, v6 in (
            (self.router, left, '10.220.0.1', 'fd42:220::1'),
            (self.lan, right, *PRIVATE),
        ):
            self.run(namespace, 'sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=0',
                     f'net.ipv6.conf.{interface}.disable_ipv6=0')
            self.run(namespace, 'ip', 'addr', 'add', v4 + '/24', 'dev', interface)
            self.run(namespace, 'ip', '-6', 'addr', 'add', v6 + '/64', 'dev', interface, 'nodad')
            self.run(namespace, 'ip', 'link', 'set', interface, 'up')
        for family, network, via, destination in (
            ('-4', '10.220.0.0/24', PRIVATE[0], EXIT[0] + '/32'),
            ('-6', 'fd42:220::/64', PRIVATE[1], EXIT[1] + '/128'),
        ):
            self.run(self.router, 'ip', family, 'route', 'del', network, 'proto', 'boot')
            self.run(self.router, 'ip', family, 'route', 'replace', destination, 'via', via)
            self.run(self.lan, 'ip', family, 'addr', 'add', destination, 'dev', 'lo')
        self.run(self.router, 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
        self.spawn(self.lan, [sys.executable, __file__, '--witness', company, self.events],
                   'witness', cleanup)
        self.router_port = 51900 + slot
        self.gateway_port = 51820 + slot
        self.start(self.router, 'router', cleanup)
        self.enroll(self.router, 'router', self.router_port, 'nb-router')
        self.start(self.bridge, 'gateway', cleanup)
        self.enroll(self.bridge, 'gateway', self.gateway_port, 'wgates-tun')
        peers = {peer['name']: peer['id'] for peer in self.api('/peers')}
        assert set(peers) == {'gateway', 'router'}, 'control plane peer inventory differs'
        self.peer = peers['gateway']
        group = next(group['id'] for group in self.api('/groups') if group['name'] == 'All')
        resource_group = self.api('/groups', dict(name='Private LAN', peers=[]))['id']
        network = self.api('/networks', dict(name='private', description='Company LAN'))['id']
        self.api(f'/networks/{network}/routers', dict(peer=peers['router'], metric=100,
                                                      masquerade=True, enabled=True))
        for cidr in ('10.220.0.0/24', 'fd42:220::/64'):
            self.api(f'/networks/{network}/resources', dict(
                name=cidr, address=cidr, enabled=True, groups=[resource_group]))
        self.api('/policies', dict(name='Private LAN', enabled=True, rules=[dict(
            name='Private LAN', enabled=True, action='accept', protocol='all',
            bidirectional=False, sources=[group], destinations=[resource_group])]))
        self.api('/routes', dict(description='Test exit', network_id='exit', enabled=True,
                                 peer=peers['router'], network='0.0.0.0/0', metric=100,
                                 masquerade=True, groups=[group], keep_route=True,
                                 skip_auto_apply=True))

    def api(self, endpoint, payload=None, pending=False):
        result = stand.run('ip', 'netns', 'exec', self.gateway, sys.executable, __file__,
                           '--api', self.url + '/api' + endpoint, str(self.work / 'cert.pem'),
                           input=json.dumps(dict(payload=payload, token=self.token)), timeout=8)
        if not result.returncode:
            status, value = json.loads(result.stdout)
            if 200 <= status < 300:
                return value
            if pending and status in (0, 503):
                return None
            raise RuntimeError(f'{self.name} NetBird API {endpoint} returned {status}')
        raise RuntimeError(f'{self.name} NetBird API helper failed')

    @staticmethod
    def run(namespace, *args):
        return stand.checked('ip', 'netns', 'exec', namespace, *map(str, args))

    def spawn(self, namespace, args, label, cleanup, env=None):
        with (self.work / (label + '.log')).open('ab') as log:
            process = subprocess.Popen(['ip', 'netns', 'exec', namespace, *map(str, args)],
                                       env=env, stdout=log, stderr=log)
        cleanup.callback(stop, process)
        return process

    def state(self, role):
        return self.work / role

    def start(self, namespace, role, cleanup):
        state = self.state(role)
        state.mkdir(mode=0o700, exist_ok=True)
        args = [self.client, '--daemon-addr', f'unix://{state}/control.sock',
                '--config', state / 'config.json', '--log-file', 'console', 'service', 'run']
        process = self.spawn(namespace, args, role, cleanup, dict(self.env, NB_STATE_DIR=str(state)))
        def ready():
            if process.poll() is not None:
                raise RuntimeError(f'{self.name} {role} daemon exited with {process.returncode}')
            return (state / 'control.sock').is_socket()

        wait_for(f'{self.name} {role} control socket', ready)
        if role == 'gateway':
            self.process = process

    def cli(self, namespace, role, *command):
        state = self.state(role)
        result = stand.run('ip', 'netns', 'exec', namespace, str(self.client),
                           '--daemon-addr', f'unix://{state}/control.sock',
                           '--log-file', 'console', *map(str, command),
                           env=dict(self.env, NB_STATE_DIR=str(state)), timeout=50)
        if result.returncode:
            raise RuntimeError(f'{self.name} NetBird {role} {command[0]} failed')
        return result.stdout

    def enroll(self, namespace, role, port, interface):
        key = self.api('/setup-keys', dict(name=role, type='one-off', expires_in=86400,
                                           auto_groups=[], usage_limit=1))['key']
        path = self.work / 'setup-key'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, 'w') as file:
                file.write(key)
            self.cli(namespace, role, 'up', '--management-url', self.url, '--setup-key-file', path,
                     '--interface-name', interface, '--wireguard-port', port,
                     '--hostname', role, '--disable-dns', '--disable-auto-connect=false')
        finally:
            path.unlink()

    def select_exit(self):
        wait_for(f'{self.name} advertised exit', lambda: self.cli(self.bridge, 'gateway', 'networks', 'list'),
                 lambda value: 'exit' in value)
        self.cli(self.bridge, 'gateway', 'networks', 'select', '-a', 'exit')


def api_request(url, cert):
    arguments = json.load(sys.stdin)
    body = json.dumps(arguments['payload']).encode() if arguments['payload'] is not None else None
    request = Request(url, data=body, headers={'Content-Type': 'application/json'})
    if arguments['token']:
        request.add_header('Authorization', 'Token ' + arguments['token'])
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=cert)))
    try:
        with opener.open(request, timeout=3) as response:
            print(json.dumps([response.status, json.load(response)]))
    except HTTPError as error:
        print(json.dumps([error.code, None]))
    except (URLError, TimeoutError):
        print('[0, null]')


def close_bridges(process):
    process.stdin.close()
    try:
        code = process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        stop(process)
        raise RuntimeError('native bridge cleanup timed out') from None
    assert code == 0, 'native bridge setup or cleanup failed'


def acceptance(context, native_test, client, server, geodata):
    ns, control, work = context['ns'], context['control'], context['work']
    gateway, ingress = context['names']['gateway'], context['names']['client']
    for option in ('net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1'):
        ns('gateway', 'sysctl', '-qw', option)

    ns('gateway', 'ip', '-4', 'route', 'add', 'default', 'via', '10.210.0.2')
    ns('gateway', 'ip', '-6', 'route', 'add', 'default', 'via', 'fd42:210::2')

    def management_path():
        configuration = tuple(ns('gateway', 'ip', family, '-j', 'rule', 'show').stdout
                              for family in ('-4', '-6'))
        routes = tuple(ns('gateway', 'ip', family, '-j', 'route', 'show', 'default').stdout
                       for family in ('-4', '-6'))
        assert context['api']('server/status')['xray']['state'] == 'running'
        assert control('status')
        return configuration, routes

    baseline = management_path()

    def client_run(*args):
        return stand.run('ip', 'netns', 'exec', ingress, *map(str, args), timeout=12)

    def tcp(name, company=None, marker=None):
        marker = marker or secrets.token_hex(8)
        result = client_run('curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:10880',
                            '--max-time', '8', '-fsS', f'http://{name}:18080/{marker}')
        if company is None:
            assert result.returncode != 0, f'protected TCP escaped for {name}'
            return marker
        assert result.returncode == 0, f'TCP to {name} failed'
        assert json.loads(result.stdout)['company'] == company, f'TCP to {name} reached wrong company'
        return marker

    def query(name, expected=None):
        result = client_run(sys.executable, stand.__file__, '--dns-query', 'udp', name, '1')
        value = json.loads(result.stdout)['answer'] if not result.returncode else None
        assert value == expected, f'wrong DNS result for {name}'

    def udp(mode, family, company, expected):
        marker = secrets.token_hex(8) + '.payload.test'
        result = client_run(sys.executable, stand.__file__, '--udp',
                            UDP_TARGETS[mode, family, company], marker)
        value = json.loads(result.stdout)['answer'] if not result.returncode else None
        assert value == expected, f'wrong UDP result for {mode}/IPv{family}/{company}'
        return marker

    def events(company):
        return [json.loads(line) for line in company.events.read_text().splitlines()] if company.events.exists() else []

    def seen(records, marker):
        return any(marker in record.get('name', record.get('marker', '')) for record in records)

    def verify_path(company, other, marker):
        assert seen(events(company), marker), f'{company.name} witness did not receive {marker}'
        assert not seen(events(other), marker), f'{other.name} witness received {marker}'
        assert not seen(direct(), marker), f'direct witness received {marker}'

    def direct():
        return [json.loads(line) for line in context['events'].read_text().splitlines()]

    def denied(companies, marker):
        assert not seen(direct(), marker), f'direct witness received protected {marker}'
        assert not any(seen(events(company), marker) for company in companies), \
            f'company witness received blocked {marker}'

    bridge_dir = work / 'native-bridges'
    nobody = pwd.getpwnam('nobody')
    with ExitStack() as cleanup:
        process = subprocess.Popen(
            # Keep the stand's mount namespace so peer namespace mounts are visible here.
            ['nsenter', f'--net=/run/netns/{gateway}', str(native_test),
             'native_runtime::netbird_fixture::bridges', '--exact', '--ignored', '--nocapture'],
            stdin=subprocess.PIPE, text=True,
        )
        cleanup.callback(close_bridges, process)
        process.stdin.write(json.dumps(dict(directory=str(bridge_dir), xray=str(context['xray']),
                                           uid=nobody.pw_uid, gid=nobody.pw_gid,
                                           servers=['10.213.0.2:18443', '10.214.0.2:18443'])) + '\n')
        process.stdin.flush()
        manifest = bridge_dir / 'bridges.json'
        wait_for('native bridges', manifest.is_file)
        bridges = json.loads(manifest.read_text())
        assert len({entry['namespace'] for entry in bridges}) == 2
        companies = [Company(context, label, bridge, client, server, geodata, cleanup)
                     for label, bridge in zip(COMPANIES, bridges, strict=True)]
        print('Both native NetBird accounts registered', flush=True)

        for company, bridge in zip(companies, bridges, strict=True):
            name = company.name
            group = control('group', 'create', '--name', f'Company {name}')['data']['id']
            connection = control(
                'connection', 'import', '--group', group, '--name', f'NetBird bridge {name}',
                '--protocol', 'vless', '--file', '-', '--dns', f'udp://{PRIVATE[0]}:15353',
                payload=context['outbound'](bridge['address'], bridge['port'], bridge['id']),
            )['data']['id']
            probes = {
                f'tcp_ipv{family}': dict(url=f'http://{address}:18080/probe')
                for family, address in ((4, PRIVATE[0]), (6, f'[{PRIVATE[1]}]'))
            }
            probes.update({
                f'udp_ipv{family}': dict(server=f'{address}:15353', query_name='probe.example.test',
                                        query_type='A')
                for family, address in ((4, PRIVATE[0]), (6, f'[{PRIVATE[1]}]'))
            })
            probes['dns'] = dict(query_name=f'probe.private.v4.{name}.corp.test', query_type='A')
            control('group', 'update', group, '--primary', connection, '--probe-file', '-', payload=probes)
            control('rule', 'create', '--group', group, '--destination', f'{name}.corp.test')
            company.group = group

        preview = control('routing', 'preview')['data']
        applied = control('routing', 'apply', preview['plan_id'])['data']
        verified = {}
        for company in companies:
            capabilities = applied['capabilities'][company.group]
            assert capabilities['tcp_ipv4'] == capabilities['dns'] == 'verified', \
                f'IPv4 or DNS did not pass for {company.name}: {capabilities}'
            verified[company.name] = {cap for cap in CAPABILITIES if capabilities[cap] == 'verified'}

        for company in companies:
            interface = json.loads(company.run(company.bridge, 'ip', '-j', 'link', 'show',
                                               'dev', 'wgates-tun').stdout)
            assert len(interface) == 1 and 'UP' in interface[0]['flags'], 'native tunnel is not up'
            assert company.run(company.bridge, 'ss', '-H', '-lun',
                               f'sport = :{company.gateway_port}').stdout.strip(), 'missing WireGuard port'
        print('IPv4 and private DNS passed resource probes in both namespaces', flush=True)

        for index, company in enumerate(companies):
            other = companies[1 - index]
            # The normal direct route and witness are still available.
            result = client_run('curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:10880',
                                '--max-time', '5', '-fsS', 'http://1.1.1.1:18080/netbird-direct')
            assert result.returncode == 0 and json.loads(result.stdout)['peer'] == '10.210.0.1'
            denied(companies, tcp(host('exit', 4, company.name)))
            tag = secrets.token_hex(8)
            query(f'{tag}.who.private.v4.{company.name}.corp.test', f'198.18.{index+1}.1')
            verify_path(company, other, tag)
            for family in (4, 6):
                allowed = verified[company.name]
                target = host('private', family, company.name)
                if f'tcp_ipv{family}' in allowed:
                    verify_path(company, other, tcp(target, company.name))
                else:
                    denied(companies, tcp(target))
                tag = udp('private', family, company.name, f'198.18.{index+1}.1'
                          if f'udp_ipv{family}' in allowed else None)
                if f'udp_ipv{family}' in allowed:
                    verify_path(company, other, tag)
                else:
                    denied(companies, tag)

        for company in companies:
            company.select_exit()
        print('Private routes, overlapping resources and DNS isolated', flush=True)
        for index, company in enumerate(companies):
            other = companies[1 - index]
            wait_for(f'{company.name} exit route', lambda: client_run(
                'curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:10880', '--max-time', '3',
                '-fsS', f'http://{host("exit", 4, company.name)}:18080/exit-ready').returncode == 0)
            for family in (4, 6):
                target = host('exit', family, company.name)
                allowed = verified[company.name]
                if f'tcp_ipv{family}' in allowed:
                    verify_path(company, other, tcp(target, company.name))
                else:
                    denied(companies, tcp(target))
                tag = udp('exit', family, company.name, f'198.18.{index+1}.1'
                          if f'udp_ipv{family}' in allowed else None)
                if f'udp_ipv{family}' in allowed:
                    verify_path(company, other, tag)
                else:
                    denied(companies, tag)
            tag = secrets.token_hex(8)
            query(f'{tag}.who.exit.v4.{company.name}.corp.test', f'198.18.{index+1}.1')
            verify_path(company, other, tag)
        assert management_path() == baseline

        a, b = companies
        keep_running = threading.Event()
        witnessed = threading.Event()

        def monitor_b():
            count = 0
            while not keep_running.is_set():
                verify_path(b, a, tcp(host('exit', 4, 'b'), 'b'))
                tag = secrets.token_hex(8)
                query(f'{tag}.who.private.v4.b.corp.test', '198.18.2.1')
                verify_path(b, a, tag)
                count += 1
                witnessed.set()
                keep_running.wait(.25)
            return count

        def assert_a_blocked():
            denied(companies, tcp(host('exit', 4, 'a')))
            tag = secrets.token_hex(8)
            query(f'{tag}.who.private.v4.a.corp.test')
            denied(companies, tag)
            assert management_path() == baseline

        def check_a_recovery():
            target = host('private', 4, 'a')
            wait_for('A private route recovery', lambda: client_run(
                'curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:10880', '--max-time', '3',
                '-fsS', f'http://{target}:18080/recovery').returncode == 0)
            verify_path(a, b, tcp(target, 'a'))
            a.select_exit()
            verify_path(a, b, tcp(host('exit', 4, 'a'), 'a'))

        with ThreadPoolExecutor(max_workers=1) as pool:
            watcher = pool.submit(monitor_b)
            try:
                assert witnessed.wait(15), 'B did not produce baseline traffic'
                stop(a.process)
                assert_a_blocked()
                a.start(a.bridge, 'gateway', cleanup)
                check_a_recovery()
                a.cli(a.bridge, 'gateway', 'deregister')
                assert_a_blocked()
                a.enroll(a.bridge, 'gateway', a.gateway_port, 'wgates-tun')
                check_a_recovery()
                assert management_path() == baseline
            finally:
                keep_running.set()
            assert watcher.result() >= 3, 'B did not stay under traffic through recovery'
        print('Both companies passed exit routing; B stayed reachable through A restart and enrollment',
              flush=True)
        for name, observed in verified.items():
            print(f'{name} verified private/exit capabilities: {", ".join(sorted(observed))}', flush=True)
    remaining = stand.checked('ip', 'netns', 'list').stdout
    assert all(company.lan not in remaining and company.bridge not in remaining for company in companies)
    print('NetBird test namespaces and processes removed', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('wgates', 'panel_root', 'native_test', 'netbird', 'netbird_server'):
        parser.add_argument(arg, type=Path)
    parser.add_argument('--geodata', type=Path, required=True)
    args = parser.parse_args()
    paths = [path.resolve(strict=True) for path in
             (args.wgates, args.panel_root, args.native_test, args.netbird, args.netbird_server)]
    assert stand.checked(str(paths[3]), 'version').stdout.strip() == '0.83.2'
    geodata = list(geodata_files(args.geodata))
    os.umask(0o077)
    stand.main(*paths[:2], native_acceptance=lambda context: acceptance(context, *paths[2:], geodata),
               extra_udp_targets=[(port, host(*target)) for target, port in UDP_TARGETS.items()])


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--witness':
        witness(*sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == '--api':
        api_request(*sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == '--prepare-geodata':
        os.umask(0o077)
        prepare_geodata(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        main()
