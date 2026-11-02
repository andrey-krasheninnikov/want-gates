#!/usr/bin/env python3
"""Run real VLESS traffic only on a disposable local Linux systemd host."""
import argparse
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def dns_query(name):
    query = struct.pack('!6H', secrets.randbits(16), 0x100, 1, 0, 0, 0)
    for label in name.split('.'):
        query += bytes([len(label)]) + label.encode()
    return query + b'\0' + struct.pack('!HH', 1, 1)


def resource(events):
    lock = threading.Lock()

    def record(transport, peer, marker):
        with lock, open(events, 'a') as file:
            file.write(json.dumps(dict(transport=transport, peer=peer, marker=marker)) + '\n')

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            record('tcp', self.client_address[0], self.path)
            body = json.dumps(dict(peer=self.client_address[0])).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class V6(ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    for cls, address in [(ThreadingHTTPServer, '0.0.0.0'), (V6, '::')]:
        server = cls((address, 18080), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    for family, address in [(socket.AF_INET, '10.220.0.10'), (socket.AF_INET, '10.221.0.10'), (socket.AF_INET6, 'fd42:220::10'), (socket.AF_INET6, 'fd42:221::10')]:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, 15353))

        def answer(sock=sock):
            while True:
                query, peer = sock.recvfrom(4096)
                if len(query) < 17:
                    continue
                position, labels = 12, []
                while query[position]:
                    size = query[position]
                    labels.append(query[position + 1:position + 1 + size].decode())
                    position += size + 1
                question = query[12:position + 5]
                kind = struct.unpack('!H', query[position + 1:position + 3])[0]
                source = ipaddress.ip_address(peer[0])
                company = 1 if source in ipaddress.ip_network('10.211.0.0/24') or source in ipaddress.ip_network('fd42:211::/64') else 2 if source in ipaddress.ip_network('10.212.0.0/24') or source in ipaddress.ip_network('fd42:212::/64') else 0
                result = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6, f'198.18.{company}.1' if kind == 1 else f'fd43::{company + 1}')
                packet = query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + question
                packet += b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(result)) + result
                record('udp', peer[0], '.'.join(labels))
                sock.sendto(packet, peer)

        threading.Thread(target=answer, daemon=True).start()
    signal.pause()


def udp_client(port, marker):
    query = dns_query(marker)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(query, ('127.0.0.1', int(port)))
        packet = sock.recv(4096)
    assert packet[:2] == query[:2] and len(packet) >= len(query) + 16
    print(json.dumps(dict(answer=socket.inet_ntop(socket.AF_INET, packet[-4:]))))


def fault_proxy(flag):
    class Proxy(BaseHTTPRequestHandler):
        def handle_request(self):
            size=int(self.headers.get('Content-Length','0'))
            body=self.rfile.read(size) if size else None
            headers={'Authorization':self.headers.get('Authorization',''),'Content-Type':self.headers.get('Content-Type','application/x-www-form-urlencoded')}
            request=urllib.request.Request('http://127.0.0.1:20530'+self.path,data=body,headers=headers,method=self.command)
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                with opener.open(request,timeout=15) as response:result=response.read()
                mode=''
                if self.path.endswith('/xray/update') and Path(flag).exists():
                    mode=Path(flag).read_text().strip()
                    Path(flag).write_text('')
                if mode=='intervening':
                    req=urllib.request.Request('http://127.0.0.1:20530/panel/api/xray/',data=b'',headers=headers)
                    with opener.open(req,timeout=10) as response:value=json.loads(response.read())['obj']
                    if isinstance(value,str):value=json.loads(value)
                    value['xraySetting']['log']['loglevel']='error'
                    data=urllib.parse.urlencode(dict(xraySetting=json.dumps(value['xraySetting']),outboundTestUrl=value['outboundTestUrl'])).encode()
                    req=urllib.request.Request('http://127.0.0.1:20530/panel/api/xray/update',data=data,headers=headers)
                    with opener.open(req,timeout=15) as response:assert json.loads(response.read())['success']
                if mode:
                    self.send_response(500)
                    result=b'{"success":false}'
                else:self.send_response(200)
                self.send_header('Content-Length',str(len(result)))
                self.end_headers();self.wfile.write(result)
            except (urllib.error.URLError,ConnectionError):
                self.send_error(502)
        do_GET=handle_request
        do_POST=handle_request
        def log_message(self,*_):pass
    ThreadingHTTPServer(('127.0.0.1',20531),Proxy).serve_forever()


def run(*args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, timeout=kwargs.pop('timeout', 30), **kwargs)


def checked(*args, **kwargs):
    result = run(*args, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr[:600]}')
    return result


def main(binary, panel_root):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Run only as root on a disposable Linux systemd host.')
    repo = Path(__file__).resolve().parent.parent
    binary, panel_root = Path(binary).resolve(strict=True), Path(panel_root).resolve(strict=True)
    xray = next((panel_root / 'bin').glob('xray-linux-*'))
    assert '26.9.9' in checked(str(xray), 'version').stdout
    prefix = f'wgates-routing-{os.getpid()}'
    names = {key: f'{prefix}-{key}' for key in ['client', 'gateway', 'a', 'b', 'resource']}
    unit = Path('/run/systemd/system') / f'{prefix}.service'
    runtime, state = Path('/run') / prefix, Path('/var/lib') / prefix
    installed = Path('/usr/local/bin') / prefix
    processes, logs, created = [], [], []
    account_attempted = False
    installed_created = unit_created = start_attempted = False
    temporary = tempfile.TemporaryDirectory(prefix='wgates-routing-', dir='/var/tmp')
    work = Path(temporary.name)

    def ns(name, *args, **kwargs):
        return checked('ip', 'netns', 'exec', names[name], *map(str, args), **kwargs)

    def spawn(name, args, label, env=None, cwd=None):
        log = open(work / f'{label}.log', 'w+')
        logs.append((label, log))
        process = subprocess.Popen(['ip', 'netns', 'exec', names[name], *map(str, args)], stdout=log, stderr=log, env=env, cwd=cwd)
        processes.append(process)
        return process

    def link(left, right, index, left_ip=1, right_ip=2):
        a, b = f'w4{index}a', f'w4{index}b'
        checked('ip', 'link', 'add', a, 'type', 'veth', 'peer', 'name', b)
        checked('ip', 'link', 'set', a, 'netns', names[left])
        checked('ip', 'link', 'set', b, 'netns', names[right])
        for name, interface, address in [(left, a, left_ip), (right, b, right_ip)]:
            ns(name, 'sysctl', '-q', '-w', f'net.ipv6.conf.{interface}.disable_ipv6=0')
            ns(name, 'ip', 'addr', 'add', f'10.{index}.0.{address}/24', 'dev', interface)
            ns(name, 'ip', '-6', 'addr', 'add', f'fd42:{index}::{address}/64', 'dev', interface, 'nodad')
            ns(name, 'ip', 'link', 'set', interface, 'up')

    try:
        assert not any(path.exists() or path.is_symlink() for path in [unit, runtime, state, installed])
        for lookup in [pwd.getpwnam,grp.getgrnam]:
            try:lookup(prefix)
            except KeyError:pass
            else:raise RuntimeError('test account or group already exists')

        for namespace in names.values():
            checked('ip', 'netns', 'add', namespace)
            created.append(namespace)
        for name in names:
            ns(name, 'sysctl', '-q', '-w', 'net.ipv6.conf.all.disable_ipv6=0', 'net.ipv6.conf.default.disable_ipv6=0')
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
        link('gateway', 'resource', 210)
        link('a', 'resource', 211)
        link('b', 'resource', 212)
        link('gateway', 'a', 213)
        link('gateway', 'b', 214)
        link('gateway', 'client', 215)
        for index in [220, 221]:
            ns('resource', 'ip', 'addr', 'add', f'10.{index}.0.10/32', 'dev', 'lo')
            ns('resource', 'ip', '-6', 'addr', 'add', f'fd42:{index}::10/128', 'dev', 'lo', 'nodad')
            for name, transit in [('gateway', 210), ('a', 211), ('b', 212)]:
                ns(name, 'ip', 'route', 'add', f'10.{index}.0.0/24', 'via', f'10.{transit}.0.2')
                ns(name, 'ip', '-6', 'route', 'add', f'fd42:{index}::/64', 'via', f'fd42:{transit}::2')
        ns('resource', 'ip', 'addr', 'add', '10.220.0.200/32', 'dev', 'lo')
        ns('resource','ip','addr','add','1.1.1.1/32','dev','lo')
        ns('resource','ip','-6','addr','add','2606:4700::1111/128','dev','lo','nodad')
        ns('gateway','ip','route','add','1.1.1.1/32','via','10.210.0.2')
        ns('gateway','ip','-6','route','add','2606:4700::1111/128','via','fd42:210::2')

        events = work / 'events.jsonl'
        resource_process = spawn('resource', ['python3', __file__, '--resource', events], 'resources')
        capture = spawn('resource',['tcpdump','-ni','any','-l','tcp port 18080 or udp port 15353'],'resource-packets')
        ids = {key: str(uuid.uuid4()) for key in ['ingress', 'a', 'b']}

        def start_xray(name, config):
            path = work / f'{name}.json'
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            return spawn(name, [xray, 'run', '-config', path], f'xray-{name}', cwd=panel_root)

        def outbound(address, port, identity):
            return dict(protocol='vless', settings=dict(address=address, port=port, id=identity, encryption='none'), streamSettings=dict(network='raw', security='none'))

        exits = {}
        for name, index, port in [('a', 213, 19001), ('b', 214, 19002)]:
            exits[name] = start_xray(name, dict(log=dict(loglevel='info'), inbounds=[dict(tag='vpn', listen=f'10.{index}.0.2', port=port, protocol='vless', settings=dict(clients=[dict(id=ids[name])], decryption='none'))], outbounds=[dict(protocol='freedom',settings=dict(finalRules=[dict(action='allow',ip=['10.220.0.0/24','10.221.0.0/24','fd42:220::/64','fd42:221::/64'])]))]))
        env = dict(os.environ, XUI_DB_FOLDER=str(work / 'panel-db'), XUI_LOG_FOLDER=str(work / 'panel-log'), XUI_BIN_FOLDER=str(panel_root / 'bin'), XUI_ENABLE_FAIL2BAN='false')
        checked(str(panel_root / 'x-ui'), 'setting', '-port', '20530', '-listenIP', '127.0.0.1', '-webBasePath', '/', '-username', 'stand-operator', '-password', secrets.token_hex(24), env=env, cwd=panel_root)
        result = checked(str(panel_root / 'x-ui'), 'setting', '-getApiToken', '-tokenName', prefix, env=env, cwd=panel_root)
        token = re.search(r'^apiToken:\s*(\S+)\s*$', result.stdout, re.M).group(1)
        panel = spawn('gateway', [panel_root / 'x-ui', 'run'], 'panel', env=env, cwd=panel_root)
        # Requests run inside the gateway namespace without exposing a host port.
        api_helper = work / 'api.py'
        api_helper.write_text('''import json,sys,urllib.request,urllib.parse
request=json.load(sys.stdin)
data=urllib.parse.urlencode(request["form"]).encode() if request["form"] is not None else None
req=urllib.request.Request("http://127.0.0.1:20530/panel/api/"+request["path"],data=data,headers={"Authorization":"Bearer "+request["token"]})
with urllib.request.urlopen(req,timeout=10) as response: print(response.read().decode())
''')
        api_helper.chmod(0o600)

        def api(path, form=None):
            value=json.loads(ns('gateway', 'python3', api_helper, input=json.dumps(dict(path=path,form=form,token=token))).stdout)
            assert value['success'], 'test panel rejected API request'
            return value.get('obj')

        deadline=time.monotonic()+30
        while True:
            assert panel.poll() is None, 'panel stopped during startup'
            try:
                status=api('server/status')
                if status['xray']['state']=='running' and status['xray']['version']=='26.9.9':break
            except (RuntimeError,KeyError,TypeError): pass
            assert time.monotonic()<deadline,'panel did not become ready'
            time.sleep(0.2)
        api('inbounds/add',dict(enable='true',remark='routing stand',listen='10.215.0.1',port='19000',protocol='vless',settings=json.dumps(dict(clients=[dict(id=ids['ingress'],email='stand-client',enable=True)],decryption='none')),streamSettings=json.dumps(dict(network='tcp',security='none')),sniffing=json.dumps(dict(enabled=True,destOverride=['http','tls'],routeOnly=True))))
        settings=api('xray/',{})
        if isinstance(settings,str):settings=json.loads(settings)
        baseline=settings['xraySetting']
        baseline['log']['loglevel']='warning'
        baseline['outbounds'].append(dict(tag='retained-outbound',protocol='blackhole',settings={}))
        baseline['routing']['rules'].append(dict(type='field',inboundTag=['retained-inbound'],outboundTag='retained-outbound'))
        api('xray/update',dict(xraySetting=json.dumps(baseline),outboundTestUrl=settings['outboundTestUrl']))
        settings=api('xray/',{})
        if isinstance(settings,str):settings=json.loads(settings)
        baseline=settings['xraySetting']
        inbounds=[dict(tag='client-socks',listen='127.0.0.1',port=10880,protocol='socks',settings=dict(auth='noauth',udp=True))]
        for port,address in [(15354,'10.220.0.10'),(15355,'10.221.0.10'),(15356,'fd42:220::10'),(15357,'fd42:221::10')]:
            inbounds.append(dict(tag=f'udp-{port}',listen='127.0.0.1',port=port,protocol='dokodemo-door',settings=dict(address=address,port=15353,network='udp')))
        client=start_xray('client',dict(log=dict(loglevel='warning'),inbounds=inbounds,outbounds=[outbound('10.215.0.1',19000,ids['ingress'])]))
        with installed.open('xb') as destination:
            installed_created=True
            with binary.open('rb') as source:shutil.copyfileobj(source,destination)
        installed.chmod(0o755)
        account=work / 'sysusers.conf'
        account.write_text((repo/'packaging/sysusers.d/wgates.conf').read_text().replace('wgates',prefix))
        account_attempted=True
        checked('systemd-sysusers',str(account))
        uid=pwd.getpwnam(prefix).pw_uid
        text=(repo/'packaging/systemd/wgates.service').read_text().replace('wgates',prefix)
        text=text.replace('[Service]','[Service]\nNetworkNamespacePath=/run/netns/'+names['gateway'])
        with unit.open('x') as file:
            unit_created=True
            file.write(text)
        checked('systemd-analyze','verify',str(unit))
        checked('systemctl','daemon-reload')
        start_attempted=True
        checked('systemctl','start',unit.name)

        def control(*args, payload=None, success=True):
            result=run(str(installed),*args,'--socket',str(runtime/'control.sock'),input=json.dumps(payload) if isinstance(payload,(dict,list)) else payload,timeout=330)
            if success and result.returncode:raise RuntimeError(result.stderr[:1000])
            if not success:
                assert result.returncode!=0,'operation unexpectedly succeeded'
                return result
            assert not result.stderr
            assert token not in result.stdout and all(identity not in result.stdout for identity in ids.values())
            return json.loads(result.stdout)

        deadline=time.monotonic()+10
        while run(str(installed),'status','--socket',str(runtime/'control.sock')).returncode:
            assert time.monotonic()<deadline,'control service did not become ready'
            time.sleep(0.1)
        flag=work/'fault-mode'
        proxy=spawn('gateway',['python3',__file__,'--proxy',flag],'fault-proxy')
        time.sleep(0.1)
        control('panel','configure','--file','-',payload=dict(url='http://127.0.0.1:20531/',token=token))
        control('panel','preflight')
        groups,connections,rules={},{},{}
        for name,index,address,port in [('a',220,'10.213.0.2',19001),('b',221,'10.214.0.2',19002)]:
            group=control('group','create','--name',f'Company {name}')['data']['id'];groups[name]=group
            connection=control('connection','import','--group',group,'--name',f'VPN {name}','--protocol','vless','--file','-',payload=json.dumps(outbound(address,port,ids[name])))['data']['id'];connections[name]=connection
            control('group','update',group,'--primary',connection,'--probe-file','-',payload=dict(tcp_ipv4=dict(url=f'http://10.{index}.0.10:18080/check'),tcp_ipv6=dict(url=f'http://[fd42:{index}::10]:18080/check'),udp_ipv4=dict(server=f'10.{index}.0.10:15353',query_name='probe.example.test',query_type='A'),udp_ipv6=dict(server=f'[fd42:{index}::10]:15353',query_name='probe.example.test',query_type='AAAA')))
            for destination in [f'10.{index}.0.0/24',f'fd42:{index}::/64']:
                rule=control('rule','create','--group',group,'--destination',destination)['data'];rules[destination]=rule['id']
        for name,peer in [('gateway','10.210.0.1'),('a','10.211.0.1'),('b','10.212.0.1')]:
            assert json.loads(ns(name,'curl','--noproxy','*','--max-time','3','-fsS','http://10.220.0.10:18080/direct-path').stdout)['peer']==peer
        preview=control('routing','preview')['data']
        current=api('xray/',{})
        if isinstance(current,str):current=json.loads(current)
        assert current['xraySetting']==baseline,'preview changed saved template'
        applied=control('routing','apply',preview['plan_id'])['data']
        assert applied['state']=='applied',applied
        assert all(value=='verified' for group in applied['capabilities'].values() for value in group.values()),applied
        for connection in connections.values():
            summary=control('connection','show',connection)['data']
            assert summary['runtime']=='applied' and set(summary['capabilities'])=={'tcp_ipv4','udp_ipv4','tcp_ipv6','udp_ipv6'}
        print('real 3x-ui apply verified TCP/UDP over IPv4/IPv6 for both groups')

        def tcp(address,expected,positive=True):
            marker='/'+secrets.token_hex(12)
            host=f'[{address}]' if ':' in address else address
            result=run('ip','netns','exec',names['client'],'curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','3','-fsS',f'http://{host}:18080{marker}')
            if positive:assert result.returncode==0 and json.loads(result.stdout)['peer']==expected,(address,result.stderr)
            else:assert result.returncode!=0,(address,'protected TCP escaped')
            return marker

        def udp(port,expected,positive=True):
            marker=secrets.token_hex(12)+'.example.test'
            result=run('ip','netns','exec',names['client'],'python3',__file__,'--udp',str(port),marker)
            if positive:assert result.returncode==0 and json.loads(result.stdout)['answer']==expected,(port,result.stderr)
            else:assert result.returncode!=0,(port,'protected UDP escaped')
            return marker

        for address,peer in [('10.220.0.10','10.211.0.1'),('10.221.0.10','10.212.0.1'),('fd42:220::10','fd42:211::1'),('fd42:221::10','fd42:212::1')]:tcp(address,peer)
        for port,answer in [(15354,'198.18.1.1'),(15355,'198.18.2.1'),(15356,'198.18.1.1'),(15357,'198.18.2.1')]:udp(port,answer)
        tcp('1.1.1.1','10.210.0.1');tcp('2606:4700::1111','fd42:210::1')
        count=len(api('inbounds/list'))
        control('routing','apply',preview['plan_id'])
        assert len(api('inbounds/list'))==count
        current=api('xray/',{})
        if isinstance(current,str):current=json.loads(current)
        assert current['xraySetting']['log']==baseline['log']
        assert [v for v in current['xraySetting']['outbounds'] if not v['tag'].startswith('wgates-')]==baseline['outbounds']
        assert [v for v in current['xraySetting']['routing']['rules'] if not v.get('ruleTag','').startswith('wgates-')]==baseline['routing']['rules']
        # A real panel save followed by a failed acknowledgement must restore the verified path.
        saved_before_fault=current['xraySetting']
        extra=control('rule','create','--group',groups['a'],'--destination','10.222.0.0/24')['data']['id']
        fault_plan=control('routing','preview')['data']['plan_id']
        flag.write_text('fail_after_save')
        control('routing','apply',fault_plan,success=False)
        assert control('routing','status')['data']['last_observation']['state']=='restored'
        tcp('10.220.0.10','10.211.0.1');udp(15354,'198.18.1.1')
        control('rule','delete',extra)
        extra=control('rule','create','--group',groups['a'],'--destination','10.223.0.0/24')['data']['id']
        fault_plan=control('routing','preview')['data']['plan_id']
        flag.write_text('intervening')
        control('routing','apply',fault_plan,success=False)
        current=api('xray/',{})
        if isinstance(current,str):current=json.loads(current)
        assert current['xraySetting']['log']['loglevel']=='error'
        assert control('routing','status')['data']['last_observation']['state']=='recovery_required'
        control('routing','preview',success=False)
        control('routing','recover',fault_plan,success=False)
        api('xray/update',dict(xraySetting=json.dumps(saved_before_fault),outboundTestUrl=settings['outboundTestUrl']))
        assert control('routing','recover',fault_plan)['data']['state']=='restored'
        control('rule','delete',extra)
        # Drift after preview must be rejected before any managed write.
        drift_plan=control('routing','preview')['data']['plan_id']
        changed=json.loads(json.dumps(saved_before_fault));changed['log']['loglevel']='error'
        api('xray/update',dict(xraySetting=json.dumps(changed),outboundTestUrl=settings['outboundTestUrl']))
        drift=control('routing','apply',drift_plan,success=False)
        assert 'drift' in drift.stderr
        current=api('xray/',{})
        if isinstance(current,str):current=json.loads(current)
        assert current['xraySetting']==changed
        api('xray/update',dict(xraySetting=json.dumps(saved_before_fault),outboundTestUrl=settings['outboundTestUrl']))
        print('real panel drift rejection, failed acknowledgement, safe restoration and intervening-edit protection passed')
        nested=control('rule','create','--group',groups['b'],'--destination','10.220.0.128/25')['data']['id']
        preview=control('routing','preview')['data'];control('routing','apply',preview['plan_id'])
        tcp('10.220.0.200','10.212.0.1')
        control('rule','delete',nested)
        # Removing one probe removes only that capability; the destination remains protected.
        control('group','update',groups['a'],'--probe-file','-',payload=dict(tcp_ipv4=dict(url='http://10.220.0.10:18080/check'),tcp_ipv6=dict(url='http://[fd42:220::10]:18080/check'),udp_ipv4=dict(server='10.220.0.10:15353',query_name='probe.example.test',query_type='A')))
        preview=control('routing','preview')['data'];partial=control('routing','apply',preview['plan_id'])['data'];assert partial['state']=='partial'
        blocked=[udp(15356,None,False)]
        tcp('fd42:220::10','fd42:211::1');udp(15354,'198.18.1.1')
        exits['a'].terminate();exits['a'].wait(timeout=5)
        blocked.extend([tcp('10.220.0.10',None,False),tcp('fd42:220::10',None,False),udp(15354,None,False)])
        tcp('10.221.0.10','10.212.0.1');udp(15355,'198.18.2.1');tcp('1.1.1.1','10.210.0.1')
        recorded=[json.loads(line) for line in events.read_text().splitlines()]
        assert not any(event['marker'] in blocked for event in recorded),'protected traffic reached a direct or other-group resource'
        assert state.stat().st_uid==uid and (state/'routing').stat().st_mode&0o777==0o700
        for path in (state/'routing').glob('*.json'):
            assert path.stat().st_mode&0o777==0o600 and path.stat().st_uid==uid
        checked('systemctl','restart',unit.name)
        deadline=time.monotonic()+10
        while run(str(installed),'status','--socket',str(runtime/'control.sock')).returncode:
            assert time.monotonic()<deadline;time.sleep(0.1)
        assert control('routing','status')['data']['last_observation']['state']=='partial'
        print('VLESS ingress packets, longest-prefix routing, unmatched direct, partial capabilities, no direct/cross-group leaks, restart and preservation passed')
    except BaseException:
        # Logs may contain test credentials; keep diagnostics to process state and control errors.
        print('routing stand failed; process states: '+str([(p.pid,p.poll()) for p in processes]),file=sys.stderr)
        if 'events' in locals() and events.exists():print('resource events: '+events.read_text()[-2000:],file=sys.stderr)
        for label,log in logs:
            log.flush();log.seek(0)
            diagnostic=log.read()[-2500:]
            for secret in list(locals().get('ids',{}).values())+[locals().get('token','')]:
                if secret:diagnostic=diagnostic.replace(secret,'[redacted]')
            print(label+': '+diagnostic,file=sys.stderr)

        raise
    finally:
        if unit_created and unit.exists():
            checked('systemctl','stop',unit.name,timeout=25)
            unit.unlink();checked('systemctl','daemon-reload')
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=8)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        for _,log in logs:log.close()
        if installed_created and installed.exists():installed.unlink()
        if start_attempted and state.exists():
            assert state.name==prefix and state.stat().st_uid==pwd.getpwnam(prefix).pw_uid
            shutil.rmtree(state)
        if start_attempted and runtime.exists():
            assert runtime.name==prefix;shutil.rmtree(runtime)
        if account_attempted:
            try:account=pwd.getpwnam(prefix)
            except KeyError:pass
            else:
                assert account.pw_dir==str(state)
                checked('userdel',prefix)
            try:grp.getgrnam(prefix)
            except KeyError:pass
            else:checked('groupdel',prefix)
        for namespace in reversed(created):checked('ip','netns','del',namespace)
        temporary.cleanup()
        for owned,path in [(unit_created,unit),(installed_created,installed),(start_attempted,state),(start_attempted,runtime)]:
            if owned:assert not path.exists() and not path.is_symlink()
        assert all(namespace not in checked('ip','netns','list').stdout for namespace in created)
        print('routing stand resources removed')


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--resource':resource(sys.argv[2])
    elif len(sys.argv)>1 and sys.argv[1]=='--udp':udp_client(sys.argv[2],sys.argv[3])
    elif len(sys.argv)>1 and sys.argv[1]=='--proxy':fault_proxy(sys.argv[2])
    else:
        parser=argparse.ArgumentParser(description=__doc__)
        parser.add_argument('binary');parser.add_argument('panel_root')
        args=parser.parse_args();main(args.binary,args.panel_root)
