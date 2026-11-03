#!/usr/bin/env python3
"""Check privileged native startup boundaries on a disposable Linux host."""
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import time


def main(binary, xray):
    assert sys.platform == 'linux' and os.geteuid() == 0, 'use only a disposable Linux root environment'
    binary, xray = Path(binary).resolve(strict=True), Path(xray).resolve(strict=True)
    account = pwd.getpwnam('nobody')
    failures = []
    with tempfile.TemporaryDirectory(prefix='wgates-native-safety-', dir='/var/lib') as directory:
        work = Path(directory)
        def paths(name):
            runtime, state = work/(name+'-run'), work/(name+'-state')
            runtime.mkdir(mode=0o750)
            os.chown(runtime, 0, account.pw_gid)
            return runtime/'control.sock', state
        def start(socket_path, state):
            return subprocess.Popen([str(binary),'native-runtime','--socket',str(socket_path),'--state-dir',str(state),'--service-user','nobody','--xray-bin',str(xray)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def stop(process):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
            return process.communicate()
        control, state = paths('positive')
        process = start(control, state)
        try:
            deadline = time.monotonic()+10
            while not control.exists():
                assert process.poll() is None, 'native runtime failed before positive readiness'
                assert time.monotonic()<deadline
                time.sleep(.05)
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(8)
                client.connect(str(control))
                client.sendall(b'{"api_version":1,"command":"preflight"}\n')
                response=b''
                while b'\n' not in response: response+=client.recv(4096)
                assert 'data' in json.loads(response),response
        finally: stop(process)
        assert not control.exists(), 'owned native socket remains after normal stop'

        control, state = paths('occupied')
        with socket.socket(socket.AF_UNIX) as existing:
            existing.bind(str(control))
            existing.listen(1)
            identity=(control.stat().st_dev,control.stat().st_ino)
            process=start(control,state)
            try:
                try: result=process.wait(timeout=5)
                except subprocess.TimeoutExpired: result=None
                preserved=control.exists() and (control.stat().st_dev,control.stat().st_ino)==identity
                if result in (None,0) or not preserved: failures.append('occupied root socket was replaced or startup did not reject it')
            finally: stop(process)

        control, _ = paths('untrusted')
        parent=work/'untrusted-parent'
        parent.mkdir(mode=0o700)
        parent.chmod(0o777)
        state=parent/'state'
        process=start(control,state)
        try:
            try: result=process.wait(timeout=5)
            except subprocess.TimeoutExpired: result=None
            if result in (None,0) or state.exists(): failures.append('root state accepted a writable parent directory')
        finally: stop(process)

        control,state=paths('cleanup')
        state.mkdir(mode=0o700)
        result=subprocess.run([str(binary),'native-cleanup','--socket',str(control),'--state-dir',str(state),'--service-user','nobody','--xray-bin',str(work/'absent-xray')],capture_output=True,timeout=15)
        if result.returncode: failures.append('cleanup depends on the presence of an unused Xray executable')
    assert not failures, '; '.join(failures)
    print('Native root socket preservation, controlled parent directories and dependency-independent cleanup passed')


if __name__=='__main__':
    main(*sys.argv[1:])
