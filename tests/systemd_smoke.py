#!/usr/bin/env python3
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time


def run(*args):
    try:
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=15)
    except subprocess.CalledProcessError as error:
        print(error.stdout + error.stderr, file=sys.stderr)
        raise


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("Run only as root on a disposable Linux systemd test host.")
    source = Path(sys.argv[1]).resolve(strict=True)
    repo = Path(__file__).resolve().parent.parent
    name = f"wgates-test-{os.getpid()}"
    binary = Path("/usr/local/bin") / name
    unit = Path("/run/systemd/system") / f"{name}.service"
    runtime = Path("/run") / name
    state = Path("/var/lib") / name
    for path in (binary, unit, runtime, state):
        assert not path.exists() and not path.is_symlink(), path
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup(name)
        except KeyError:
            pass
        else:
            raise RuntimeError("Test account already exists")
    uid = gid = None
    account_attempted = False
    try:
        shutil.copyfile(source, binary)
        binary.chmod(0o755)
        with tempfile.TemporaryDirectory(prefix="wgates-systemd-") as temporary:
            config = Path(temporary) / "sysusers.conf"
            config.write_text(
                (repo / "packaging/sysusers.d/wgates.conf")
                .read_text()
                .replace("wgates", name)
            )
            account_attempted = True
            run("systemd-sysusers", str(config))
        uid = pwd.getpwnam(name).pw_uid
        gid = grp.getgrnam(name).gr_gid
        unit.write_text(
            (repo / "packaging/systemd/wgates.service")
            .read_text()
            .replace("wgates", name)
        )
        run("systemd-analyze", "verify", str(unit))
        run("systemctl", "daemon-reload")

        def ready():
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                result = subprocess.run(
                    [str(binary), "status", "--socket", str(runtime / "control.sock")],
                    capture_output=True, text=True, timeout=3,
                )
                if result.returncode == 0:
                    result = json.loads(result.stdout)
                    assert result["ready"] is True and result["api_version"] == 1
                    return
                time.sleep(0.1)
            raise RuntimeError("systemd service did not become ready")

        run("systemctl", "start", unit.name)
        ready()
        assert stat.S_IMODE(runtime.stat().st_mode) == 0o750
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
        assert stat.S_IMODE((runtime / "control.sock").stat().st_mode) == 0o660
        assert state.stat().st_uid == uid
        denied = subprocess.run(
            ["runuser", "-u", "nobody", "--", str(binary), "status",
             "--socket", str(runtime / "control.sock")],
            capture_output=True, text=True, timeout=3,
        )
        assert denied.returncode != 0 and not denied.stdout
        assert "Permission denied" in denied.stderr
        run("runuser", "-u", name, "--", "touch", str(state / "probe"))
        run("systemctl", "stop", unit.name)
        assert not runtime.exists()
        assert (state / "probe").exists()
        assert run("systemctl", "show", "-p", "ExecMainStatus", "--value", unit.name).stdout.strip() == "0"
        run("systemctl", "start", unit.name)
        ready()
        assert (state / "probe").exists()
        run("systemctl", "stop", unit.name)
        print("systemd start/status, access denial, graceful stop, and restart passed")
    except BaseException:
        diagnostic = subprocess.run(
            ["journalctl", "-u", unit.name, "--no-pager", "-n", "30"],
            capture_output=True, text=True,
        )
        print(diagnostic.stdout, file=sys.stderr)
        raise
    finally:
        if account_attempted:
            try:
                account = pwd.getpwnam(name)
            except KeyError:
                pass
            else:
                assert account.pw_dir == str(state)
                uid = account.pw_uid if uid is None else uid
            try:
                group = grp.getgrnam(name)
            except KeyError:
                pass
            else:
                gid = group.gr_gid if gid is None else gid
        if unit.exists():
            run("systemctl", "stop", unit.name)
            unit.unlink()
            run("systemctl", "daemon-reload")
        socket = runtime / "control.sock"
        if socket.exists():
            assert stat.S_ISSOCK(socket.lstat().st_mode)
            socket.unlink()
        if runtime.exists():
            runtime.rmdir()
        if state.exists():
            probe = state / "probe"
            if probe.exists():
                probe.unlink()
            state.rmdir()
        if binary.exists():
            binary.unlink()
        if uid is not None:
            assert pwd.getpwnam(name).pw_uid == uid
            run("userdel", name)
        if gid is not None:
            try:
                current = grp.getgrnam(name)
            except KeyError:
                pass
            else:
                assert current.gr_gid == gid and not current.gr_mem
                run("groupdel", name)
        assert all(not p.exists() for p in (binary, unit, runtime, state))
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(name)
            except KeyError:
                pass
            else:
                raise RuntimeError("Test account cleanup was not confirmed")
        print("systemd test resources removed")


if __name__ == "__main__":
    main()
