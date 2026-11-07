"""Ctrl+Break bridge; run ONLY in the harness-created hidden private console."""
import argparse
import ctypes
import json
from pathlib import Path
import subprocess
import sys
import threading
import time


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", type=Path, required=True)
    parser.add_argument("--trigger", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    args = parser.parse_args()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # CREATE_NEW_CONSOLE was used by our parent. No AttachConsole or global signal.
    members = (ctypes.c_ulong * 16)()
    count = kernel.GetConsoleProcessList(members, len(members))
    if count != 1:
        emit("probe_unavailable", reason="A private single-process console was not available")
        return 77
    child = subprocess.Popen([sys.executable, "-I", "-u", str(args.demo / "supervisor.py"),
                              "--simulate-failures", "0", "--steps", "50", "--step-ms", "100",
                              "--deadline-seconds", "4", "--stop-file", str(args.stop_file)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=sys.stderr,
                             text=True, encoding="utf-8", creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    emit("probe_supervisor_started", pid=child.pid)
    def relay():
        for line in child.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
    reader = threading.Thread(target=relay, daemon=True)
    reader.start()
    sent = False
    until = time.monotonic() + 6
    try:
        while child.poll() is None:
            if args.trigger.exists() and not sent:
                if not kernel.GenerateConsoleCtrlEvent(1, child.pid):
                    raise OSError(ctypes.get_last_error(), "GenerateConsoleCtrlEvent failed")
                sent = True
                emit("probe_break_sent", pid=child.pid)
            if time.monotonic() > until:
                raise TimeoutError("Private-console supervisor exceeded timeout")
            time.sleep(0.02)
        reader.join(timeout=1)
        return child.returncode
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        reader.join(timeout=1)
        child.stdout.close()


if __name__ == "__main__":
    raise SystemExit(main())
