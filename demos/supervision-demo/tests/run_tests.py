"""Black-box regression tests for the bounded arithmetic supervision demo."""
import argparse
import ctypes
import json
import hashlib
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

DEMO = None
OUTPUT = None
RUNS = []
MAX_EVENTS = 512


class ProcessHandle:
    """A pinned Windows process, verified as a child of our own process."""
    def __init__(self, pid, parent_pid):
        if os.name != "nt":
            raise unittest.SkipTest("Exact owned-process handles require Windows")
        from ctypes import wintypes
        self.pid = pid
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.handle = self.kernel.OpenProcess(0x100000 | 0x400 | 0x1, False, pid)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "OpenProcess failed")
        class BasicInfo(ctypes.Structure):
            _fields_ = [("reserved", ctypes.c_void_p), ("peb", ctypes.c_void_p),
                        ("reserved2", ctypes.c_void_p * 2),
                        ("pid", ctypes.c_size_t), ("parent", ctypes.c_size_t)]
        query = ctypes.WinDLL("ntdll").NtQueryInformationProcess
        query.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p,
                          wintypes.ULONG, ctypes.c_void_p]
        query.restype = wintypes.LONG
        info = BasicInfo()
        status = query(self.handle, 0, ctypes.byref(info), ctypes.sizeof(info), None)
        if status != 0 or info.pid != pid or info.parent != parent_pid:
            self.close()
            raise AssertionError("Refusing unverified process ownership")

    def alive(self):
        return self.kernel.WaitForSingleObject(self.handle, 0) == 258

    def wait_dead(self, timeout=3):
        return self.kernel.WaitForSingleObject(self.handle, int(timeout * 1000)) == 0

    def kill(self, code=75):
        if self.alive() and not self.kernel.TerminateProcess(self.handle, code):
            raise OSError(ctypes.get_last_error(), "TerminateProcess failed")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class Run:
    def __init__(self, label, args=(), stop=None, command=None, console=False):
        self.label = label
        self.events, self.errors, self.handles, self.auxiliary = [], [], {}, {}
        self.lines, self.stderr, self.cleanup = [], [], {}
        self.inbox = queue.Queue()
        self.started = time.monotonic()
        self.closed = False
        self.parent_pid = None
        cmd = command or [sys.executable, "-I", "-u", str(DEMO / "supervisor.py")]
        cmd = list(cmd) + list(args)
        if stop is not None:
            cmd += ["--stop-file", str(stop)]
        self.command = cmd
        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            if console:
                kwargs["creationflags"] = subprocess.CREATE_NEW_CONSOLE
                startup = subprocess.STARTUPINFO()
                startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startup.wShowWindow = subprocess.SW_HIDE
                kwargs["startupinfo"] = startup
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                     errors="replace", bufsize=1, **kwargs)
        self.parent_pid = self.proc.pid
        self.console = console
        self.stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.stdout_thread.start()
        self.stderr_thread.start()
        RUNS.append(self)

    def _read_stdout(self):
        try:
            while True:
                line = self.proc.stdout.readline(4097)
                if not line:
                    break
                if len(self.lines) >= MAX_EVENTS:
                    if "stdout event limit exceeded" not in self.errors:
                        self.errors.append("stdout event limit exceeded")
                    continue
                self.lines.append(line[:4096].rstrip())
                try:
                    if len(line) > 4096:
                        raise ValueError("oversized JSON line")
                    record = json.loads(line)
                    if not isinstance(record, dict) or not isinstance(record.get("event"), str):
                        raise ValueError("JSON object with event required")
                    event = record["event"]
                    if event == "probe_supervisor_started":
                        pid = record["pid"]
                        if os.name == "nt":
                            self.auxiliary[pid] = ProcessHandle(pid, self.proc.pid)
                        self.parent_pid = pid
                    if event == "worker_started" and os.name == "nt":
                        try:
                            self.handles[record["pid"]] = ProcessHandle(record["pid"], self.parent_pid)
                        except OSError as exc:
                            # A very short-lived child may have exited before OpenProcess.
                            if exc.errno != 87:
                                raise
                    self.events.append(record)
                    self.inbox.put(record)
                except Exception as exc:
                    self.errors.append(type(exc).__name__ + ": " + str(exc))
        except Exception as exc:
            self.errors.append("stdout: " + repr(exc))
        finally:
            self.inbox.put(None)

    def _read_stderr(self):
        size = 0
        while True:
            chunk = self.proc.stderr.read(1024)
            if not chunk:
                return
            if size < 8192:
                self.stderr.append(chunk[:8192 - size])
                size += len(chunk)

    def event(self, name, timeout=4):
        until = time.monotonic() + timeout
        while True:
            try:
                record = self.inbox.get(timeout=max(0.001, until - time.monotonic()))
            except queue.Empty:
                raise AssertionError(f"Timeout waiting for {name}: {self.events[-5:]}")
            if record is None:
                raise AssertionError(f"EOF before {name}: {self.events[-5:]} / {self.errors}")
            if record["event"] == name:
                return record
            if time.monotonic() >= until:
                raise AssertionError(f"Timeout waiting for {name}")

    def finish(self, timeout=5):
        try:
            code = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise AssertionError("Supervisor exceeded harness timeout")
        self.stdout_thread.join(timeout=1)
        self.stderr_thread.join(timeout=1)
        if self.stdout_thread.is_alive() or self.stderr_thread.is_alive():
            raise AssertionError("Output pipes did not close")
        if self.errors:
            raise AssertionError(self.errors)
        return code

    def records(self, event):
        return [record for record in self.events if record["event"] == event]

    def owned_worker(self, pid):
        if os.name != "nt":
            raise unittest.SkipTest("Abrupt termination tests require Windows process handles")
        if pid not in self.handles:
            raise AssertionError("Worker exited before ownership could be verified")
        return self.handles[pid]

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=3)
            self.cleanup["supervisor_forced"] = True
        for pid, handle in list(self.auxiliary.items()) + list(self.handles.items()):
            try:
                if not handle.wait_dead(timeout=2):
                    self.cleanup.setdefault("forced_children", []).append(pid)
                    handle.kill(99)
                    if not handle.wait_dead(timeout=2):
                        self.errors.append(f"Child {pid} survived cleanup")
            finally:
                handle.close()
        self.stdout_thread.join(timeout=1)
        self.stderr_thread.join(timeout=1)
        self.proc.stdout.close()
        self.proc.stderr.close()
        trace = {"test": self.label, "command": self.command,
                 "supervisor_pid": self.proc.pid, "returncode": self.proc.returncode,
                 "duration_seconds": round(time.monotonic() - self.started, 3),
                 "events": self.events, "raw_lines": self.lines if self.errors else [],
                 "stderr": "".join(self.stderr), "reader_errors": self.errors,
                 "cleanup": self.cleanup}
        path = OUTPUT / f"{len(list(OUTPUT.glob('trace-*.json'))):03d}-{self.label}.json"
        path = path.with_name("trace-" + path.name)
        path.write_text(json.dumps(trace, ensure_ascii=False, indent=2), encoding="utf-8")


def check_success(events, steps, attempts):
    terminals = [e for e in events if e["event"] in {"completed", "failed", "stopped"}]
    if len(terminals) != 1 or terminals[0].get("event") != "completed":
        raise AssertionError("Exactly one completed terminal event required")
    if terminals[0].get("result") != steps * (steps + 1) // 2:
        raise AssertionError("Wrong arithmetic result")
    if terminals[0].get("attempts") != attempts:
        raise AssertionError("Wrong attempt count")
    for attempt in range(1, attempts + 1):
        progress = [e for e in events if e["event"] == "progress" and e.get("attempt") == attempt]
        expected_steps = steps if attempt == attempts else min(3, steps)
        if [e.get("step") for e in progress] != list(range(1, expected_steps + 1)):
            raise AssertionError("Missing, repeated or non-sequential progress")
        if [e.get("total") for e in progress] != [n * (n + 1) // 2 for n in range(1, expected_steps + 1)]:
            raise AssertionError("Wrong progress total")


class SupervisionTests(unittest.TestCase):
    def setUp(self):
        self.runs = []
        self.temp = tempfile.TemporaryDirectory(prefix="case-", dir=OUTPUT)
        self.directory = Path(self.temp.name)
        self.stop = self.directory / "STOP"

    def tearDown(self):
        try:
            for run in self.runs:
                run.close()
            forced = [run.label for run in self.runs if run.cleanup]
            self.assertFalse(forced, "Cleanup required forced process termination: " + str(forced))
        finally:
            self.temp.cleanup()

    def launch(self, *args, stop=None, command=None, console=False):
        run = Run(self._testMethodName, args, self.stop if stop is None else stop, command, console)
        self.runs.append(run)
        return run

    def terminal(self, run, code, event, **fields):
        self.assertEqual(run.finish(), code)
        terminals = [e for e in run.events if e["event"] in {"completed", "failed", "stopped"}]
        self.assertEqual(len(terminals), 1)
        self.assertEqual(terminals[0]["event"], event)
        for key, value in fields.items():
            self.assertEqual(terminals[0].get(key), value, key)
        self.assertIs(run.events[-1], terminals[0])
        self.assertEqual(len(run.records("supervisor_started")), 1)
        for handle in run.handles.values():
            self.assertTrue(handle.wait_dead(2), "Worker survives terminal event")

    def test_success_no_failure_exact_result(self):
        run = self.launch("--simulate-failures", "0", "--steps", "10", "--step-ms", "10")
        self.terminal(run, 0, "completed", result=55, attempts=1)
        check_success(run.events, 10, 1)
        self.assertEqual(len(run.records("worker_started")), 1)
        self.assertEqual(len(run.records("worker_ready")), 1)
        self.assertEqual(run.records("worker_exited")[0]["returncode"], 0)
        self.assertFalse(run.records("restart_scheduled"))

    def test_one_failure_then_success(self):
        run = self.launch("--simulate-failures", "1", "--steps", "7", "--step-ms", "10", "--retry-delay-ms", "0")
        self.terminal(run, 0, "completed", result=28, attempts=2)
        check_success(run.events, 7, 2)
        self.assertEqual([e["returncode"] for e in run.records("worker_exited")], [75, 0])
        self.assertEqual([e["attempt"] for e in run.records("restart_scheduled")], [2])
        self.assertEqual(run.records("restart_scheduled")[0]["delay_ms"], 0)
        self.assertEqual([e["attempt"] for e in run.records("simulated_failure")], [1])

    def test_restart_limit_zero(self):
        run = self.launch("--simulate-failures", "1", "--max-restarts", "0", "--steps", "1", "--step-ms", "10")
        self.terminal(run, 1, "failed", reason="restart_limit")
        self.assertEqual(len(run.records("worker_started")), 1)
        self.assertEqual([e["step"] for e in run.records("progress")], [1])
        self.assertEqual(len(run.records("simulated_failure")), 1)
        self.assertFalse(run.records("restart_scheduled"))

    def test_restart_limit_three(self):
        run = self.launch("--simulate-failures", "4", "--max-restarts", "3", "--steps", "4", "--step-ms", "10", "--retry-delay-ms", "0")
        self.terminal(run, 1, "failed", reason="restart_limit")
        self.assertEqual([e["attempt"] for e in run.records("worker_started")], [1, 2, 3, 4])
        self.assertEqual([e["attempt"] for e in run.records("restart_scheduled")], [2, 3, 4])
        self.assertEqual([e["returncode"] for e in run.records("worker_exited")], [75] * 4)
        self.assertEqual(len(run.records("simulated_failure")), 4)

    def test_three_restarts_can_succeed(self):
        run = self.launch("--simulate-failures", "3", "--max-restarts", "3", "--steps", "2", "--step-ms", "10", "--retry-delay-ms", "0")
        self.terminal(run, 0, "completed", result=3, attempts=4)
        check_success(run.events, 2, 4)
        self.assertEqual([e["returncode"] for e in run.records("worker_exited")], [75, 75, 75, 0])

    def test_invalid_parameters(self):
        values = {"--simulate-failures": ["-1", "5"], "--max-restarts": ["-1", "4"],
                  "--steps": ["0", "51"], "--step-ms": ["9", "201"],
                  "--retry-delay-ms": ["-1", "1001"],
                  "--deadline-seconds": ["0.09", "30.1", "NaN", "inf", "-inf", "oops"]}
        for flag, invalid in values.items():
            for value in invalid:
                with self.subTest(flag=flag, value=value):
                    run = self.launch(f"{flag}={value}")
                    self.assertEqual(run.finish(), 2)
                    self.assertFalse(run.records("worker_started"))
                    self.assertFalse(run.events)
                    run.close()

    def test_stop_before_start(self):
        self.stop.touch()
        run = self.launch()
        self.terminal(run, 0, "stopped", reason="stop_file")
        self.assertFalse(run.records("worker_started"))

    def test_stop_during_work(self):
        run = self.launch("--simulate-failures", "0", "--steps", "50", "--step-ms", "100")
        run.event("progress")
        self.stop.touch()
        self.terminal(run, 0, "stopped", reason="stop_file")
        self.assertEqual(len(run.records("worker_started")), 1)
        self.assertFalse(run.records("restart_scheduled"))

    def test_stop_during_backoff(self):
        run = self.launch("--simulate-failures", "4", "--max-restarts", "3", "--step-ms", "10", "--retry-delay-ms", "1000")
        run.event("restart_scheduled")
        self.stop.touch()
        self.terminal(run, 0, "stopped", reason="stop_file")
        self.assertEqual(len(run.records("worker_started")), 1)
        self.assertEqual(len(run.records("restart_scheduled")), 1)

    @unittest.skipUnless(os.name == "nt", "Verified process handles implemented on Windows")
    def test_killed_parent_releases_worker(self):
        run = self.launch("--simulate-failures", "0", "--steps", "50", "--step-ms", "200")
        ready = run.event("worker_ready")
        handle = run.owned_worker(ready["pid"])
        self.assertTrue(handle.alive())
        run.proc.kill()
        run.finish(timeout=3)
        self.assertTrue(handle.wait_dead(3), "Worker survives private-pipe EOF")
        self.assertFalse(run.records("restart_scheduled"))

    @unittest.skipUnless(os.name == "nt", "Verified process handles implemented on Windows")
    def test_killed_worker_reserved_code_never_restarts(self):
        run = self.launch("--simulate-failures", "4", "--max-restarts", "3", "--steps", "50", "--step-ms", "200")
        ready = run.event("worker_ready")
        handle = run.owned_worker(ready["pid"])
        handle.kill(75)
        self.terminal(run, 1, "failed", reason="unexpected_exit")
        self.assertEqual(len(run.records("worker_started")), 1)
        self.assertEqual(run.records("worker_exited")[0]["returncode"], 75)
        self.assertFalse(run.records("simulated_failure"))
        self.assertFalse(run.records("restart_scheduled"))

    def test_deadline_during_work(self):
        run = self.launch("--simulate-failures", "0", "--steps", "50", "--step-ms", "200", "--deadline-seconds", "0.4")
        self.terminal(run, 124, "stopped", reason="deadline")
        self.assertEqual(len(run.records("worker_started")), 1)
        self.assertFalse(run.records("restart_scheduled"))

    def test_deadline_during_backoff(self):
        run = self.launch("--simulate-failures", "4", "--max-restarts", "3", "--steps", "1", "--step-ms", "10", "--retry-delay-ms", "1000", "--deadline-seconds", "0.5")
        self.terminal(run, 124, "stopped", reason="deadline")
        self.assertEqual(len(run.records("worker_started")), 1)
        self.assertEqual(len(run.records("restart_scheduled")), 1)

    def test_two_runs_are_isolated(self):
        other_stop = self.directory / "SECOND_STOP"
        first = self.launch("--simulate-failures", "0", "--steps", "50", "--step-ms", "100")
        second = self.launch("--simulate-failures", "0", "--steps", "8", "--step-ms", "40", stop=other_stop)
        first_ready = first.event("worker_ready")
        second_ready = second.event("worker_ready")
        self.assertNotEqual(first_ready["pid"], second_ready["pid"])
        self.stop.touch()
        self.terminal(first, 0, "stopped", reason="stop_file")
        self.terminal(second, 0, "completed", result=36, attempts=1)
        check_success(second.events, 8, 1)
        self.assertFalse(other_stop.exists())

    @unittest.skipUnless(os.name == "nt", "Ctrl+Break is Windows-specific")
    def test_ctrl_break_in_private_hidden_console(self):
        trigger = self.directory / "BREAK"
        command = [sys.executable, "-I", "-u", str(Path(__file__).with_name("console_bridge.py")),
                   "--demo", str(DEMO), "--trigger", str(trigger)]
        run = self.launch(command=command, console=True)
        # The helper creates a private hidden console; never attach to the user's console.
        try:
            run.event("worker_ready")
        except AssertionError:
            if run.records("probe_unavailable"):
                self.skipTest(run.records("probe_unavailable")[0]["reason"])
            raise
        trigger.touch()
        self.terminal(run, 130, "stopped", reason="signal")
        self.assertEqual(len(run.records("probe_break_sent")), 1)
        self.assertEqual(len(run.records("worker_started")), 1)
        self.assertFalse(run.records("restart_scheduled"))

    def test_protocol_error_with_isolated_worker(self):
        # Copy only the supervisor; the original demo remains untouched.
        isolated = self.directory / "isolated-demo"
        isolated.mkdir()
        (isolated / "supervisor.py").write_bytes((DEMO / "supervisor.py").read_bytes())
        (isolated / "worker.py").write_text('print("not-json", flush=True)\n', encoding="utf-8")
        run = self.launch(command=[sys.executable, "-I", "-u", str(isolated / "supervisor.py")])
        self.terminal(run, 1, "failed", reason="protocol_error")
        self.assertEqual(len(run.records("worker_started")), 1)
        self.assertFalse(run.records("restart_scheduled"))

    @unittest.skipUnless(os.name == "nt", "Windows invalid pathname raises deterministic OSError")
    def test_io_error_invalid_stop_path(self):
        run = self.launch(stop=self.directory / "invalid<STOP")
        self.terminal(run, 1, "failed", reason="io_error")
        self.assertFalse(run.records("worker_started"))

    def test_negative_control_wrong_result_is_rejected(self):
        witness = self.directory / "false_supervisor.py"
        witness.write_text('import json\nprint(json.dumps({"event":"supervisor_started"}))\n'
                           'print(json.dumps({"event":"completed","result":999,"attempts":1}))\n', encoding="utf-8")
        run = self.launch(command=[sys.executable, "-I", "-u", str(witness)])
        self.assertEqual(run.finish(), 0)
        with self.assertRaisesRegex(AssertionError, "Wrong arithmetic result"):
            check_success(run.events, 10, 1)


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.append({"test": test.id(), "status": "passed"})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes.append({"test": test.id(), "status": "failed", "detail": self._exc_info_to_string(err, test)[-6000:]})

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes.append({"test": test.id(), "status": "error", "detail": self._exc_info_to_string(err, test)[-6000:]})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes.append({"test": test.id(), "status": "skipped", "reason": reason})

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err:
            self.outcomes.append({"test": str(subtest), "status": "failed", "detail": self._exc_info_to_string(err, test)[-6000:]})


def main():
    global DEMO, OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", required=True, type=Path, help="directory containing supervisor.py and worker.py")
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("_artifacts"))
    parser.add_argument("--test", action="append", help="specific method name, may be repeated")
    args = parser.parse_args()
    DEMO = args.demo.resolve()
    if not (DEMO / "supervisor.py").is_file():
        parser.error("--demo must contain supervisor.py")
    OUTPUT = args.output.resolve()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    suite = (unittest.TestSuite(SupervisionTests(name) for name in args.test)
             if args.test else unittest.defaultTestLoader.loadTestsFromTestCase(SupervisionTests))
    started = time.monotonic()
    try:
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    finally:
        for run in RUNS:
            run.close()
    forced_cleanup = [run.label for run in RUNS if run.cleanup]
    success = result.wasSuccessful() and not forced_cleanup
    source_hashes = {name: hashlib.sha256((DEMO / name).read_bytes()).hexdigest()
                     for name in ("supervisor.py", "worker.py")}
    summary = {"demo": str(DEMO), "source_sha256": source_hashes, "python": sys.version, "platform": sys.platform,
               "tests_run": result.testsRun, "success": success,
               "failures": len(result.failures), "errors": len(result.errors),
               "skipped": len(result.skipped), "duration_seconds": round(time.monotonic() - started, 3),
               "outcomes": result.outcomes,
               "forced_cleanup_runs": forced_cleanup}
    (OUTPUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
