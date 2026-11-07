"""Visible, bounded recovery demo for a fixed arithmetic worker."""

import argparse
import json
import math
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time

SIMULATED_FAILURE = 75
POLL_SECONDS = 0.025


def bounded_int(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"expected {low}..{high}")
        return number
    return parse


def bounded_deadline(value):
    number = float(value)
    if not math.isfinite(number) or not 0.1 <= number <= 30:
        raise argparse.ArgumentTypeError("expected a finite value in 0.1..30")
    return number


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--simulate-failures", type=bounded_int(0, 4), default=1)
    parser.add_argument("--max-restarts", type=bounded_int(0, 3), default=2)
    parser.add_argument("--steps", type=bounded_int(1, 50), default=10)
    parser.add_argument("--step-ms", type=bounded_int(10, 200), default=100)
    parser.add_argument("--retry-delay-ms", type=bounded_int(0, 1000), default=200)
    parser.add_argument("--deadline-seconds", type=bounded_deadline, default=10)
    parser.add_argument("--stop-file", type=Path,
                        default=Path(__file__).resolve().with_name("STOP"))
    return parser.parse_args()


class Demo:
    def __init__(self, args):
        self.args = args
        self.started = time.monotonic()
        self.deadline = self.started + args.deadline_seconds
        self.signalled = threading.Event()
        self.child = None
        self.reader = None
        self.attempt = 0

    def emit(self, event, **fields):
        print(json.dumps({"event": event,
                          "elapsed_ms": round((time.monotonic() - self.started) * 1000),
                          **fields}), flush=True)

    def on_signal(self, _signum, _frame):
        self.signalled.set()

    def stop_reason(self):
        # Explicit user intent takes precedence over successful work or retries.
        if self.signalled.is_set():
            return "signal"
        try:
            self.args.stop_file.lstat()
        except FileNotFoundError:
            pass
        else:
            return "stop_file"
        if time.monotonic() >= self.deadline:
            return "deadline"
        return None

    def close_child(self):
        child = self.child
        if child is None:
            return
        if child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1)
        if self.reader is not None:
            self.reader.join(timeout=1)
        if child.stdout is not None:
            child.stdout.close()
        self.child = None
        self.reader = None
        self.emit("worker_exited", pid=child.pid, attempt=self.attempt,
                  returncode=child.returncode)

    def stop(self, reason):
        self.close_child()
        self.emit("stopped", reason=reason)
        return {"signal": 130, "deadline": 124}.get(reason, 0)

    def fail(self, reason):
        self.close_child()
        self.emit("failed", reason=reason)
        return 1

    def launch(self, simulate):
        command = [sys.executable, "-I", "-u",
                   str(Path(__file__).resolve().with_name("worker.py")),
                   "--steps", str(self.args.steps), "--step-ms", str(self.args.step_ms)]
        if simulate:
            command.append("--simulate-failure")
        # No shell, no user-supplied command. stdin is a private lifetime pipe.
        self.child = subprocess.Popen(command, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      close_fds=True)
        events = queue.Queue(maxsize=64)
        child = self.child

        def read_events():
            try:
                while True:
                    line = child.stdout.readline(4097)
                    if not line:
                        break
                    if len(line) > 4096 or not line.endswith(b"\n"):
                        events.put(("error", None))
                        return
                    try:
                        record = json.loads(line)
                    except (ValueError, UnicodeDecodeError):
                        events.put(("error", None))
                        return
                    if not isinstance(record, dict):
                        events.put(("error", None))
                        return
                    events.put(("record", record))
            except OSError:
                events.put(("error", None))
            finally:
                events.put(("eof", None))

        self.reader = threading.Thread(target=read_events, daemon=True)
        self.reader.start()
        self.emit("worker_started", pid=child.pid, attempt=self.attempt)
        return events

    def run_attempt(self, simulate):
        events = self.launch(simulate)
        ready, failed, completed, eof = False, False, False, False
        step, total = 0, 0
        while True:
            reason = self.stop_reason()
            if reason:
                return "stop", reason
            try:
                kind, record = events.get(timeout=POLL_SECONDS)
            except queue.Empty:
                kind, record = None, None
            if kind == "error":
                return "fail", "protocol_error"
            if kind == "eof":
                eof = True
            if kind == "record":
                event = record.get("event")
                if (event == "worker_ready" and not ready
                        and type(record.get("pid")) is int
                        and record.get("pid") == self.child.pid):
                    ready = True
                    self.emit(event, pid=self.child.pid, attempt=self.attempt)
                elif (event == "progress" and ready and not failed and not completed
                      and type(record.get("step")) is int
                      and type(record.get("total")) is int
                      and step < self.args.steps and record.get("step") == step + 1
                      and record.get("total") == total + step + 1):
                    step += 1
                    total += step
                    self.emit(event, attempt=self.attempt, step=step, total=total)
                elif (event == "simulated_failure" and simulate and ready and not failed
                      and not completed and step == min(3, self.args.steps)):
                    failed = True
                    self.emit(event, attempt=self.attempt)
                elif (event == "worker_completed" and ready and not failed and not completed
                      and type(record.get("result")) is int
                      and step == self.args.steps and record.get("result") == total):
                    completed = True
                else:
                    return "fail", "protocol_error"
            returncode = self.child.poll()
            if returncode is not None and eof:
                self.close_child()
                reason = self.stop_reason()
                if reason:
                    return "stop", reason
                if returncode == 0 and completed:
                    return "complete", total
                if returncode == SIMULATED_FAILURE and failed and simulate:
                    return "retry", None
                # Kills, signals, missing results and all unknown failures are terminal.
                return "fail", "unexpected_exit"

    def run(self):
        self.emit("supervisor_started", pid=os.getpid(),
                  stop_file=str(self.args.stop_file.absolute()),
                  max_restarts=self.args.max_restarts)
        while True:
            reason = self.stop_reason()
            if reason:
                return self.stop(reason)
            self.attempt += 1
            kind, value = self.run_attempt(self.attempt <= self.args.simulate_failures)
            if kind == "stop":
                return self.stop(value)
            if kind == "fail":
                return self.fail(value)
            if kind == "complete":
                reason = self.stop_reason()
                if reason:
                    return self.stop(reason)
                self.emit("completed", result=value, attempts=self.attempt)
                return 0
            if self.attempt > self.args.max_restarts:
                return self.fail("restart_limit")
            reason = self.stop_reason()
            if reason:
                return self.stop(reason)
            self.emit("restart_scheduled", attempt=self.attempt + 1,
                      delay_ms=self.args.retry_delay_ms)
            retry_at = time.monotonic() + self.args.retry_delay_ms / 1000
            while time.monotonic() < retry_at:
                reason = self.stop_reason()
                if reason:
                    return self.stop(reason)
                self.signalled.wait(min(POLL_SECONDS, max(0, retry_at - time.monotonic())))


def main():
    demo = Demo(arguments())
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), demo.on_signal)
    try:
        return demo.run()
    except BrokenPipeError:
        # Stop if the visible event output is closed; there is no background mode.
        return 1
    except OSError:
        return demo.fail("io_error")
    finally:
        demo.close_child()


if __name__ == "__main__":
    raise SystemExit(main())
