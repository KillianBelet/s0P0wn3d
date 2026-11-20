"""Fixed arithmetic worker. No network, persistence, or process launching."""

import argparse
import json
import os
import signal
import threading

SIMULATED_FAILURE = 75


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--steps", type=int, choices=range(1, 51), required=True)
    parser.add_argument("--step-ms", type=int, choices=range(10, 201), required=True)
    parser.add_argument("--simulate-failure", action="store_true")
    args = parser.parse_args()
    stopped = threading.Event()

    def on_signal(_signum, _frame):
        stopped.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), on_signal)

    def watch_parent_pipe():
        # Only the supervisor owns the write end. EOF or any byte means stop.
        # os.read avoids a buffered-stdin lock held by a daemon at shutdown.
        try:
            os.read(0, 1)
        finally:
            stopped.set()

    threading.Thread(target=watch_parent_pipe, daemon=True).start()
    emit("worker_ready", pid=os.getpid())
    total = 0
    for step in range(1, args.steps + 1):
        if stopped.wait(args.step_ms / 1000):
            return 0
        total += step
        emit("progress", step=step, total=total)
        if args.simulate_failure and step == min(3, args.steps):
            emit("simulated_failure")
            return SIMULATED_FAILURE
    if stopped.is_set():
        return 0
    emit("worker_completed", result=total)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, OSError):
        # There is no reader anymore: stop, never retry or recreate a parent.
        os._exit(1)
