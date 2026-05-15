"""
ShieldScan — Dev Hot-Reload Runner
===================================
Usage:
    python dev.py              # watches gui_restored.py (default)
    python dev.py gui.py       # watch a specific file
    python dev.py --all        # watch ALL .py files in Tools/

Restarts the app automatically whenever a watched file is saved.
Requires: pip install watchdog
"""

from __future__ import annotations
import os
import sys
import time
import signal
import subprocess
import threading
import argparse

_HERE    = os.path.dirname(os.path.abspath(__file__))
_TARGET  = os.path.join(_HERE, "gui_restored.py")
_DEBOUNCE = 0.6   # seconds — ignore rapid successive saves


def _pick_target(args) -> list[str]:
    if args.all:
        return [os.path.join(_HERE, f)
                for f in os.listdir(_HERE) if f.endswith(".py")]
    if args.file:
        p = os.path.join(_HERE, args.file)
        if not os.path.exists(p):
            print(f"[dev] File not found: {p}")
            sys.exit(1)
        return [p]
    return [_TARGET]


class _WatchdogReloader:
    """Uses the `watchdog` library for efficient OS-level file events."""

    def __init__(self, paths: list[str]):
        self._paths   = paths
        self._proc:   subprocess.Popen | None = None
        self._timer:  threading.Timer  | None = None
        self._lock    = threading.Lock()

    # ── Process control ────────────────────────────────────────────────────

    def _launch(self):
        self._kill()
        print(f"\n[dev]  Launching  gui_restored.py …")
        self._proc = subprocess.Popen(
            [sys.executable, _TARGET],
            cwd=_HERE,
        )

    def _kill(self):
        if self._proc and self._proc.poll() is None:
            try:
                if sys.platform == "win32":
                    self._proc.terminate()
                else:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                self._proc.wait(timeout=4)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        self._proc = None

    # ── Debounced reload ───────────────────────────────────────────────────

    def _schedule_reload(self, src: str):
        with self._lock:
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(
                _DEBOUNCE, self._do_reload, args=(src,))
            self._timer.daemon = True
            self._timer.start()

    def _do_reload(self, src: str):
        print(f"[dev]  Change detected in  {os.path.basename(src)}")
        self._launch()

    # ── Main loop ──────────────────────────────────────────────────────────

    def run(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            print("[dev]  watchdog not installed — falling back to polling mode.")
            print("[dev]  Install with:  pip install watchdog")
            _PollingReloader(self._paths).run()
            return

        watch_dirs = {os.path.dirname(p) for p in self._paths}
        watch_files = set(os.path.normcase(p) for p in self._paths)

        class _Handler(FileSystemEventHandler):
            def __init__(self, outer: _WatchdogReloader):
                self._outer = outer

            def on_modified(self, event):
                if not event.is_directory:
                    fp = os.path.normcase(event.src_path)
                    if fp in watch_files or any(fp.endswith(".py")
                                                for _ in [None] if "--all" in sys.argv):
                        self._outer._schedule_reload(event.src_path)

        observer = Observer()
        handler  = _Handler(self)
        for d in watch_dirs:
            observer.schedule(handler, d, recursive=False)
        observer.start()

        watched = ", ".join(os.path.basename(p) for p in self._paths)
        print(f"[dev]  Watching: {watched}")
        print( "[dev]  Save any watched file to hot-reload the app.")
        print( "[dev]  Press Ctrl+C to stop.\n")

        self._launch()
        try:
            while True:
                time.sleep(1)
                if self._proc and self._proc.poll() is not None:
                    print("[dev]  App exited — waiting for file change to relaunch …")
        except KeyboardInterrupt:
            print("\n[dev]  Stopping …")
        finally:
            observer.stop()
            observer.join()
            self._kill()


class _PollingReloader:
    """Fallback: polls mtime every second — no extra dependencies."""

    def __init__(self, paths: list[str]):
        self._paths = paths
        self._proc: subprocess.Popen | None = None

    def _launch(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=4)
            except Exception:
                self._proc.kill()
        print(f"\n[dev]  Launching  gui_restored.py …")
        self._proc = subprocess.Popen([sys.executable, _TARGET], cwd=_HERE)

    def run(self):
        watched = ", ".join(os.path.basename(p) for p in self._paths)
        print(f"[dev]  Polling mode — watching: {watched}")
        print( "[dev]  Save any watched file to hot-reload the app.")
        print( "[dev]  Press Ctrl+C to stop.\n")

        mtimes = {p: os.path.getmtime(p) for p in self._paths if os.path.exists(p)}
        self._launch()
        try:
            while True:
                time.sleep(1)
                for p in self._paths:
                    if not os.path.exists(p):
                        continue
                    mt = os.path.getmtime(p)
                    if mtimes.get(p) != mt:
                        mtimes[p] = mt
                        print(f"[dev]  Change in {os.path.basename(p)}")
                        self._launch()
                        break
                if self._proc and self._proc.poll() is not None:
                    print("[dev]  App exited — waiting for file change …")
        except KeyboardInterrupt:
            print("\n[dev]  Stopping …")
            if self._proc:
                self._proc.terminate()


def main():
    parser = argparse.ArgumentParser(
        description="ShieldScan hot-reload dev runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file",  nargs="?", help="Specific .py file to watch")
    parser.add_argument("--all", action="store_true",
                        help="Watch all .py files in the Tools directory")
    args = parser.parse_args()

    paths = _pick_target(args)

    # Try watchdog first, fall back to polling automatically
    try:
        import watchdog  # noqa: F401
        _WatchdogReloader(paths).run()
    except ImportError:
        _PollingReloader(paths).run()


if __name__ == "__main__":
    main()
