"""Network port scanner.

Scans a target host across a port range using a thread pool so the
whole range finishes in a couple of seconds instead of minutes —
scanning 1-1024 sequentially with even a modest per-port timeout can
take a long time, since most closed/filtered ports each cost a full
timeout. Running the probes concurrently collapses that wall-clock
time to roughly one timeout period total instead of one per port.

This module is GUI-agnostic: PortScanWorker is a QObject meant to be
moved to a QThread by the caller (see main.py), so the socket I/O
never blocks the UI event loop.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List

from PyQt5.QtCore import QObject, pyqtSignal

# Ports the proposal flags explicitly as risky if exposed.
RISKY_PORTS = {21, 23, 3389}

# Small built-in lookup so common services get a readable label
# without adding an extra dependency.
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-ALT",
}


@dataclass
class PortResult:
    port: int
    service: str
    risky: bool


def service_name(port: int) -> str:
    return COMMON_SERVICES.get(port, "unknown")


def _scan_one(host: str, port: int, timeout: float) -> bool:
    """Return True if `port` is open (accepting TCP connections) on `host`."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


class PortScanWorker(QObject):
    """Scans `start`..`end` on `host` concurrently inside a QThread.

    Usage (see main.py for the full pattern):
        thread = QThread()
        worker = PortScanWorker(host, start, end)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(thread.quit)
        thread.start()
    """

    progress = pyqtSignal(int)          # percent complete, 0-100
    port_found = pyqtSignal(object)     # PortResult, emitted as each open port is found
    finished = pyqtSignal(list)         # final List[PortResult], sorted by port number
    error = pyqtSignal(str)             # human-readable error (e.g. bad hostname)

    def __init__(self, host: str, start: int, end: int,
                 timeout: float = 0.35, max_workers: int = 200):
        super().__init__()
        self.host = host
        self.start = start
        self.end = end
        self.timeout = timeout
        self.max_workers = max_workers
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            socket.gethostbyname(self.host)
        except socket.gaierror:
            self.error.emit(f'Could not resolve host "{self.host}".')
            self.finished.emit([])
            return

        ports = range(self.start, self.end + 1)
        total = max(len(ports), 1)
        completed = 0
        open_ports: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(_scan_one, self.host, port, self.timeout): port
                for port in ports
            }
            for future in as_completed(futures):
                if self._cancelled:
                    break
                port = futures[future]
                completed += 1
                try:
                    is_open = future.result()
                except OSError:
                    is_open = False
                if is_open:
                    result = PortResult(
                        port=port,
                        service=service_name(port),
                        risky=port in RISKY_PORTS,
                    )
                    open_ports.append(result)
                    self.port_found.emit(result)
                self.progress.emit(int(completed / total * 100))

        open_ports.sort(key=lambda r: r.port)
        self.finished.emit(open_ports)
