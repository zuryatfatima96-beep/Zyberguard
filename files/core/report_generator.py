"""Aggregates results from every module into the final security report.

AuditState is the single shared object the GUI controller updates as
each check completes; build_report_text() and save_report() turn it
into the text report described in the proposal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .file_integrity import IntegrityResult
from .ip_lookup import IpInfo
from .password_checker import PasswordResult
from .port_scanner import PortResult

DEFAULT_REPORT_PATH = Path(__file__).resolve().parent.parent / "reports" / "security_report.txt"


@dataclass
class AuditState:
    """Holds the latest result from each module for the current session."""
    target_ip: str = ""
    port_results: List[PortResult] = field(default_factory=list)
    ports_scanned: int = 0
    password_result: Optional[PasswordResult] = None
    file_result: Optional[IntegrityResult] = None
    ip_info: Optional[IpInfo] = None

    def security_score(self) -> int:
        """Score = (Safe Ports + Strong Password + Safe File + Known IP) x 25,
        matching the formula in the project proposal."""
        safe_ports = int(self.ports_scanned > 0 and not any(p.risky for p in self.port_results))
        strong_password = int(bool(self.password_result and self.password_result.is_strong))
        safe_file = int(bool(self.file_result and self.file_result.status in ("safe", "saved")))
        known_ip = int(self.ip_info is not None)
        return (safe_ports + strong_password + safe_file + known_ip) * 25


def build_report_text(state: AuditState) -> str:
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("ZYBERGUARD - SECURITY AUDIT REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    lines.append("-- Port Scan --")
    if state.ports_scanned:
        lines.append(f"Target: {state.target_ip}")
        lines.append(f"Ports scanned: {state.ports_scanned}")
        lines.append(f"Open ports found: {len(state.port_results)}")
        for r in state.port_results:
            flag = "RISKY" if r.risky else "safe"
            lines.append(f"  - Port {r.port} ({r.service}): {flag}")
    else:
        lines.append("No scan performed.")
    lines.append("")

    lines.append("-- Password Strength --")
    if state.password_result:
        pr = state.password_result
        lines.append(f"Rating: {pr.rating} ({pr.score}/4)")
        lines.append(f"SHA-256: {pr.sha256_hash}")
        for label, passed in pr.checks.items():
            lines.append(f"  - {label}: {'OK' if passed else 'MISSING'}")
    else:
        lines.append("No password checked.")
    lines.append("")

    lines.append("-- File Integrity --")
    if state.file_result:
        fr = state.file_result
        lines.append(f"File: {fr.file_path}")
        lines.append(f"Status: {fr.status.upper()}")
        lines.append(f"Current hash: {fr.current_hash}")
    else:
        lines.append("No file checked.")
    lines.append("")

    lines.append("-- IP Lookup --")
    if state.ip_info:
        info = state.ip_info
        lines.append(f"IP: {info.ip}")
        lines.append(f"Location: {info.city}, {info.region}, {info.country}")
        lines.append(f"Timezone: {info.timezone}")
        lines.append(f"ISP: {info.isp}")
        lines.append(f"Coordinates: {info.lat}, {info.lon}")
    else:
        lines.append("No IP looked up.")
    lines.append("")

    lines.append("-- Overall Security Score --")
    lines.append(f"Score: {state.security_score()}%")
    lines.append("=" * 60)

    return "\n".join(lines)


def save_report(state: AuditState, path: Path = DEFAULT_REPORT_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = build_report_text(state)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path
