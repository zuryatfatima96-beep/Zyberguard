"""ZyberGuard — Personal Security Audit Toolkit.

Run with:  python main.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from PyQt5 import uic
from PyQt5.QtCore import QThread
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFileDialog,
    QLineEdit,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QTableWidgetItem,
)

from core.file_integrity import HashStore
from core.ip_lookup import IpInfo, IpLookupWorker
from core.password_checker import check_password
from core.port_scanner import PortResult, PortScanWorker
from core.report_generator import AuditState, build_report_text, save_report

BASE_DIR   = Path(__file__).resolve().parent
UI_PATH    = BASE_DIR / "zyberguard_ui.ui"
DARK_QSS   = BASE_DIR / "zyberguard_dark.qss"
LIGHT_QSS  = BASE_DIR / "zyberguard_light.qss"

FILE_STATUS_LABELS = {
    "saved":       "Hash Saved",
    "safe":        "Safe ✓",
    "tampered":    "TAMPERED ⚠",
    "no_baseline": "No Baseline",
}


def _set_dynamic_property(widget, name: str, value) -> None:
    widget.setProperty(name, value)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


class MainWindow(QMainWindow):
    def __init__(self, app: QApplication):
        super().__init__()
        self._app = app
        self._theme = "dark"          # "dark" or "light"

        uic.loadUi(str(UI_PATH), self)

        self.state       = AuditState()
        self.hash_store  = HashStore()

        self._scan_thread: QThread | None = None
        self._scan_worker: PortScanWorker | None = None
        self._ip_thread:   QThread | None = None
        self._ip_worker:   IpLookupWorker | None = None
        self._pending_audit_tasks = 0

        self._apply_theme("dark")
        self._setup_navigation()
        self._setup_dashboard_page()
        self._setup_port_scanner_page()
        self._setup_password_page()
        self._setup_file_integrity_page()
        self._setup_ip_lookup_page()
        self._setup_report_page()

        self._refresh_saved_hashes_table()
        self._update_dashboard()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------
    def _apply_theme(self, theme: str) -> None:
        self._theme = theme
        qss_path = DARK_QSS if theme == "dark" else LIGHT_QSS
        if qss_path.exists():
            self._app.setStyleSheet(qss_path.read_text(encoding="utf-8"))
        # Update toggle button label if it exists
        if hasattr(self, "btnThemeToggle"):
            self.btnThemeToggle.setText("☀  Light Mode" if theme == "dark" else "🌙  Dark Mode")

    def _toggle_theme(self) -> None:
        self._apply_theme("light" if self._theme == "dark" else "dark")

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------
    def _setup_navigation(self) -> None:
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        nav_map = [
            (self.btnNavDashboard,    self.pageDashboard),
            (self.btnNavPortScan,     self.pagePortScan),
            (self.btnNavPassword,     self.pagePassword),
            (self.btnNavFileIntegrity,self.pageFileIntegrity),
            (self.btnNavIpLookup,     self.pageIpLookup),
            (self.btnNavReport,       self.pageReport),
        ]
        for btn, page in nav_map:
            self.nav_group.addButton(btn)
            # Use pressed (fires immediately on click, no bool argument)
            btn.pressed.connect(lambda p=page, b=btn: self._go_to_page(p, b))

        # Wire theme toggle button
        self.btnThemeToggle.clicked.connect(self._toggle_theme)

        self._go_to_page(self.pageDashboard, self.btnNavDashboard)

    def _go_to_page(self, page, button) -> None:
        self.stackedWidget.setCurrentWidget(page)
        # Manually keep checked state consistent
        for btn in self.nav_group.buttons():
            btn.setChecked(btn is button)

    def _goto_report_page(self) -> None:
        self._go_to_page(self.pageReport, self.btnNavReport)

    # ------------------------------------------------------------------
    # Port Scanner
    # ------------------------------------------------------------------
    def _setup_port_scanner_page(self) -> None:
        self.btnScanStart.clicked.connect(self._on_scan_start_clicked)
        self.tblScanResults.horizontalHeader().setStretchLastSection(True)

    def _on_scan_start_clicked(self) -> None:
        host  = self.leTargetIp.text().strip() or "127.0.0.1"
        start = self.sbPortStart.value()
        end   = self.sbPortEnd.value()
        if start > end:
            QMessageBox.warning(self, "Invalid Range",
                                "Start port must be ≤ end port.")
            return
        self._run_port_scan(host, start, end)

    def _run_port_scan(self, host: str, start: int, end: int) -> None:
        if self._scan_thread is not None and self._scan_thread.isRunning():
            QMessageBox.information(self, "Scan In Progress",
                                    "Please wait for the current scan to finish.")
            return

        self.btnScanStart.setEnabled(False)
        self.btnScanStart.setText("Scanning…")
        self.tblScanResults.setRowCount(0)
        self.pbScanProgress.setValue(0)
        self.lblScanSummary.setText(f"Scanning {host}, ports {start}–{end}…")

        self._scan_thread  = QThread(self)
        self._scan_worker  = PortScanWorker(host, start, end)
        self._scan_worker.moveToThread(self._scan_thread)

        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.progress.connect(self.pbScanProgress.setValue)
        self._scan_worker.port_found.connect(self._on_port_found)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.finished.connect(
            lambda results: self._on_scan_finished(host, start, end, results))
        self._scan_worker.finished.connect(self._scan_thread.quit)
        self._scan_worker.finished.connect(self._scan_worker.deleteLater)
        self._scan_thread.finished.connect(self._scan_thread.deleteLater)
        self._scan_thread.start()

    def _on_port_found(self, result: PortResult) -> None:
        row = self.tblScanResults.rowCount()
        self.tblScanResults.insertRow(row)
        self.tblScanResults.setItem(row, 0, QTableWidgetItem(str(result.port)))
        self.tblScanResults.setItem(row, 1, QTableWidgetItem(result.service))
        status = QTableWidgetItem("RISKY" if result.risky else "Safe")
        status.setForeground(QColor("#e05260" if result.risky else "#0F6B52"))
        self.tblScanResults.setItem(row, 2, status)

    def _on_scan_error(self, message: str) -> None:
        QMessageBox.warning(self, "Scan Error", message)

    def _on_scan_finished(self, host: str, start: int, end: int,
                          results: list) -> None:
        self.btnScanStart.setEnabled(True)
        self.btnScanStart.setText("▶  Start Scan")
        self.pbScanProgress.setValue(100)

        self.state.target_ip     = host
        self.state.ports_scanned = end - start + 1
        self.state.port_results  = results

        risky = sum(1 for r in results if r.risky)
        msg   = f"Scan complete: {len(results)} open port(s)"
        if risky:
            msg += f", {risky} risky"
        msg += f" (range {start}–{end})."
        self.lblScanSummary.setText(msg)
        self._update_dashboard()
        self._maybe_finish_full_audit()

    # ------------------------------------------------------------------
    # Password Checker
    # ------------------------------------------------------------------
    def _setup_password_page(self) -> None:
        self.btnTogglePassword.toggled.connect(self._on_toggle_password_visibility)
        self.btnCheckPassword.clicked.connect(self._on_check_password_clicked)
        self.lePassword.returnPressed.connect(self._on_check_password_clicked)

    def _on_toggle_password_visibility(self, checked: bool) -> None:
        self.lePassword.setEchoMode(
            QLineEdit.Normal if checked else QLineEdit.Password)
        self.btnTogglePassword.setText("🙈" if checked else "👁")

    def _on_check_password_clicked(self) -> None:
        password = self.lePassword.text()
        if not password:
            QMessageBox.information(self, "Password Required",
                                    "Type a password to analyze.")
            return
        result = check_password(password)
        self.lblPasswordRating.setText(result.rating)
        self.pbPasswordStrength.setValue(result.score)
        _set_dynamic_property(self.pbPasswordStrength, "level",
                               str(max(result.score, 1)))
        self.lePasswordHash.setText(result.sha256_hash)
        self.listPasswordCriteria.clear()
        for label, passed in result.checks.items():
            icon = "✓" if passed else "✗"
            item = QListWidgetItem(f"{icon}  {label}")
            item.setForeground(QColor("#0F6B52" if passed else "#e05260"))
            self.listPasswordCriteria.addItem(item)
        self.state.password_result = result
        self._update_dashboard()
        self._maybe_finish_full_audit()

    # ------------------------------------------------------------------
    # File Integrity
    # ------------------------------------------------------------------
    def _setup_file_integrity_page(self) -> None:
        self.btnBrowseFile.clicked.connect(self._on_browse_file_clicked)
        self.btnSaveHash.clicked.connect(self._on_save_hash_clicked)
        self.btnVerifyFile.clicked.connect(self._on_verify_file_clicked)
        self.tblSavedHashes.horizontalHeader().setStretchLastSection(True)

    def _on_browse_file_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to check")
        if path:
            self.leFilePath.setText(path)
            self.lblFileStatus.setText("Ready — Save Baseline Hash or Verify File.")
            _set_dynamic_property(self.lblFileStatus, "state", "")

    def _current_file_path(self) -> str | None:
        path = self.leFilePath.text().strip()
        if not path:
            QMessageBox.information(self, "No File Selected",
                                    "Browse for a file first.")
            return None
        return path

    def _on_save_hash_clicked(self) -> None:
        path = self._current_file_path()
        if not path:
            return
        try:
            result = self.hash_store.save_hash(path)
        except OSError as exc:
            QMessageBox.warning(self, "Error", f"Could not read file:\n{exc}")
            return
        self.lblFileStatus.setText(
            f"Baseline hash saved for {Path(path).name}.")
        _set_dynamic_property(self.lblFileStatus, "state", "safe")
        self.state.file_result = result
        self._refresh_saved_hashes_table()
        self._update_dashboard()
        self._maybe_finish_full_audit()

    def _on_verify_file_clicked(self) -> None:
        path = self._current_file_path()
        if not path:
            return
        try:
            result = self.hash_store.verify(path)
        except OSError as exc:
            QMessageBox.warning(self, "Error", f"Could not read file:\n{exc}")
            return
        if result.status == "no_baseline":
            self.lblFileStatus.setText(
                "No baseline saved — click Save Baseline Hash first.")
            _set_dynamic_property(self.lblFileStatus, "state", "warn")
        elif result.status == "safe":
            self.lblFileStatus.setText("✓ File is safe — hash matches baseline.")
            _set_dynamic_property(self.lblFileStatus, "state", "safe")
        else:
            self.lblFileStatus.setText(
                "⚠ TAMPERED — hash does not match baseline!")
            _set_dynamic_property(self.lblFileStatus, "state", "danger")
        self.state.file_result = result
        self._update_dashboard()
        self._maybe_finish_full_audit()

    def _refresh_saved_hashes_table(self) -> None:
        entries = self.hash_store.all_entries()
        self.tblSavedHashes.setRowCount(0)
        for path, info in entries.items():
            row = self.tblSavedHashes.rowCount()
            self.tblSavedHashes.insertRow(row)
            self.tblSavedHashes.setItem(row, 0, QTableWidgetItem(path))
            short_hash = info.get("hash", "")[:24] + "…"
            self.tblSavedHashes.setItem(row, 1, QTableWidgetItem(short_hash))
            self.tblSavedHashes.setItem(
                row, 2, QTableWidgetItem(info.get("saved_on", "")))

    # ------------------------------------------------------------------
    # IP Lookup
    # ------------------------------------------------------------------
    def _setup_ip_lookup_page(self) -> None:
        self.btnLookupIp.clicked.connect(self._on_lookup_ip_clicked)
        self.leIpAddress.returnPressed.connect(self._on_lookup_ip_clicked)

    def _on_lookup_ip_clicked(self) -> None:
        ip = self.leIpAddress.text().strip()
        if not ip:
            QMessageBox.information(self, "IP Required",
                                    "Enter an IP address to look up.")
            return
        self._run_ip_lookup(ip)

    def _run_ip_lookup(self, ip: str) -> None:
        if self._ip_thread is not None and self._ip_thread.isRunning():
            QMessageBox.information(self, "Lookup In Progress",
                                    "Please wait for the current lookup to finish.")
            return
        self.btnLookupIp.setEnabled(False)
        self.pbIpLoading.setVisible(True)

        self._ip_thread = QThread(self)
        self._ip_worker = IpLookupWorker(ip)
        self._ip_worker.moveToThread(self._ip_thread)

        self._ip_thread.started.connect(self._ip_worker.run)
        self._ip_worker.finished.connect(self._on_ip_lookup_finished)
        self._ip_worker.error.connect(self._on_ip_lookup_error)
        self._ip_worker.finished.connect(self._ip_thread.quit)
        self._ip_worker.error.connect(self._ip_thread.quit)
        self._ip_worker.finished.connect(self._ip_worker.deleteLater)
        self._ip_worker.error.connect(self._ip_worker.deleteLater)
        self._ip_thread.finished.connect(self._ip_thread.deleteLater)
        self._ip_thread.start()

    def _on_ip_lookup_finished(self, info: IpInfo) -> None:
        self.btnLookupIp.setEnabled(True)
        self.pbIpLoading.setVisible(False)
        self.lblIpCountry.setText(info.country)
        self.lblIpCity.setText(info.city)
        self.lblIpRegion.setText(info.region)
        self.lblIpTimezone.setText(info.timezone)
        self.lblIpIsp.setText(info.isp)
        self.lblIpCoords.setText(f"{info.lat}, {info.lon}")
        self.state.ip_info = info
        self._update_dashboard()
        self._maybe_finish_full_audit()

    def _on_ip_lookup_error(self, message: str) -> None:
        self.btnLookupIp.setEnabled(True)
        self.pbIpLoading.setVisible(False)
        QMessageBox.warning(self, "Lookup Failed", message)
        self._maybe_finish_full_audit()

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    def _setup_report_page(self) -> None:
        self.btnGenerateReport.clicked.connect(self._on_generate_report_clicked)
        self.btnSaveReport.clicked.connect(self._on_save_report_clicked)

    def _on_generate_report_clicked(self) -> None:
        text = build_report_text(self.state)
        self.txtReportPreview.setPlainText(text)
        try:
            path = save_report(self.state)
            self.statusbar.showMessage(f"Report saved to {path}", 5000)
        except OSError as exc:
            QMessageBox.warning(self, "Error", f"Could not save report:\n{exc}")
        self._update_dashboard()

    def _on_save_report_clicked(self) -> None:
        text = self.txtReportPreview.toPlainText()
        if not text:
            QMessageBox.information(self, "Nothing to Save",
                                    "Generate the report first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report As", "security_report.txt",
            "Text Files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self.statusbar.showMessage(f"Report saved to {path}", 5000)

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    def _setup_dashboard_page(self) -> None:
        self.btnDashGenerateReport.clicked.connect(
            self._on_run_full_audit_clicked)

    def _update_dashboard(self) -> None:
        self.lblCardPortsValue.setText(
            str(len(self.state.port_results))
            if self.state.ports_scanned else "—")
        self.lblCardPasswordValue.setText(
            self.state.password_result.rating
            if self.state.password_result else "—")
        self.lblCardFileValue.setText(
            FILE_STATUS_LABELS.get(self.state.file_result.status, "—")
            if self.state.file_result else "—")
        self.lblCardIpValue.setText(
            self.state.ip_info.country if self.state.ip_info else "—")

        score = self.state.security_score()
        self.lblSecurityScoreValue.setText(f"{score}%")
        self.pbSecurityScore.setValue(score)
        level = "safe" if score >= 75 else "warn" if score >= 50 else "danger"
        _set_dynamic_property(self.pbSecurityScore, "level", level)

    def _on_run_full_audit_clicked(self) -> None:
        self._pending_audit_tasks = 0
        if self.lePassword.text():
            self._on_check_password_clicked()
        if self.leFilePath.text().strip():
            self._on_verify_file_clicked()
        host = self.leTargetIp.text().strip()
        if host:
            self._pending_audit_tasks += 1
            self._run_port_scan(host, self.sbPortStart.value(),
                                self.sbPortEnd.value())
        ip = self.leIpAddress.text().strip()
        if ip:
            self._pending_audit_tasks += 1
            self._run_ip_lookup(ip)
        if self._pending_audit_tasks == 0:
            self._on_generate_report_clicked()
            self._goto_report_page()

    def _maybe_finish_full_audit(self) -> None:
        if self._pending_audit_tasks > 0:
            self._pending_audit_tasks -= 1
            if self._pending_audit_tasks == 0:
                self._on_generate_report_clicked()
                self._goto_report_page()


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow(app)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
