"""IP geolocation lookup against ip-api.com.

The HTTP request runs inside IpLookupWorker, meant to be moved to a
QThread by the caller, so a slow or unreachable network never freezes
the GUI's event loop.
"""
from __future__ import annotations

from dataclasses import dataclass

import requests
from PyQt5.QtCore import QObject, pyqtSignal

API_URL = "http://ip-api.com/json/{ip}"
REQUEST_TIMEOUT = 6  # seconds


@dataclass
class IpInfo:
    ip: str
    country: str
    city: str
    region: str
    timezone: str
    isp: str
    lat: float
    lon: float


class IpLookupWorker(QObject):
    finished = pyqtSignal(object)   # IpInfo on success
    error = pyqtSignal(str)         # message on failure

    def __init__(self, ip_address: str):
        super().__init__()
        self.ip_address = ip_address

    def run(self) -> None:
        try:
            response = requests.get(
                API_URL.format(ip=self.ip_address), timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            self.error.emit(f"Network error: {exc}")
            return

        if data.get("status") != "success":
            self.error.emit(data.get("message", "Lookup failed for that address."))
            return

        info = IpInfo(
            ip=self.ip_address,
            country=data.get("country", "—"),
            city=data.get("city", "—"),
            region=data.get("regionName", "—"),
            timezone=data.get("timezone", "—"),
            isp=data.get("isp", "—"),
            lat=data.get("lat", 0.0),
            lon=data.get("lon", 0.0),
        )
        self.finished.emit(info)
