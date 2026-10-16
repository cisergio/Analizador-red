"""Cliente pequeño y sin caché para VirusTotal API v3."""

from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any


class VirusTotalError(RuntimeError):
    """Error de configuración, cuota o respuesta de VirusTotal."""


class _UrllibSession:
    """Adaptador pequeño para poder inyectar sesiones falsas en las pruebas."""

    def get(self, url: str, *, headers: dict[str, str], timeout: int) -> Any:
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return _UrllibResponse(response.status, response.read())
        except urllib.error.HTTPError as exc:
            return _UrllibResponse(exc.code, exc.read())


class _UrllibResponse:
    def __init__(self, status_code: int, body: bytes):
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return json.loads(self._body.decode("utf-8"))


class VirusTotalClient:
    def __init__(self, api_key: str | None = None, *, session: Any = None, min_interval: float = 15.1):
        self.api_key = (api_key or os.getenv("VT_API_KEY", "")).strip()
        if not self.api_key:
            raise VirusTotalError("Falta la clave VirusTotal. Configura VT_API_KEY.")
        self.session = session or _UrllibSession()
        self.min_interval = min_interval
        self._last_request: float | None = None

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        try:
            normalized = str(ipaddress.ip_address(ip))
        except ValueError as exc:
            raise VirusTotalError(f"Dirección IP no válida: {ip}") from exc
        if self._last_request is not None:
            wait = self.min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
        try:
            response = self.session.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{normalized}",
                headers={"x-apikey": self.api_key}, timeout=30,
            )
            self._last_request = time.monotonic()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise VirusTotalError(f"Error de conexión: {exc}") from exc
        if response.status_code == 404:
            raise VirusTotalError("VirusTotal no tiene un informe para esta IP (404).")
        if response.status_code == 401:
            raise VirusTotalError("Clave VirusTotal no válida (401).")
        if response.status_code == 403:
            raise VirusTotalError("VirusTotal rechazó la consulta o el plan no permite este endpoint (403).")
        if response.status_code == 429:
            raise VirusTotalError("Cuota de VirusTotal agotada (429). Espera a que se restablezca.")
        if response.status_code >= 400:
            raise VirusTotalError(f"VirusTotal respondió HTTP {response.status_code}.")
        try:
            return response.json()
        except ValueError as exc:
            raise VirusTotalError("VirusTotal devolvió una respuesta JSON no válida.") from exc


def summarize_ip_response(ip: str, payload: dict[str, Any]) -> dict[str, Any]:
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    return {
        "ip": ip, "country": attrs.get("country"), "asn": attrs.get("asn"), "as_owner": attrs.get("as_owner"),
        "reputation": attrs.get("reputation"), "analysis_stats": stats,
        "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }
