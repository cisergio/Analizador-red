"""Lectura y resumen de capturas PCAP/PCAPNG usando el programa externo TShark."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


class CaptureError(RuntimeError):
    """Error controlado para problemas al encontrar TShark o leer una captura."""


def find_tshark() -> str:
    # TSHARK_PATH permite indicar una instalación que no esté añadida al PATH.
    configured = os.getenv("TSHARK_PATH", "").strip().strip('"')
    candidates: list[Path] = []
    if configured:
        # expanduser admite, por ejemplo, una ruta que use ~ en Linux/macOS.
        configured_path = Path(configured).expanduser()
        candidates.append(configured_path)
        # TSHARK_PATH puede indicar el ejecutable o la carpeta que lo contiene.
        if configured_path.is_dir():
            candidates.append(configured_path / ("tshark.exe" if os.name == "nt" else "tshark"))
    # shutil.which busca ejecutables que la terminal pueda resolver por el PATH.
    for name in ("tshark", "tshark.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    if os.name == "nt":
        # Wireshark suele instalarse aquí en Windows, aunque el PATH no esté actualizado.
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            program_files = os.getenv(variable)
            if program_files:
                candidates.append(Path(program_files) / "Wireshark" / "tshark.exe")
        candidates.append(Path(r"C:\Program Files\Wireshark\tshark.exe"))

    for candidate in candidates:
        # is_file evita devolver rutas inexistentes; resolve normaliza la ruta elegida.
        if candidate.is_file():
            return str(candidate.resolve())

    details = []
    if configured:
        details.append(f"TSHARK_PATH apunta a una ruta que no existe o no es un archivo válido: {configured}")
    details.append("No aparece en el PATH visible para esta terminal")
    raise CaptureError(
        "No se encuentra TShark. " + "; ".join(details) + ". "
        "Cierra y vuelve a abrir PowerShell, o configura TSHARK_PATH con la ruta completa "
        r'(por ejemplo: $env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe").'
    )


def _run_tshark(args: list[str], *, tshark: str | None = None) -> str:
    # Si las pruebas o un llamador dan una ruta explícita, se usa; si no, se busca TShark.
    command = [tshark or find_tshark(), *args]
    try:
        # Cada elemento se pasa como argumento por separado: no se interpreta como una cadena de shell.
        # Capturamos la salida para procesarla y mostramos errores más claros al usuario.
        result = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace")
    except OSError as exc:
        # Incluye errores del sistema al arrancar el ejecutable (ruta, permisos, etc.).
        raise CaptureError(f"No se pudo ejecutar TShark: {exc}") from exc
    if result.returncode:
        # TShark suele explicar en stderr por qué no pudo leer o decodificar el archivo.
        detail = result.stderr.strip() or f"código {result.returncode}"
        raise CaptureError(f"TShark no pudo leer la captura: {detail}")
    # La salida estándar contiene el resumen o las columnas que se solicitaron.
    return result.stdout


def _first(value: Any) -> str | None:
    # Convierte un valor simple o una lista de valores a su primer texto; utilitario genérico.
    if isinstance(value, list):
        return _first(value[0]) if value else None
    if value is None:
        return None
    return str(value)


def analyze_capture(path: str | Path, *, tshark: str | None = None) -> dict[str, Any]:
    """Devuelve el resumen de protocolos, endpoints, DNS y conversaciones de una captura."""
    # Path acepta rutas como texto o Path; resolve produce una ruta absoluta normalizada.
    capture = Path(path).expanduser().resolve()
    if not capture.is_file():
        raise CaptureError(f"No existe el archivo de captura: {capture}")
    # Primera lectura: pide a TShark una jerarquía/resumen de protocolos (-z io,phs).
    summary = _run_tshark(["-r", str(capture), "-q", "-z", "io,phs"], tshark=tshark)
    # Segunda lectura: solicita columnas concretas para poder construir nuestros propios conteos.
    # -T fields selecciona salida tabular; separator y occurrence mantienen columnas previsibles.
    fields = _run_tshark([
        "-r", str(capture), "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
        "-e", "frame.number", "-e", "frame.protocols", "-e", "ip.src", "-e", "ipv6.src",
        "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.srcport", "-e", "udp.srcport",
        "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "dns.qry.name", "-e", "dns.a",
        "-e", "dns.aaaa", "-e", "dns.resp.name",
    ], tshark=tshark)

    # Counter suma cuántas veces aparece cada dato; sets guardan valores únicos.
    protocols: Counter[str] = Counter()
    addresses: Counter[str] = Counter()
    conversations: Counter[tuple[str, str, str, str, str]] = Counter()
    dns_names: set[str] = set()
    dns_ips: set[str] = set()
    packets = 0
    for line in fields.splitlines():
        # Cada línea representa un paquete; TShark separa las 14 columnas por tabuladores.
        cols = line.split("\t")
        # Si un campo final está vacío, split puede omitirlo; se rellena para conservar índices.
        cols += [""] * (14 - len(cols))
        if cols[0]:
            packets += 1
        # frame.protocols tiene una ruta como eth:ethertype:ip:udp:quic.
        # Cada elemento se cuenta; por eso los totales por protocolo se solapan.
        for proto in filter(None, cols[1].split(":")):
            protocols[proto] += 1
        # IPv4 e IPv6 tienen nombres de campo distintos; se usa el que venga informado.
        src, dst = cols[2] or cols[3], cols[4] or cols[5]
        if src:
            addresses[src] += 1
        if dst:
            addresses[dst] += 1
        # También se unifican los campos de puerto TCP y UDP.
        src_port, dst_port = cols[6] or cols[7], cols[8] or cols[9]
        # Determina el transporte cuando la captura trae alguno de esos puertos.
        transport = "TCP" if cols[6] or cols[8] else "UDP" if cols[7] or cols[9] else ""
        if src and dst:
            # La clave incluye protocolo, IPs y puertos para distinguir conversaciones.
            conversations[(transport, src, src_port, dst, dst_port)] += 1
        # DNS puede traer varios nombres; set elimina duplicados del informe.
        dns_names.update(x for x in (cols[10], cols[13]) if x)
        # Se guardan las respuestas IPv4/IPv6 asociadas con consultas DNS.
        dns_ips.update(x for x in (cols[11], cols[12]) if x)

    # El diccionario resultante es la estructura común que consumen VirusTotal y report.py.
    return {
        "file": str(capture), "packets": packets,
        "protocols": dict(protocols.most_common()),
        "ips": [{"ip": ip, "packet_references": count} for ip, count in sorted(addresses.items(), key=lambda kv: (-kv[1], kv[0]))],
        "conversations": [
            {"transport": proto, "source": src, "source_port": sport, "destination": dst, "destination_port": dport, "packets": count}
            for (proto, src, sport, dst, dport), count in conversations.most_common()
        ],
        "dns_names": sorted(dns_names), "dns_ips": sorted(dns_ips), "tshark_protocol_summary": summary.strip(),
    }


def public_ip_addresses(report: dict[str, Any]) -> list[str]:
    """Devuelve IPs únicas de paquetes y DNS que son direcciones globales públicas."""
    # Se combinan IPs observadas en paquetes y respuestas DNS porque ambas pueden ser destinos útiles.
    values = set(report.get("dns_ips", []))
    values.update(row["ip"] for row in report.get("ips", []))
    result: list[str] = []
    for value in values:
        try:
            # ipaddress valida el formato y detecta propiedades como is_global.
            addr = ipaddress.ip_address(value)
        except ValueError:
            # Un texto que no sea una dirección IP se ignora sin frenar el informe.
            continue
        if addr.is_global:
            result.append(str(addr))
    # Orden estable: primero IPv4, luego IPv6; dentro de cada grupo, orden numérico.
    return sorted(result, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x))))


def export_json(report: dict[str, Any], destination: str | Path) -> None:
    # Función auxiliar para guardar la estructura completa como JSON legible (no la usa el menú actual).
    Path(destination).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
