"""Lectura de conversaciones e IPs desde PCAP/PCAPNG mediante TShark."""

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
    """La captura no se pudo analizar."""


def find_tshark() -> str:
    configured = os.getenv("TSHARK_PATH", "").strip().strip('"')
    if configured and Path(configured).is_file():
        return configured
    path = shutil.which("tshark")
    if not path:
        raise CaptureError("No se encuentra TShark. Instálalo y añádelo al PATH.")
    return path


def _run_tshark(args: list[str], *, tshark: str | None = None) -> str:
    command = [tshark or find_tshark(), *args]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace")
    except OSError as exc:
        raise CaptureError(f"No se pudo ejecutar TShark: {exc}") from exc
    if result.returncode:
        detail = result.stderr.strip() or f"código {result.returncode}"
        raise CaptureError(f"TShark no pudo leer la captura: {detail}")
    return result.stdout


def _first(value: Any) -> str | None:
    if isinstance(value, list):
        return _first(value[0]) if value else None
    if value is None:
        return None
    return str(value)


def analyze_capture(path: str | Path, *, tshark: str | None = None) -> dict[str, Any]:
    """Extrae resumen de paquetes, protocolos, endpoints, DNS y conversaciones."""
    capture = Path(path).expanduser().resolve()
    if not capture.is_file():
        raise CaptureError(f"No existe el archivo de captura: {capture}")
    summary = _run_tshark(["-r", str(capture), "-q", "-z", "io,phs"], tshark=tshark)
    fields = _run_tshark([
        "-r", str(capture), "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
        "-e", "frame.number", "-e", "frame.protocols", "-e", "ip.src", "-e", "ipv6.src",
        "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.srcport", "-e", "udp.srcport",
        "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "dns.qry.name", "-e", "dns.a",
        "-e", "dns.aaaa", "-e", "dns.resp.name",
    ], tshark=tshark)

    protocols: Counter[str] = Counter()
    addresses: Counter[str] = Counter()
    conversations: Counter[tuple[str, str, str, str, str]] = Counter()
    dns_names: set[str] = set()
    dns_ips: set[str] = set()
    packets = 0
    for line in fields.splitlines():
        cols = line.split("\t")
        cols += [""] * (14 - len(cols))
        if cols[0]:
            packets += 1
        for proto in filter(None, cols[1].split(":")):
            protocols[proto] += 1
        src, dst = cols[2] or cols[3], cols[4] or cols[5]
        if src:
            addresses[src] += 1
        if dst:
            addresses[dst] += 1
        src_port, dst_port = cols[6] or cols[7], cols[8] or cols[9]
        transport = "TCP" if cols[6] or cols[8] else "UDP" if cols[7] or cols[9] else ""
        if src and dst:
            conversations[(transport, src, src_port, dst, dst_port)] += 1
        dns_names.update(x for x in (cols[10], cols[13]) if x)
        dns_ips.update(x for x in (cols[11], cols[12]) if x)

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
    """IPs globales (excluye privadas, loopback, reservadas y no especificadas)."""
    values = set(report.get("dns_ips", []))
    values.update(row["ip"] for row in report.get("ips", []))
    result: list[str] = []
    for value in values:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            continue
        if addr.is_global:
            result.append(str(addr))
    return sorted(result, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x))))


def export_json(report: dict[str, Any], destination: str | Path) -> None:
    Path(destination).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
