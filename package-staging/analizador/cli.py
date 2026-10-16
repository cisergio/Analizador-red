"""Menú de consola del analizador."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .capture import CaptureError, analyze_capture, public_ip_addresses
from .report import write_reports
from .virustotal import VirusTotalClient, VirusTotalError, summarize_ip_response


def process_capture(path: str, output_dir: str = "informes", *, vt_client: Any = None, vt_enabled: bool = False, tshark: str | None = None) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    report = analyze_capture(path, tshark=tshark)
    vt_results: list[dict[str, Any]] = []
    errors: list[str] = []
    if vt_enabled:
        client = vt_client or VirusTotalClient()
        counts = {row.get("ip"): row.get("packet_references", 0) for row in report.get("ips", [])}
        for ip in sorted(public_ip_addresses(report), key=lambda value: (-counts.get(value, 0), value)):
            try:
                vt_results.append(summarize_ip_response(ip, client.lookup_ip(ip)))
            except VirusTotalError as exc:
                errors.append(f"VirusTotal {ip}: {exc}")
                continue
    txt, csv = write_reports(report, output_dir, vt_results, errors)
    report["report_txt"] = str(txt)
    report["report_csv"] = str(csv)
    return report, vt_results, errors


def main() -> int:
    print("Analizador de capturas de red")
    while True:
        print("\n1. Analizar captura PCAP/PCAPNG\n2. Salir")
        choice = input("Opción: ").strip()
        if choice == "2":
            return 0
        if choice != "1":
            print("Opción no válida.")
            continue
        path = input("Ruta de la captura: ").strip().strip('"')
        if not Path(path).is_file():
            print("No existe el archivo indicado.")
            continue
        vt_choice = input("Consultar IPs públicas en VirusTotal? (s/N): ").strip().lower()
        vt_enabled = vt_choice in {"s", "si", "sí", "y", "yes"}
        if vt_enabled and not os.getenv("VT_API_KEY"):
            print("Configura VT_API_KEY antes de usar VirusTotal.")
            continue
        try:
            report, _, errors = process_capture(path, vt_enabled=vt_enabled)
            print(f"\nPaquetes: {report['packets']} | IPs: {len(report['ips'])}")
            print(f"Informes: {report['report_txt']} y {report['report_csv']}")
            for error in errors:
                print(f"Aviso: {error}")
        except (CaptureError, VirusTotalError) as exc:
            print(f"Error: {exc}")
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Error al guardar o procesar el informe: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
