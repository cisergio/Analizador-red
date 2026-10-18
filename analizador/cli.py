"""Menú de consola del analizador."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from .capture import CaptureError, analyze_capture, public_ip_addresses
from .report import write_reports
from .virustotal import VirusTotalClient, VirusTotalError, summarize_ip_response


def process_capture(path: str, output_dir: str = "informes", *, vt_client: Any = None, vt_enabled: bool = False, tshark: str | None = None) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Coordina el análisis, las consultas online opcionales y la escritura de informes."""
    # Primera fase local: lee el PCAP/PCAPNG con TShark y construye el resumen base.
    report = analyze_capture(path, tshark=tshark)
    # Separamos resultados y errores para incluir ambos en la salida y en los informes.
    vt_results: list[dict[str, Any]] = []
    errors: list[str] = []
    if vt_enabled:
        # Permite inyectar un cliente simulado en pruebas; normalmente se crea el cliente real.
        client = vt_client or VirusTotalClient()
        # Se usa el número de referencias para consultar primero los destinos más vistos.
        counts = {row.get("ip"): row.get("packet_references", 0) for row in report.get("ips", [])}
        # La función filtra direcciones privadas y conserva también las direcciones públicas de DNS.
        ips = sorted(public_ip_addresses(report), key=lambda value: (-counts.get(value, 0), value))
        if not ips:
            print("VirusTotal: no se encontraron IPs públicas que consultar.", flush=True)
        else:
            print(f"\nConsultando {len(ips)} IP(s) en VirusTotal. Las peticiones se hacen de una en una.", flush=True)
        for index, ip in enumerate(ips, start=1):
            # perf_counter mide cuánto tarda cada consulta; flush hace visible el estado al momento.
            started = time.perf_counter()
            print(f"[{index}/{len(ips)}] Consultando {ip}...", end=" ", flush=True)
            try:
                # Las peticiones son secuenciales; un error concreto no impide probar la siguiente IP.
                vt_results.append(summarize_ip_response(ip, client.lookup_ip(ip)))
                elapsed = time.perf_counter() - started
                print(f"OK ({elapsed:.1f} s)", flush=True)
            except VirusTotalError as exc:
                errors.append(f"VirusTotal {ip}: {exc}")
                elapsed = time.perf_counter() - started
                print(f"ERROR ({elapsed:.1f} s): {exc}", flush=True)
                continue
        if ips:
            print(f"Consultas VirusTotal terminadas: {len(vt_results)} correctas, {len(errors)} con error.", flush=True)
    # Se escriben ambos formatos incluso si algunas consultas online fallaron.
    txt, csv = write_reports(report, output_dir, vt_results, errors)
    # Guardamos sus rutas en el resumen para que el menú pueda mostrarlas al usuario.
    report["report_txt"] = str(txt)
    report["report_csv"] = str(csv)
    return report, vt_results, errors


def main() -> int:
    """Punto de entrada interactivo: muestra opciones y recoge los datos del usuario."""
    print("Analizador de capturas de red")
    while True:
        print("\n1. Analizar captura PCAP/PCAPNG\n2. Salir")
        choice = input("Opción: ").strip()
        if choice == "2":
            # Código 0 significa que el programa terminó normalmente.
            return 0
        if choice != "1":
            print("Opción no válida.")
            continue
        path = input("Ruta de la captura: ").strip().strip('"')
        # Evita lanzar TShark si el usuario escribió una ruta incorrecta.
        if not Path(path).is_file():
            print("No existe el archivo indicado.")
            continue
        vt_choice = input("Consultar IPs públicas en VirusTotal? (s/N): ").strip().lower()
        # Solo una respuesta afirmativa activa peticiones de red.
        vt_enabled = vt_choice in {"s", "si", "sí", "y", "yes"}
        if vt_enabled and not os.getenv("VT_API_KEY"):
            print("Configura VT_API_KEY antes de usar VirusTotal.")
            continue
        # Enter elige el directorio por defecto; el usuario puede especificar cualquier ruta.
        output_dir = input("Carpeta donde guardar los informes [informes]: ").strip().strip('"') or "informes"
        try:
            report, _, errors = process_capture(path, output_dir=output_dir, vt_enabled=vt_enabled)
            print(f"\nPaquetes: {report['packets']} | IPs: {len(report['ips'])}")
            print(f"Informes: {report['report_txt']} y {report['report_csv']}")
            for error in errors:
                print(f"Aviso: {error}")
        except (CaptureError, VirusTotalError) as exc:
            # Errores previstos (TShark/API/configuración) se muestran sin cerrar el menú.
            print(f"Error: {exc}")
        except (OSError, json.JSONDecodeError) as exc:
            # Errores al guardar archivos u otras operaciones locales también se reportan.
            print(f"Error al guardar o procesar el informe: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
