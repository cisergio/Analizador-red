"""Generación de reportes legibles TXT y CSV."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def write_reports(report: dict[str, Any], destination: str | Path, vt_results: list[dict[str, Any]] | None = None, errors: list[str] | None = None) -> tuple[Path, Path]:
    """Crea versiones TXT y CSV y devuelve las rutas de ambos archivos."""
    # Crea la carpeta de destino y sus carpetas padre si aún no existen.
    out = Path(destination)
    out.mkdir(parents=True, exist_ok=True)
    # El nombre base procede de la captura, pero las extensiones identifican el tipo de informe.
    stem = Path(report.get("file", "captura")).stem
    txt_path, csv_path = out / f"{stem}_informe.txt", out / f"{stem}_informe.csv"
    # None equivale a listas vacías: así el resto del código puede iterar sin comprobar cada vez.
    vt_results, errors = vt_results or [], errors or []
    # Construimos líneas en memoria para escribir el TXT de una sola vez.
    lines = [
        "INFORME DE ANÁLISIS DE CAPTURA", "=" * 34,
        f"Archivo: {report.get('file', '')}", f"Paquetes analizados: {report.get('packets', 0)}", "",
        "PROTOCOLOS", "----------",
    ]
    # Si una categoría está vacía, dejamos un mensaje claro en vez de una sección en blanco.
    lines += [f"{name}: {count}" for name, count in report.get("protocols", {}).items()] or ["Sin datos"]
    lines += ["", "DIRECCIONES IP", "--------------"]
    lines += [f"{row['ip']} ({row['packet_references']} referencias)" for row in report.get("ips", [])] or ["Sin datos"]
    lines += ["", "CONSULTAS DNS", "-------------"] + (report.get("dns_names", []) or ["Sin datos"])
    lines += ["", "RESULTADOS VIRUSTOTAL", "---------------------"]
    # Añade un resumen corto por IP; el CSV conserva también los campos en columnas.
    if vt_results:
        lines += [f"{r.get('ip')}: maliciosas={r.get('malicious', 0)}, sospechosas={r.get('suspicious', 0)}, reputación={r.get('reputation')}" for r in vt_results]
    else:
        lines.append("Sin consultas")
    # Cada error queda en el archivo para que los resultados parciales sean auditables.
    lines += ["", "ERRORES", "-------"] + (errors or ["Ninguno"])
    # UTF-8 permite guardar acentos y otros caracteres sin perderlos.
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # newline="" es la forma recomendada por csv; utf-8-sig facilita abrirlo en Excel.
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["tipo", "ip", "referencias_paquetes", "maliciosas", "sospechosas", "reputacion", "pais", "asn", "detalle"])
        # Relaciona cada IP consultada con su resultado para completar las filas de IP.
        vt_by_ip = {r.get("ip"): r for r in vt_results}
        for row in report.get("ips", []):
            # Las IP privadas o no consultadas siguen apareciendo; sus columnas VT quedan vacías.
            vt = vt_by_ip.get(row["ip"], {})
            writer.writerow(["ip", row["ip"], row.get("packet_references", 0), vt.get("malicious", ""), vt.get("suspicious", ""), vt.get("reputation", ""), vt.get("country", ""), vt.get("asn", ""), ""])
        for name in report.get("dns_names", []):
            # DNS usa una fila de tipo dns y almacena el nombre en la columna detalle.
            writer.writerow(["dns", "", "", "", "", "", "", "", name])
        for error in errors:
            # Los errores se guardan como filas distintas para que no se pierdan en el CSV.
            writer.writerow(["error", "", "", "", "", "", "", "", error])
    return txt_path, csv_path
