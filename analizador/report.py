"""Generación de reportes legibles TXT y CSV."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def write_reports(report: dict[str, Any], destination: str | Path, vt_results: list[dict[str, Any]] | None = None, errors: list[str] | None = None) -> tuple[Path, Path]:
    out = Path(destination)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(report.get("file", "captura")).stem
    txt_path, csv_path = out / f"{stem}_informe.txt", out / f"{stem}_informe.csv"
    vt_results, errors = vt_results or [], errors or []
    lines = [
        "INFORME DE ANÁLISIS DE CAPTURA", "=" * 34,
        f"Archivo: {report.get('file', '')}", f"Paquetes analizados: {report.get('packets', 0)}", "",
        "PROTOCOLOS", "----------",
    ]
    lines += [f"{name}: {count}" for name, count in report.get("protocols", {}).items()] or ["Sin datos"]
    lines += ["", "DIRECCIONES IP", "--------------"]
    lines += [f"{row['ip']} ({row['packet_references']} referencias)" for row in report.get("ips", [])] or ["Sin datos"]
    lines += ["", "CONSULTAS DNS", "-------------"] + (report.get("dns_names", []) or ["Sin datos"])
    lines += ["", "RESULTADOS VIRUSTOTAL", "---------------------"]
    if vt_results:
        lines += [f"{r.get('ip')}: maliciosas={r.get('malicious', 0)}, sospechosas={r.get('suspicious', 0)}, reputación={r.get('reputation')}" for r in vt_results]
    else:
        lines.append("Sin consultas")
    lines += ["", "ERRORES", "-------"] + (errors or ["Ninguno"])
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["tipo", "ip", "referencias_paquetes", "maliciosas", "sospechosas", "reputacion", "pais", "asn", "detalle"])
        vt_by_ip = {r.get("ip"): r for r in vt_results}
        for row in report.get("ips", []):
            vt = vt_by_ip.get(row["ip"], {})
            writer.writerow(["ip", row["ip"], row.get("packet_references", 0), vt.get("malicious", ""), vt.get("suspicious", ""), vt.get("reputation", ""), vt.get("country", ""), vt.get("asn", ""), ""])
        for name in report.get("dns_names", []):
            writer.writerow(["dns", "", "", "", "", "", "", "", name])
        for error in errors:
            writer.writerow(["error", "", "", "", "", "", "", "", error])
    return txt_path, csv_path
