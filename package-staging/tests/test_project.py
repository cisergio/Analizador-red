from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from analizador.capture import CaptureError, analyze_capture, public_ip_addresses
from analizador.cli import process_capture
from analizador.report import write_reports
from analizador.virustotal import VirusTotalClient, VirusTotalError, summarize_ip_response


class CaptureTests(unittest.TestCase):
    def test_analyze_capture_extracts_and_counts(self):
        with tempfile.TemporaryDirectory() as td:
            capture = Path(td) / "tiny.pcap"
            capture.write_bytes(b"fixture")
            fields = "1\tip:tcp\t8.8.8.8\t\t192.168.1.2\t\t443\t\t50000\t\t\t\t\t\t\n"
            with patch("analizador.capture._run_tshark", side_effect=["Protocol Hierarchy", fields]):
                report = analyze_capture(capture, tshark="fake")
        self.assertEqual(report["packets"], 1)
        self.assertEqual(report["protocols"], {"ip": 1, "tcp": 1})
        self.assertEqual({x["ip"] for x in report["ips"]}, {"8.8.8.8", "192.168.1.2"})
        self.assertEqual(len(report["conversations"]), 1)

    def test_missing_capture_fails_before_tshark(self):
        with self.assertRaises(CaptureError):
            analyze_capture("does-not-exist.pcap")

    def test_configured_tshark_path(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / "tshark.exe"
            binary.write_bytes(b"placeholder")
            with patch.dict("os.environ", {"TSHARK_PATH": str(binary)}):
                from analizador.capture import find_tshark
                self.assertEqual(find_tshark(), str(binary))

    def test_public_ip_filter(self):
        report = {"ips": [{"ip": "8.8.8.8"}, {"ip": "192.168.0.1"}, {"ip": "2001:4860:4860::8888"}, {"ip": "127.0.0.1"}]}
        self.assertEqual(public_ip_addresses(report), ["8.8.8.8", "2001:4860:4860::8888"])


class VirusTotalTests(unittest.TestCase):
    def test_key_required(self):
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(VirusTotalError):
            VirusTotalClient(api_key="")

    def test_api_call_and_summary(self):
        session = Mock()
        response = Mock(status_code=200)
        response.json.return_value = {"data": {"attributes": {"country": "ES", "last_analysis_stats": {"malicious": 2, "harmless": 4}}}}
        session.get.return_value = response
        client = VirusTotalClient("secret", session=session, min_interval=0)
        payload = client.lookup_ip("8.8.8.8")
        session.get.assert_called_once()
        self.assertEqual(session.get.call_args.kwargs["headers"]["x-apikey"], "secret")
        self.assertEqual(summarize_ip_response("8.8.8.8", payload)["malicious"], 2)

    def test_http_error_is_translated(self):
        session = Mock()
        session.get.return_value.status_code = 429
        with self.assertRaisesRegex(VirusTotalError, "Cuota"):
            VirusTotalClient("key", session=session, min_interval=0).lookup_ip("8.8.4.4")

    def test_invalid_ip_is_rejected_without_request(self):
        session = Mock()
        with self.assertRaises(VirusTotalError):
            VirusTotalClient("key", session=session).lookup_ip("bad-ip")
        session.get.assert_not_called()


class ReportTests(unittest.TestCase):
    def test_txt_csv_written_with_errors(self):
        with tempfile.TemporaryDirectory() as td:
            txt, csv_path = write_reports({"file": "/tmp/capture.pcap", "packets": 3, "ips": [{"ip": "8.8.8.8", "packet_references": 3}], "protocols": {"tcp": 3}, "dns_names": ["example.com"]}, td, errors=["timeout"])
            self.assertTrue(txt.is_file())
            self.assertIn("timeout", txt.read_text(encoding="utf-8"))
            with csv_path.open(encoding="utf-8-sig", newline="") as f:
                rows = list(csv.reader(f))
            self.assertEqual(rows[1][1], "8.8.8.8")
            self.assertEqual(rows[-1][0], "error")

    def test_vt_failure_does_not_stop_next_ip(self):
        report = {"file": "test.pcap", "ips": [{"ip": "1.1.1.1", "packet_references": 1}, {"ip": "8.8.8.8", "packet_references": 1}], "dns_ips": [], "packets": 2, "protocols": {}, "dns_names": []}
        client = Mock()
        client.lookup_ip.side_effect = [VirusTotalError("timeout"), {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}]
        with patch("analizador.cli.analyze_capture", return_value=report), patch("analizador.cli.write_reports", return_value=(Path("report.txt"), Path("report.csv"))) as writer:
            result, vt_results, errors = process_capture("test.pcap", "out", vt_client=client, vt_enabled=True)
        self.assertEqual(len(vt_results), 1)
        self.assertEqual(vt_results[0]["ip"], "8.8.8.8")
        self.assertEqual(len(errors), 1)
        writer.assert_called_once()
        self.assertEqual(result["report_txt"], "report.txt")


if __name__ == "__main__":
    unittest.main()
