import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from osint_toolkit.inventory import write_csv

ROOT = Path(__file__).resolve().parents[1]
CT = ("--ct", "fixtures/certificates.json")
ZONE_A = ("--dns", "fixtures/zone-a.json")
ZONE_B = ("--dns", "fixtures/zone-b.json")


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "osint_toolkit", *args],
        cwd=ROOT,
        capture_output=True,
        check=False,
        encoding="utf-8",
        timeout=5,
    )


class ReportTests(unittest.TestCase):
    def test_fixture_inventory_merges_only_scoped_evidence(self):
        result = run_cli("--domain", "Orchard.example.", *CT, *ZONE_A, *ZONE_B, "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        actual = {
            entry["name"]: (
                entry["certificate_ids"],
                [(r["type"], r["value"], r["snapshot_ids"]) for r in entry["dns_records"]],
            )
            for entry in report["names"]
        }
        a, b = "synthetic-zone-a", "synthetic-zone-b"
        self.assertEqual(report["domain"], "orchard.example")
        self.assertEqual(report["counts"], {
            "names": 5, "certificate_observations": 6, "dns_records": 6, "dns_observations": 8,
        })
        self.assertEqual(actual, {
            "*.dev.orchard.example": ([101], []),
            "files.orchard.example": ([], [("CNAME", "www.orchard.example", [a])]),
            "orchard.example": ([101], [
                ("MX", "10 mail.orchard.example", [a]), ("NS", "ns1.provider.example", [a]),
            ]),
            "www.orchard.example": ([101, 102], [
                ("A", "192.0.2.10", [a, b]), ("A", "192.0.2.11", [b]),
                ("AAAA", "2001:db8::10", [a, b]),
            ]),
            "xn--bcher-kva.orchard.example": ([101, 102], []),
        })

    def test_order_and_repeated_files_do_not_change_json(self):
        base = ("--domain", "orchard.example", "--format", "json")
        first = run_cli(*base, *CT, *ZONE_A, *ZONE_B)
        second = run_cli(*base, *ZONE_B, *ZONE_A, *CT, *ZONE_A, *CT)
        for result in (first, second):
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(first.stdout, second.stdout)

    def test_default_text_for_unmatched_scope(self):
        result = run_cli("--domain", "other.example", *CT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "Domain: other.example",
            "Names: 0 | Certificate observations: 0 | DNS records: 0 | DNS observations: 0",
            "No matching evidence.",
        ])

    def test_nonempty_text_lists_dns_provenance(self):
        result = run_cli("--domain", "www.orchard.example", *CT, *ZONE_A, *ZONE_B)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[2:], [
            "",
            "www.orchard.example",
            "  Certificate IDs: 101, 102",
            "  A 192.0.2.10 (snapshots: synthetic-zone-a, synthetic-zone-b)",
            "  A 192.0.2.11 (snapshots: synthetic-zone-b)",
            "  AAAA 2001:db8::10 (snapshots: synthetic-zone-a, synthetic-zone-b)",
        ])

    def test_invalid_invocations(self):
        for args in (CT, ("--domain", "orchard.example"), ("--domain", "*.orchard.example", *CT)):
            with self.subTest(args=args):
                result = run_cli(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("error:", result.stderr)


class CsvTests(unittest.TestCase):
    def test_csv_flattens_unique_observations_in_report_order(self):
        args = ("--domain", "orchard.example", "--format", "csv")
        first = run_cli(*args, *CT, *ZONE_A, *ZONE_B)
        second = run_cli(*args, *ZONE_B, *CT, *ZONE_A, *ZONE_B, *CT)
        for result in (first, second):
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(first.stdout, second.stdout)
        reader = csv.DictReader(io.StringIO(first.stdout))
        self.assertEqual(reader.fieldnames, [
            "domain", "name", "evidence_type", "certificate_id", "record_type", "record_value",
            "snapshot_id",
        ])
        rows = list(reader)
        self.assertEqual({row["domain"] for row in rows}, {"orchard.example"})
        self.assertEqual(len(rows), 14)
        self.assertEqual(rows[0], {
            "domain": "orchard.example", "name": "*.dev.orchard.example", "evidence_type": "ct",
            "certificate_id": "101", "record_type": "", "record_value": "", "snapshot_id": "",
        })
        www = [row for row in rows if row["name"] == "www.orchard.example"]
        self.assertEqual([
            (r["evidence_type"], r["certificate_id"], r["record_type"], r["record_value"], r["snapshot_id"])
            for r in www
        ], [
            ("ct", "101", "", "", ""),
            ("ct", "102", "", "", ""),
            ("dns", "", "A", "192.0.2.10", "synthetic-zone-a"),
            ("dns", "", "A", "192.0.2.10", "synthetic-zone-b"),
            ("dns", "", "A", "192.0.2.11", "synthetic-zone-b"),
            ("dns", "", "AAAA", "2001:db8::10", "synthetic-zone-a"),
            ("dns", "", "AAAA", "2001:db8::10", "synthetic-zone-b"),
        ])

    def test_csv_empty_report_has_header_only(self):
        result = run_cli("--domain", "other.example", "--format", "csv", *CT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertEqual(next(csv.reader(io.StringIO(result.stdout)))[0], "domain")

    def test_csv_neutralizes_formula_prefixes_and_quotes_delimiters(self):
        values = ["=", "+", "-", "@", "  =", "\ttext", "\rtext", "\ntext", "＝", 'a,"b"']
        report = {"domain": "orchard.example", "names": [{
            "name": "orchard.example", "certificate_ids": [],
            "dns_records": [{"type": "NS", "value": v, "snapshot_ids": ["synthetic"]} for v in values],
        }]}
        stream = io.StringIO(newline="")
        write_csv(report, stream)
        rows = list(csv.DictReader(io.StringIO(stream.getvalue(), newline="")))
        self.assertTrue(all(row["snapshot_id"] == "synthetic" for row in rows))
        self.assertEqual([row["record_value"] for row in rows], [
            "'=", "'+", "'-", "'@", "'  =", "'\ttext", "'\rtext", "'\ntext", "'＝", 'a,"b"',
        ])


class InputTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(directory) / "synthetic export.json"

    def run_with(self, flag, data, *extra):
        self.path.write_text(json.dumps(data), encoding="utf-8")
        return run_cli("--domain", "orchard.example", "--format", "json", *extra, flag, str(self.path))

    def assert_input_error(self, result, message):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn(self.path.name, result.stderr)
        self.assertIn(message, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_malformed_json_utf8_duplicate_keys_and_missing_file(self):
        result = run_cli("--domain", "orchard.example", "--ct", str(self.path))
        self.assert_input_error(result, "CT file")
        for content, problem in (
            (b"[\n  {]", "line 2, column 4"),
            (b"\xff", "UTF-8"),
            (b'[{"id":1,"id":2}]', "duplicate JSON object key"),
            (b"[NaN]", "non-finite JSON number"),
        ):
            with self.subTest(content=content):
                self.path.write_bytes(content)
                result = run_cli("--domain", "orchard.example", "--ct", str(self.path))
                self.assert_input_error(result, problem)

    def test_json_file_limit_counts_bytes_and_identifies_input_type(self):
        limit = 8_388_608
        for flag, source, content in (
            ("--ct", "CT", b"[]"),
            ("--dns", "DNS", '{"snapshot_id":"limit","records":[],"extra":"é"}'.encode()),
        ):
            with self.subTest(flag=flag):
                self.path.write_bytes(content.ljust(limit, b" "))
                args = ("--domain", "orchard.example", *CT, flag, str(self.path))
                result = run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                with self.path.open("ab") as stream:
                    stream.write(b" ")
                self.assert_input_error(
                    run_cli(*args), f"{source} file {str(self.path)!r}: JSON file exceeds the {limit}-byte limit"
                )

    def test_ct_rejects_invalid_rows_without_partial_output(self):
        for data, problem in (
            ({}, "JSON array"),
            ([{"id": True, "name_value": "orchard.example"}], "row 1: id"),
            ([{"id": 7, "name_value": " \t\r\n"}], "contain at least one name"),
            ([{"id": 7, "name_value": "orchard.example\n*.bad.*.example"}], "row 1, name_value line 2"),
        ):
            with self.subTest(data=data):
                self.assert_input_error(self.run_with("--ct", data, *CT), problem)

    def test_dns_rejects_invalid_records_even_outside_scope(self):
        for owner, kind, value, problem in (
            ("external.example", "TXT", "ignored metadata", "type must be"),
            ("orchard.example", "A", "2001:db8::1", "invalid A value"),
            ("orchard.example", "AAAA", "fe80::1%eth0", "invalid AAAA value"),
            ("orchard.example", "MX", "65536 mail.example", "invalid MX value"),
            ("orchard.example", "MX", "10 .", "invalid MX value"),
            ("orchard.example", "NS", "*.example", "invalid NS value"),
            ("*.orchard.example", "A", "192.0.2.1", "invalid owner name"),
        ):
            with self.subTest(owner=owner, kind=kind, value=value):
                data = {
                    "snapshot_id": "test-01",
                    "records": [{"name": owner, "type": kind, "value": value}],
                }
                self.assert_input_error(self.run_with("--dns", data), f"DNS record 1: {problem}")

    def test_dns_rejects_bad_snapshot_label(self):
        result = self.run_with("--dns", {"snapshot_id": "invalid id", "records": []})
        self.assert_input_error(result, "snapshot_id")

    def test_crlf_null_mx_unicode_owner_and_extra_metadata(self):
        certs = self.path.with_name("certs.json")
        certs.write_text(json.dumps([{
            "id": 0,
            "name_value": " BÜCHER.Orchard.example. \r\n\r\nXN--BCHER-KVA.orchard.example",
            "extra": "unused synthetic metadata",
        }]), encoding="utf-8")
        result = self.run_with("--dns", {
            "snapshot_id": "metadata-test",
            "records": [{
                "name": "Bücher.Orchard.example", "type": "MX", "value": "00\t.", "ttl": 300,
            }],
        }, "--ct", str(certs))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["names"], [{
            "name": "xn--bcher-kva.orchard.example",
            "certificate_ids": [0],
            "dns_records": [{"type": "MX", "value": "0 .", "snapshot_ids": ["metadata-test"]}],
        }])
