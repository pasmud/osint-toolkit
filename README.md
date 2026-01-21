# OSINT Toolkit: offline asset evidence

Build a repeatable inventory for one domain you own from certificate transparency (CT)-style JSON and DNS snapshots you already have. The CLI reads local files, filters names by DNS label, and reports what each export observed. It performs no DNS lookups, HTTP requests, discovery, or target enumeration.

## Quickstart

From the repository root, run the following with Python 3.11 or newer. No packages or installation are required. The fixtures are entirely synthetic and use reserved example names and documentation IP addresses.

```sh
python3 -m osint_toolkit --domain orchard.example \
  --ct fixtures/certificates.json \
  --dns fixtures/zone-a.json --dns fixtures/zone-b.json
```

The output starts with:

```text
Domain: orchard.example
Names: 5 | Certificate observations: 6 | DNS records: 6 | DNS observations: 8
```

The report entry for `www.orchard.example` shows how the same address from two snapshots is listed once while retaining both snapshot IDs:

```text
www.orchard.example
  Certificate IDs: 101, 102
  A 192.0.2.10 (snapshots: synthetic-zone-a, synthetic-zone-b)
  A 192.0.2.11 (snapshots: synthetic-zone-b)
  AAAA 2001:db8::10 (snapshots: synthetic-zone-a, synthetic-zone-b)
```

Either input type can be used alone. Repeat `--ct` or `--dns` to merge files. Use `--format json` for machine-readable output on stdout:

```sh
python3 -m osint_toolkit --domain orchard.example \
  --dns fixtures/zone-a.json --format json > inventory.json
```

Run `python3 -m osint_toolkit --help` for the complete interface.

## CSV evidence export

```sh
python3 -m osint_toolkit --domain orchard.example \
  --ct fixtures/certificates.json --dns fixtures/zone-a.json --format csv > evidence.csv
```

CSV columns are `domain`, `name`, `evidence_type`, `certificate_id`, `record_type`, `record_value`, and `snapshot_id`. Each `ct` row is one distinct name/certificate pair; each `dns` row is one distinct record/snapshot pair. Nonapplicable fields are empty. Rows follow the report's canonical order, with CT before DNS for each name. An empty report contains only the header.

CSV quotes all cells and prefixes an apostrophe to values that could be interpreted as spreadsheet formulas. Import columns as text if the spreadsheet would otherwise coerce identifiers (for example, large certificate IDs); use JSON for exact machine-readable evidence.

## Input formats

Use UTF-8 JSON files and sanitized exports for your owned domain. Each CT or DNS file may be at most 8 MiB (8,388,608 bytes), including whitespace and extra fields. Larger files are rejected before parsing, with the file path and byte limit in the error. Extra fields are not included in the report. Use opaque snapshot IDs and omit personal data from the input.

**CT-style export:** An array of objects. Each requires a nonnegative integer `id` from one consistent certificate ID namespace and a `name_value` string with at least one name. Separate names with LF or CRLF; blank lines and spaces or tabs around lines are ignored. CT wildcard names may use one complete leftmost `*` label.

```json
[
  {"id": 101, "name_value": "orchard.example\n*.dev.orchard.example"}
]
```

**DNS snapshot:** An object containing a case-sensitive `snapshot_id` and a `records` array. Each record needs string fields `name` (owner), `type`, and `value`. IDs are 1–64 ASCII letters, digits, dots, underscores or hyphens and start with a letter or digit. Give distinct snapshots distinct IDs; repeated IDs denote the same source. Names are treated as absolute with or without a final dot; zone-file shorthand, including `@`, is unsupported.

```json
{
  "snapshot_id": "synthetic-zone-a",
  "records": [
    {"name": "www.orchard.example.", "type": "A", "value": "192.0.2.10"},
    {"name": "orchard.example", "type": "MX", "value": "10 mail.orchard.example."}
  ]
}
```

Supported types are `A`, `AAAA`, `CNAME`, `MX`, and `NS` (case-insensitive). `A` and `AAAA` require an address of the matching family; IPv6 zone identifiers are unsupported. `CNAME` and `NS` take a hostname. `MX` takes a 1–5 digit preference (0–65535) followed by spaces or tabs and a hostname; `0 .` represents null MX. DNS wildcard owners, wildcard record values, service labels such as `_tcp`, TXT records, and other record types are unsupported.

## Scope and report semantics

- Hostnames normalize to lowercase ASCII: Unicode names are normalized with NFC and Python's standard-library IDNA profile (IDNA 2003), and a single trailing root dot is removed. Valid Unicode and Punycode spellings such as `bücher` and `xn--bcher-kva` merge. Names that would require lossy IDNA mapping (for example, `straße` to `strasse`) are rejected. This is not a full IDNA 2008 or browser URL parser.
- `orchard.example` matches itself and `www.orchard.example`, but excludes `notorchard.example` and `orchard.example.invalid`. Wildcards are matched by their base and kept as separate patterns: `*.dev.orchard.example` does not add `dev.orchard.example` or any concrete host. DNS records are scoped by owner. A target outside the domain may appear as a value on an in-scope record, but is never promoted to an inventory entry or followed.
- JSON includes `domain`, `counts`, and `names`; each name has `certificate_ids` and `dns_records`. A certificate observation is a unique name/ID pair. A DNS record is a unique owner/type/canonical value; a DNS observation adds a snapshot ID. Certificate IDs sort numerically; names, record types/values and snapshot IDs sort lexically. The same evidence yields the same report regardless of import order or repeated files.
- The caller supplies the ownership boundary. Reports do not establish ownership, current DNS state, host availability, certificate validity, or export authenticity. Source IDs are supplied by the exports, not independently verified. Files are loaded in memory; use small local snapshots rather than bulk archives.

Exit `0` means a report was generated, including when no evidence matched. Exit `1` means an input file could not be read or failed parsing or schema validation; no partial report is printed. Errors go to stderr and identify the file and, where applicable, the row or JSON line and column. Validation also applies to out-of-scope rows. Exit `2` means invalid CLI usage or an invalid domain.

## Verification

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q osint_toolkit tests
git diff --check
```

CI runs the tests and compilation checks on Python 3.11 and 3.14. Test inputs are local and synthetic; the suite does not contact any live service.

The January 2026 commit timeline is illustrative and is not evidence of work or activity on those dates. Released under the [MIT License](LICENSE).
