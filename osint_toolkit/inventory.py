"""Load supported exports and merge their observations into an inventory."""

import csv
import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from .names import in_scope, normalize_name

_SNAPSHOT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "SOA"}
_MAX_JSON_BYTES = 8 * 1024 * 1024


class InputError(ValueError):
    """Invalid or unreadable evidence input."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(_constant):
    raise InputError("non-finite JSON number")


def _load(path: Path):
    try:
        with path.open("rb") as stream:
            content = stream.read(_MAX_JSON_BYTES + 1)
        if len(content) > _MAX_JSON_BYTES:
            raise InputError(f"JSON file exceeds the {_MAX_JSON_BYTES}-byte limit")
        return json.loads(
            content.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON at line {exc.lineno}, column {exc.colno}") from None
    except UnicodeError:
        raise InputError("expected a UTF-8 JSON file") from None
    except InputError:
        raise
    except (ValueError, RecursionError):
        raise InputError("JSON exceeds parser limits") from None
    except OSError as exc:
        raise InputError(exc.strerror or "cannot read file") from None


def _invalid(location: str, problem: str) -> InputError:
    return InputError(f"{location}: {problem}")


def _ct_observations(data):
    if not isinstance(data, list):
        raise InputError("expected a JSON array of certificate rows")
    for index, row in enumerate(data, 1):
        location = f"certificate row {index}"
        if not isinstance(row, dict):
            raise _invalid(location, "expected an object")
        cert_id = row.get("id")
        if type(cert_id) is not int or cert_id < 0:
            raise _invalid(location, "id must be a nonnegative integer")
        names = row.get("name_value")
        if not isinstance(names, str):
            raise _invalid(location, "name_value must be a string")
        found = False
        for line_number, line in enumerate(names.replace("\r\n", "\n").split("\n"), 1):
            line = line.strip(" \t")
            if not line:
                continue
            found = True
            try:
                name = normalize_name(line, allow_wildcard=True)
            except ValueError as exc:
                raise _invalid(f"{location}, name_value line {line_number}", str(exc)) from None
            yield name, cert_id
        if not found:
            raise _invalid(location, "name_value must contain at least one name")


def _record_value(kind: str, value: str) -> str:
    if kind in {"A", "AAAA"}:
        if kind == "A":
            return str(ipaddress.IPv4Address(value))
        if "%" in value:
            raise ValueError("zone identifiers are not DNS address data")
        return str(ipaddress.IPv6Address(value))
    if kind == "MX":
        parts = re.split(r"[ \t]+", value)
        if len(parts) != 2 or re.fullmatch(r"[0-9]{1,5}", parts[0]) is None:
            raise ValueError("expected an MX preference and hostname")
        preference = int(parts[0])
        if preference > 65535:
            raise ValueError("MX preference exceeds 65535")
        if parts[1] == "." and preference == 0:
            return "0 ."
        return f"{preference} {normalize_name(parts[1])}"
    if kind == "SOA":
        parts = re.split(r"[ \t]+", value)
        if len(parts) != 7 or any(re.fullmatch(r"[0-9]{1,10}", part) is None for part in parts[2:]):
            raise ValueError("expected two DNS names and five decimal SOA fields")
        fields = [int(part) for part in parts[2:]]
        if any(field > 0xFFFFFFFF for field in fields):
            raise ValueError("SOA fields must fit in unsigned 32 bits")
        return " ".join([normalize_name(parts[0]), normalize_name(parts[1]), *map(str, fields)])
    return normalize_name(value)


def _dns_observations(data):
    if not isinstance(data, dict) or not isinstance(data.get("records"), list):
        raise InputError("expected an object with a records array")
    snapshot = data.get("snapshot_id")
    if not isinstance(snapshot, str) or _SNAPSHOT_ID.fullmatch(snapshot) is None:
        raise InputError("snapshot_id must be a 1–64 character ASCII identifier")
    for index, row in enumerate(data["records"], 1):
        location = f"DNS record {index}"
        if not isinstance(row, dict):
            raise _invalid(location, "expected an object")
        owner, kind, value = (row.get(field) for field in ("name", "type", "value"))
        if not all(isinstance(item, str) for item in (owner, kind, value)):
            raise _invalid(location, "name, type and value must be strings")
        kind = kind.upper() if kind.isascii() else ""
        if kind not in _RECORD_TYPES:
            raise _invalid(location, f"type must be one of {', '.join(sorted(_RECORD_TYPES))}")
        try:
            name = normalize_name(owner)
        except ValueError as exc:
            raise _invalid(location, f"invalid owner name ({exc})") from None
        try:
            canonical_value = _record_value(kind, value)
        except ValueError:
            raise _invalid(location, f"invalid {kind} value") from None
        yield name, kind, canonical_value, snapshot


@dataclass
class _Evidence:
    certificates: set[int] = field(default_factory=set)
    dns_records: dict[tuple[str, str], set[str]] = field(default_factory=dict)


def build_report(domain: str, ct_paths: list[Path], dns_paths: list[Path]) -> dict:
    """Build the report for an already normalized scope, or raise InputError."""
    by_name: dict[str, _Evidence] = defaultdict(_Evidence)
    for path in ct_paths:
        try:
            for name, cert_id in _ct_observations(_load(path)):
                if in_scope(name, domain):
                    by_name[name].certificates.add(cert_id)
        except InputError as exc:
            raise InputError(f"CT file {str(path)!r}: {exc}") from None
    for path in dns_paths:
        try:
            for name, kind, value, snapshot in _dns_observations(_load(path)):
                if in_scope(name, domain):
                    evidence = by_name[name]
                    evidence.dns_records.setdefault((kind, value), set()).add(snapshot)
        except InputError as exc:
            raise InputError(f"DNS file {str(path)!r}: {exc}") from None

    names = [
        {
            "name": name,
            "certificate_ids": sorted(evidence.certificates),
            "dns_records": [
                {"type": kind, "value": value, "snapshot_ids": sorted(snapshots)}
                for (kind, value), snapshots in sorted(evidence.dns_records.items())
            ],
        }
        for name, evidence in sorted(by_name.items())
    ]
    return {
        "domain": domain,
        "counts": {
            "names": len(names),
            "certificate_observations": sum(len(item["certificate_ids"]) for item in names),
            "dns_records": sum(len(item["dns_records"]) for item in names),
            "dns_observations": sum(
                len(record["snapshot_ids"]) for item in names for record in item["dns_records"]
            ),
        },
        "names": names,
    }


def render_text(report: dict) -> str:
    counts = report["counts"]
    lines = [
        f"Domain: {report['domain']}",
        f"Names: {counts['names']} | Certificate observations: {counts['certificate_observations']}"
        f" | DNS records: {counts['dns_records']} | DNS observations: {counts['dns_observations']}",
    ]
    if not report["names"]:
        lines.append("No matching evidence.")
    for item in report["names"]:
        lines.extend(("", item["name"]))
        if item["certificate_ids"]:
            lines.append("  Certificate IDs: " + ", ".join(map(str, item["certificate_ids"])))
        for record in item["dns_records"]:
            sources = ", ".join(record["snapshot_ids"])
            lines.append(f"  {record['type']} {record['value']} (snapshots: {sources})")
    return "\n".join(lines)


def _csv_cell(value: str | int) -> str:
    text = str(value)
    # CSV quoting preserves cell boundaries but does not prevent formula evaluation.
    if text.startswith(("\t", "\r", "\n")) or text.lstrip().startswith(
        ("=", "+", "-", "@", "＝", "＋", "－", "＠")
    ):
        return "'" + text
    return text


def write_csv(report: dict, stream: TextIO) -> None:
    """Write one spreadsheet-safe CSV row for each certificate or DNS observation."""
    writer = csv.writer(stream, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow((
        "domain", "name", "evidence_type", "certificate_id", "record_type", "record_value",
        "snapshot_id",
    ))
    domain = _csv_cell(report["domain"])
    for item in report["names"]:
        name = _csv_cell(item["name"])
        for cert_id in item["certificate_ids"]:
            writer.writerow((domain, name, "ct", _csv_cell(cert_id), "", "", ""))
        for record in item["dns_records"]:
            kind, value = _csv_cell(record["type"]), _csv_cell(record["value"])
            for snapshot in record["snapshot_ids"]:
                writer.writerow((domain, name, "dns", "", kind, value, _csv_cell(snapshot)))
