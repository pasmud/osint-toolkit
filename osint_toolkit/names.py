"""Canonical DNS names and owned-domain label boundaries."""

import re
import unicodedata

_DOTS = str.maketrans("\u3002\uff0e\uff61", "...")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _ascii_label(label: str) -> str:
    folded = unicodedata.normalize("NFC", label.lower())
    try:
        ascii_label = folded.encode("idna").decode("ascii")
        if _LABEL.fullmatch(ascii_label) is None:
            raise ValueError("invalid hostname label")
        if ascii_label.startswith("xn--"):
            decoded = ascii_label.encode("ascii").decode("idna")
            if decoded.encode("idna").decode("ascii") != ascii_label:
                raise ValueError("noncanonical IDNA label")
        else:
            decoded = ascii_label
    except UnicodeError:
        raise ValueError("invalid IDNA label") from None
    # Fail closed when the standard-library IDNA profile would silently
    # change label identity (e.g. sharp s to ss, or a joiner to nothing).
    if not folded.isascii() and decoded != folded:
        raise ValueError("lossy IDNA mapping")
    return ascii_label


def normalize_name(raw: str, *, allow_wildcard: bool = False) -> str:
    """Return a lowercase ASCII name without a trailing root dot."""
    name = raw.translate(_DOTS).removesuffix(".")
    wildcard = allow_wildcard and name.startswith("*.")
    if wildcard:
        name = name[2:]
    result = ".".join(_ascii_label(label) for label in name.split("."))
    if len(result) + (2 if wildcard else 0) > 253:
        raise ValueError("hostname exceeds 253 ASCII characters")
    return "*." + result if wildcard else result


def normalize_domain(raw: str) -> str:
    domain = normalize_name(raw)
    if "." not in domain or domain.replace(".", "").isdigit():
        raise ValueError("expected a dotted domain name, not an IP address")
    return domain


def in_scope(name: str, domain: str) -> bool:
    base = name.removeprefix("*.")
    return base == domain or base.endswith("." + domain)
