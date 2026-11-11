"""Stdlib port of the Curation Atlas receipt canonical form (lib/audit.ts).

``canonicalize`` must equal the TypeScript ``canonicalize`` byte for byte for any
value that ``JSON.parse`` could produce, and ``create_receipt`` must produce the
same envelope and ``receiptSha256`` as ``createReceipt`` for the same audit and
``generatedAt``. The rules that make that possible:

* numbers are IEEE-754 doubles printed with ECMAScript ``Number::toString``;
  non-finite values print as ``null`` (Python ``int`` is first rounded to a
  double, exactly as ``JSON.parse`` rounds an integer literal);
* strings are escaped like ES2019 ``JSON.stringify``: lone surrogates become
  lowercase ``\\udxxx`` escapes, everything else outside the mandatory escapes
  stays literal; a surrogate pair held as two Python code points is treated as
  the single astral character JavaScript would see;
* object keys are sorted by UTF-16 code units (``Array.prototype.sort``);
* ``UNDEFINED`` stands for a JavaScript ``undefined`` value: it is dropped from
  objects and prints ``null`` elsewhere. Callables print ``null`` (the TS
  ``canonicalize`` keeps function-valued keys and ``JSON.stringify`` returns
  ``undefined`` for them).

A receipt is a self-asserted digest, not a signature: anyone can make one that
verifies. This module never claims more than that.

No third-party imports, so it loads without fastapi or httpx.
"""

from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

__all__ = [
    "RECEIPT_SCHEMA",
    "RECEIPT_CLAIM",
    "UNDEFINED",
    "ReceiptError",
    "canonicalize",
    "create_receipt",
    "iso_now_ms",
    "js_length",
    "js_number",
    "js_string",
    "receipt_digest",
    "receipt_json",
]

RECEIPT_SCHEMA = "curation-atlas/1"
RECEIPT_CLAIM = (
    "Local public GitHub observation and deterministic derivation; "
    "not a GitHub attestation or third-party signature."
)
# Exactly what Date.prototype.toISOString produces for years 0000-9999.
_ISO_MS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", re.ASCII)
_SHORT_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}


class _Undefined:
    """Sentinel for a JavaScript ``undefined`` value."""

    _instance: "_Undefined | None" = None

    def __new__(cls) -> "_Undefined":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNDEFINED"

    def __bool__(self) -> bool:
        return False


UNDEFINED = _Undefined()


class ReceiptError(ValueError):
    """A receipt or comparison input was refused. ``code`` names the guard."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _code_units(value: str) -> list[int]:
    """The UTF-16 code units JavaScript would hold for ``value``."""
    data = value.encode("utf-16-be", "surrogatepass")
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)]


def js_length(value: str) -> int:
    """``String.prototype.length`` (UTF-16 code units)."""
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def js_number(value: float) -> str:
    """ECMAScript ``Number::toString(10)`` for a finite double."""
    if not math.isfinite(value):
        raise ValueError("js_number needs a finite double")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits_tuple = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(map(str, digits_tuple.digits))
    exponent = int(digits_tuple.exponent)
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    s = stripped.lstrip("0")
    k = len(s)
    n = k + exponent
    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    e = n - 1
    exp = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return sign + s + "e" + exp
    return sign + s[0] + "." + s[1:] + "e" + exp


def js_string(value: str) -> str:
    """ES2019 well-formed ``JSON.stringify`` of a string."""
    units = _code_units(value)
    out: list[str] = ['"']
    i = 0
    count = len(units)
    while i < count:
        unit = units[i]
        if 0xD800 <= unit <= 0xDBFF and i + 1 < count and 0xDC00 <= units[i + 1] <= 0xDFFF:
            out.append(chr(0x10000 + ((unit - 0xD800) << 10) + (units[i + 1] - 0xDC00)))
            i += 2
            continue
        if unit in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[unit])
        elif unit < 0x20 or 0xD800 <= unit <= 0xDFFF:
            out.append("\\u%04x" % unit)
        else:
            out.append(chr(unit))
        i += 1
    out.append('"')
    return "".join(out)


def canonicalize(value: Any) -> str:
    """Port of ``canonicalize`` in lib/audit.ts."""
    if value is None or value is UNDEFINED or callable(value):
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        try:
            value = float(value)
        except OverflowError:
            return "null"
    if isinstance(value, float):
        return js_number(value) if math.isfinite(value) else "null"
    if isinstance(value, str):
        return js_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = [key for key in value if value[key] is not UNDEFINED]
        for key in keys:
            if not isinstance(key, str):
                raise TypeError("canonical object keys must be strings")
        keys.sort(key=_code_units)
        if len({tuple(_code_units(key)) for key in keys}) != len(keys):
            raise TypeError("canonical object keys collide as UTF-16 strings")
        return "{" + ",".join(js_string(key) + ":" + canonicalize(value[key]) for key in keys) + "}"
    raise TypeError("unsupported canonical value: " + type(value).__name__)


def receipt_digest(canonical: str) -> str:
    """Lowercase hex SHA-256 of the UTF-8 bytes of a canonical string."""
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def iso_now_ms() -> str:
    """``new Date().toISOString()`` for the current UTC time."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (now.microsecond // 1000)


def create_receipt(audit: Any, generated_at: str | None = None) -> dict[str, Any]:
    """Port of ``createReceipt``. ``generated_at`` defaults to now, in toISOString form."""
    if generated_at is None:
        generated_at = iso_now_ms()
    if not isinstance(generated_at, str) or not _ISO_MS.fullmatch(generated_at):
        raise ReceiptError("invalid_generated_at", "generatedAt must be a toISOString UTC timestamp.")
    payload = {
        "receiptSchema": RECEIPT_SCHEMA,
        "generatedAt": generated_at,
        "claim": RECEIPT_CLAIM,
        "audit": audit,
    }
    return {**payload, "receiptSha256": receipt_digest(canonicalize(payload))}


def receipt_json(receipt: dict[str, Any]) -> str:
    """JSON text for a receipt that ``JSON.parse`` reads back to the same canonical form.

    It is the canonical form itself: valid JSON, deterministic, and free of the
    Python-only tokens (``NaN``, ``Infinity``, ``-0.0``) that ``json.dumps`` emits.
    """
    return canonicalize(receipt)
