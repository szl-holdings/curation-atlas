"""Stdlib port of lib/comparison.ts: receipt import, projection and comparison.

It follows the TypeScript step for step, with one deliberate difference: where
the TypeScript verifier is lenient, this port refuses the input. Every such
place is listed in ``FAIL_CLOSED_DIVERGENCES`` (decision P15-D5) and raises a
``ReceiptError`` whose ``code`` names the guard:

* ``mode`` or a policy ``state`` that is not a string (TS checks ``String(x)``,
  so ``["MEASURED"]`` passes there);
* an observation time without an explicit UTC offset (TS reads it as local
  time), an impossible calendar date such as 2026-02-30 (TS rolls it over),
  hour 24, a colon-less ``+0530`` offset, a lowercase ``z``, more than three
  fractional digits, or an instant outside years 0001-9999 UTC;
* a ``generatedAt`` that is not a strict timestamp, a ``claim`` other than the
  fixed receipt claim, or envelope keys other than the five receipt fields
  (TS never reads them);
* duplicate JSON object keys (``JSON.parse`` keeps the last one, so part of the
  file is outside the digest);
* an organization login or repository name that is not ASCII before
  lower-casing (TS lower-cases first, so U+212A KELVIN SIGN becomes ``k``);
* a repository whose ``error`` field is present but empty is never treated as
  pinned (TS tests ``!repository.error``).

A verified receipt proves only that its digest matches its contents. It is not
a signature or attestation.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from receipt import RECEIPT_CLAIM, RECEIPT_SCHEMA, ReceiptError, canonicalize, js_length, receipt_digest

__all__ = [
    "FAIL_CLOSED_DIVERGENCES",
    "MAX_RECEIPT_BYTES",
    "POLICY_DEFINITIONS",
    "ReceiptError",
    "compare_audits",
    "parse_timestamp",
    "project_comparison_audit",
    "verify_imported_receipt",
]

MAX_RECEIPT_BYTES = 2_000_000
MAX_DEPTH = 48
EVIDENCE_MODES = ("MEASURED", "SAMPLE", "BLOCKED", "UNAVAILABLE")
POLICY_STATES = ("LOCAL", "INHERITED", "ABSENT", "UNKNOWN")
ENVELOPE_KEYS = frozenset({"receiptSchema", "generatedAt", "claim", "audit", "receiptSha256"})

# Mirrors POLICY_DEFINITIONS in lib/audit.ts (weights are not used here).
POLICY_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {"key": "agent-instructions", "label": "Agent instructions", "inheritable": False,
     "candidates": ("AGENTS.md", ".github/copilot-instructions.md", "CLAUDE.md", "GEMINI.md")},
    {"key": "codeowners", "label": "Code ownership", "inheritable": False,
     "candidates": (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")},
    {"key": "security", "label": "Security policy", "inheritable": True,
     "candidates": (".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md")},
    {"key": "contributing", "label": "Contributing guide", "inheritable": True,
     "candidates": (".github/CONTRIBUTING.md", "CONTRIBUTING.md", "docs/CONTRIBUTING.md")},
    {"key": "code-of-conduct", "label": "Code of conduct", "inheritable": True,
     "candidates": (".github/CODE_OF_CONDUCT.md", "CODE_OF_CONDUCT.md", "docs/CODE_OF_CONDUCT.md")},
    {"key": "support", "label": "Support policy", "inheritable": True,
     "candidates": (".github/SUPPORT.md", "SUPPORT.md", "docs/SUPPORT.md")},
    {"key": "governance", "label": "Governance", "inheritable": False,
     "candidates": ("GOVERNANCE.md", ".github/GOVERNANCE.md", "docs/GOVERNANCE.md")},
    {"key": "license", "label": "License", "inheritable": False,
     "candidates": ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")},
    {"key": "dependabot", "label": "Dependency updates", "inheritable": False,
     "candidates": (".github/dependabot.yml", ".github/dependabot.yaml")},
    {"key": "workflows", "label": "Actions workflows", "inheritable": False,
     "candidates": (), "setPrefix": ".github/workflows/"},
)
_DEFINITIONS = {definition["key"]: definition for definition in POLICY_DEFINITIONS}

FAIL_CLOSED_DIVERGENCES: tuple[dict[str, str], ...] = (
    {"id": "D5-mode-array", "code": "invalid_mode",
     "ts": "accepts mode ['MEASURED'] because String(['MEASURED']) is 'MEASURED'", "python": "refuses"},
    {"id": "D5-state-array", "code": "invalid_state",
     "ts": "accepts policy state ['LOCAL'] the same way", "python": "refuses"},
    {"id": "D5-local-time", "code": "invalid_timestamp",
     "ts": "accepts observedAt without an offset and reads it in the viewer's time zone", "python": "refuses"},
    {"id": "D5-impossible-date", "code": "invalid_timestamp",
     "ts": "accepts 2026-02-30 (rolls over to 2026-03-02)", "python": "refuses"},
    {"id": "D5-hour-24", "code": "invalid_timestamp",
     "ts": "accepts T24:00:00Z as the next midnight", "python": "refuses"},
    {"id": "D5-no-seconds", "code": "invalid_timestamp",
     "ts": "accepts 2026-10-07T12:00 (local time, no seconds)", "python": "refuses"},
    {"id": "D5-compact-offset", "code": "invalid_timestamp",
     "ts": "accepts +0530 without a colon", "python": "refuses"},
    {"id": "D5-lowercase-z", "code": "invalid_timestamp",
     "ts": "accepts a lowercase z designator", "python": "refuses"},
    {"id": "D5-long-fraction", "code": "invalid_timestamp",
     "ts": "accepts more than three fractional digits and truncates them to milliseconds", "python": "refuses"},
    {"id": "D5-year-range", "code": "invalid_timestamp",
     "ts": "accepts year 0000 and instants that fall outside years 0001-9999 in UTC", "python": "refuses"},
    {"id": "D5-generated-at", "code": "invalid_generated_at",
     "ts": "never reads generatedAt (any value or none verifies)", "python": "refuses a non-timestamp"},
    {"id": "D5-claim", "code": "invalid_claim",
     "ts": "never reads claim (any text or none verifies)", "python": "refuses anything but the fixed claim"},
    {"id": "D5-extra-envelope-key", "code": "unknown_envelope_key",
     "ts": "accepts unknown envelope keys", "python": "refuses"},
    {"id": "D5-duplicate-key", "code": "duplicate_key",
     "ts": "JSON.parse keeps the last duplicate key, so earlier text is outside the digest", "python": "refuses"},
    {"id": "D5-non-ascii-login", "code": "invalid_org",
     "ts": "lower-cases before validating, so U+212A KELVIN SIGN passes as 'k'", "python": "refuses"},
    {"id": "D5-non-ascii-repo", "code": "invalid_repository",
     "ts": "same lower-casing for repository full names", "python": "refuses"},
    {"id": "D5-empty-error", "code": "compare",
     "ts": "treats error '' as no error, so the repository can count as pinned", "python": "never pinned"},
)

_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", re.ASCII)
_FULL_NAME = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", re.ASCII)
_HEX64 = re.compile(r"[a-f0-9]{64}", re.ASCII)
_HEX40 = re.compile(r"[a-fA-F0-9]{40}", re.ASCII)
_YAML = re.compile(r".*\.[yY][aA]?[mM][lL]", re.ASCII | re.DOTALL)
_TIMESTAMP = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|([+-])(\d{2}):(\d{2}))", re.ASCII
)
_GENERATED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", re.ASCII)


def _fail(code: str, message: str) -> ReceiptError:
    return ReceiptError(code, message)


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail("invalid_object", "The receipt contains an invalid object.")
    return value


def _text(value: Any, maximum: int = 500) -> str:
    if not isinstance(value, str) or js_length(value) > maximum:
        raise _fail("invalid_text", "The receipt contains an invalid or oversized field.")
    return value


def _nullable_text(value: Any, maximum: int = 500) -> str | None:
    return None if value is None else _text(value, maximum)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_integer(value: Any) -> bool:
    """``Number.isInteger``."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and value.is_integer()


def parse_timestamp(value: Any) -> datetime:
    """Strict RFC 3339 instant with an explicit offset, truncated to milliseconds like Date.parse."""
    if not isinstance(value, str) or js_length(value) > 40:
        raise _fail("invalid_timestamp", "The receipt has an invalid observation time.")
    match = _TIMESTAMP.fullmatch(value)
    if not match:
        raise _fail("invalid_timestamp", "The receipt has an invalid observation time.")
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    fraction = (match.group(7) or "").ljust(3, "0")
    if match.group(8) == "Z":
        offset = timedelta(0)
    else:
        offset_hours, offset_minutes = int(match.group(10)), int(match.group(11))
        if offset_hours > 23 or offset_minutes > 59:
            raise _fail("invalid_timestamp", "The receipt has an invalid observation time.")
        offset = timedelta(hours=offset_hours, minutes=offset_minutes)
        if match.group(9) == "-":
            offset = -offset
    try:
        parsed = datetime(year, month, day, hour, minute, second, int(fraction) * 1000, tzinfo=timezone(offset))
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise _fail("invalid_timestamp", "The receipt has an invalid observation time.") from exc


def _bounded_tree(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise _fail("too_deep", "The receipt nesting exceeds the supported limit.")
    if isinstance(value, dict):
        children = value.values()
    elif isinstance(value, list):
        children = value
    else:
        return
    for child in children:
        _bounded_tree(child, depth + 1)


def _ascii_lower(value: str, pattern: re.Pattern[str], code: str, message: str) -> str:
    if not value.isascii() or not pattern.fullmatch(value):
        raise _fail(code, message)
    return value.lower()


def project_comparison_audit(value: Any) -> dict[str, Any]:
    """Port of ``projectComparisonAudit``; refuses where the TS is lenient (see module docstring)."""
    audit = _object(value)
    schema_version = audit.get("schemaVersion")
    if not (_is_number(schema_version) and schema_version == 1) or audit.get("publicOnly") is not True:
        raise _fail("unsupported_audit", "Only public Curation Atlas v1 audits are supported.")
    mode = audit.get("mode")
    if not isinstance(mode, str) or mode not in EVIDENCE_MODES:
        raise _fail("invalid_mode", "The receipt has an unsupported evidence class.")
    org_login = _ascii_lower(_text(_object(audit.get("org")).get("login"), 39), _LOGIN,
                             "invalid_org", "The receipt has an invalid organization.")
    repositories_value = audit.get("repositories")
    if not isinstance(repositories_value, list) or len(repositories_value) > 1000:
        raise _fail("invalid_repositories", "The receipt has an invalid repository list.")
    seen: set[str] = set()
    repositories: list[dict[str, Any]] = []
    for item in repositories_value:
        repository = _object(item)
        full_name = _text(repository.get("fullName"), 150)
        if not full_name.isascii():
            raise _fail("invalid_repository", "A receipt repository does not belong to its organization.")
        full_name = full_name.lower()
        if not full_name.startswith(org_login + "/") or not _FULL_NAME.fullmatch(full_name):
            raise _fail("invalid_repository", "A receipt repository does not belong to its organization.")
        if full_name in seen:
            raise _fail("repeated_repository", "The receipt repeats a repository identity.")
        seen.add(full_name)
        if not isinstance(repository.get("treeComplete"), bool):
            raise _fail("missing_tree_coverage", "The receipt is missing its tree coverage state.")
        policies_value = repository.get("policies")
        if not isinstance(policies_value, list) or len(policies_value) != len(POLICY_DEFINITIONS):
            raise _fail("incomplete_policies", "The receipt has an incomplete policy schema.")
        policy_keys: set[str] = set()
        policies: list[dict[str, Any]] = []
        for policy_item in policies_value:
            policy = _object(policy_item)
            key = _text(policy.get("key"), 40)
            if key not in _DEFINITIONS or key in policy_keys:
                raise _fail("invalid_policy_key", "The receipt has an unknown or repeated policy key.")
            policy_keys.add(key)
            state = policy.get("state")
            if not isinstance(state, str) or state not in POLICY_STATES:
                raise _fail("invalid_state", "The receipt has an invalid policy state.")
            if "memberCount" in policy:
                member_count = policy["memberCount"]
                if not _is_integer(member_count) or member_count < 0:
                    raise _fail("invalid_member_count", "The receipt has an invalid file count.")
            source_repo = _nullable_text(policy.get("sourceRepo", _MISSING), 150)
            projected = {
                "key": key,
                "state": state,
                "path": _nullable_text(policy.get("path", _MISSING)),
                "sourceRepo": source_repo.lower() if source_repo is not None else None,
                "blobSha": _nullable_text(policy.get("blobSha", _MISSING), 1_500_000),
            }
            if key == "workflows" and "memberCount" in policy:
                projected["memberCount"] = policy["memberCount"]
            policies.append(projected)
        head_sha = _nullable_text(repository.get("headSha", _MISSING), 40)
        tree_sha = _nullable_text(repository.get("treeSha", _MISSING), 40)
        projected_repository: dict[str, Any] = {
            "fullName": full_name,
            "headSha": head_sha.lower() if head_sha is not None else None,
            "treeSha": tree_sha.lower() if tree_sha is not None else None,
            "treeComplete": repository["treeComplete"],
        }
        if "error" in repository:
            projected_repository["error"] = _text(repository["error"], 2000)
        projected_repository["policies"] = policies
        repositories.append(projected_repository)
    observed_at = audit.get("observedAt")
    parse_timestamp(observed_at)
    return {"mode": mode, "orgLogin": org_login, "observedAt": observed_at, "repositories": repositories}


class _Missing:
    pass


_MISSING = _Missing()  # a missing field is not JSON null: TS text(undefined) throws


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _fail("duplicate_key", "The receipt repeats a JSON object key.")
        result[key] = value
    return result


def _reject_constant(token: str) -> Any:
    raise _fail("invalid_json", "The receipt is not valid JSON.")


def _parse_int(token: str) -> int | float:
    # JSON.parse reads every number as a double; very long integer literals would
    # otherwise hit Python's int digit limit instead of becoming Infinity.
    return int(token) if len(token) <= 4000 else float(token)


def verify_imported_receipt(source: str | bytes) -> dict[str, Any]:
    """Port of ``verifyImportedReceipt``. Returns ``{"audit": projected, "receiptSha256": digest}``."""
    if isinstance(source, (bytes, bytearray)):
        try:
            source = bytes(source).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _fail("invalid_encoding", "The receipt is not UTF-8 text.") from exc
    if not isinstance(source, str):
        raise _fail("invalid_json", "The receipt is not valid JSON.")
    # TextEncoder length: pair surrogates first, then encode lone ones as U+FFFD (3 bytes).
    paired = source.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")
    if len(paired.encode("utf-8", "surrogatepass")) > MAX_RECEIPT_BYTES:
        raise _fail("too_large", "Choose a Curation Atlas JSON receipt smaller than 2 MB.")
    try:
        parsed = json.loads(source, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant,
                            parse_int=_parse_int)
    except ReceiptError:
        raise
    except (ValueError, RecursionError) as exc:
        raise _fail("invalid_json", "The receipt is not valid JSON.") from exc
    envelope = _object(parsed)
    _bounded_tree(envelope)
    if envelope.get("receiptSchema") != RECEIPT_SCHEMA:
        raise _fail("invalid_schema", "This file is not a Curation Atlas v1 receipt.")
    expected = _text(envelope.get("receiptSha256"), 64).lower()
    if not _HEX64.fullmatch(expected):
        raise _fail("invalid_digest", "The receipt digest is invalid.")
    payload = {key: value for key, value in envelope.items() if key != "receiptSha256"}
    actual = receipt_digest(canonicalize(payload))
    if actual != expected:
        raise _fail("digest_mismatch", "The receipt digest does not match its contents. No baseline was loaded.")
    unknown = set(envelope) - ENVELOPE_KEYS
    if unknown:
        raise _fail("unknown_envelope_key", "The receipt has fields outside the v1 envelope.")
    generated_at = envelope.get("generatedAt")
    if not isinstance(generated_at, str) or not _GENERATED_AT.fullmatch(generated_at):
        raise _fail("invalid_generated_at", "The receipt has an invalid generation time.")
    parse_timestamp(generated_at)
    if envelope.get("claim") != RECEIPT_CLAIM:
        raise _fail("invalid_claim", "The receipt claim is not the Curation Atlas v1 claim.")
    return {"audit": project_comparison_audit(envelope.get("audit")), "receiptSha256": actual}


def _pinned(repository: dict[str, Any]) -> bool:
    return (
        "error" not in repository
        and repository["treeComplete"] is True
        and bool(_HEX40.fullmatch(repository["headSha"] or ""))
        and bool(_HEX40.fullmatch(repository["treeSha"] or ""))
    )


def _comparable(audit: dict[str, Any], repository: dict[str, Any], policy: dict[str, Any]) -> bool:
    if audit["mode"] in ("SAMPLE", "UNAVAILABLE") or not _pinned(repository) or policy["state"] == "UNKNOWN":
        return False
    definition = _DEFINITIONS[policy["key"]]
    if policy["state"] == "ABSENT":
        return (policy["path"] is None and policy["blobSha"] is None and policy["sourceRepo"] is None
                and policy.get("memberCount", 0) == 0)
    if not policy["path"] or not policy["blobSha"]:
        return False
    set_prefix = definition.get("setPrefix")
    if set_prefix:
        if policy["path"] != set_prefix + "*" or not policy["blobSha"].startswith("set:"):
            return False
        members = policy["blobSha"][4:].split("|")
        if "memberCount" not in policy or len(members) != policy["memberCount"]:
            return False
        names: set[str] = set()
        for member in members:
            colon = member.rfind(":")
            if colon < 0:
                return False
            path = member[:colon]
            if (not path.startswith(set_prefix) or not _YAML.fullmatch(path)
                    or not _HEX40.fullmatch(member[colon + 1:]) or path in names):
                return False
            names.add(path)
    elif policy["path"] not in definition["candidates"] or not _HEX40.fullmatch(policy["blobSha"]):
        return False
    if policy["state"] == "INHERITED":
        origin = next((item for item in audit["repositories"] if item["fullName"] == policy["sourceRepo"]), None)
        origin_policy = None
        if origin is not None:
            origin_policy = next((item for item in origin["policies"] if item["key"] == policy["key"]), None)
        return bool(
            definition["inheritable"]
            and policy["sourceRepo"] == audit["orgLogin"] + "/.github"
            and origin is not None
            and _pinned(origin)
            and origin_policy is not None
            and origin_policy["state"] == "LOCAL"
            and origin_policy["path"] == policy["path"]
            and origin_policy["blobSha"] == policy["blobSha"]
            and origin_policy["sourceRepo"] is None
        )
    return policy["sourceRepo"] is None


def _fingerprint(policy: dict[str, Any]) -> str:
    view = {key: value for key, value in policy.items() if key != "memberCount"}
    if policy["state"] != "ABSENT" and "memberCount" in policy:
        view["memberCount"] = policy["memberCount"]
    return canonicalize(view)


def _check_projection(previous: Any) -> None:
    if (not isinstance(previous, dict) or not isinstance(previous.get("mode"), str)
            or previous["mode"] not in EVIDENCE_MODES or not isinstance(previous.get("orgLogin"), str)
            or not isinstance(previous.get("repositories"), list)):
        raise _fail("invalid_baseline", "The loaded baseline is not a projected Curation Atlas audit.")
    parse_timestamp(previous.get("observedAt"))


def compare_audits(previous: dict[str, Any], current_value: Any) -> dict[str, Any]:
    """Port of ``compareAudits``. ``previous`` is a projected audit (from verify or project)."""
    _check_projection(previous)
    current = project_comparison_audit(current_value)
    if previous["orgLogin"] != current["orgLogin"]:
        raise _fail("different_org", "Run an audit for the same organization as the loaded receipt.")
    if parse_timestamp(previous["observedAt"]) > parse_timestamp(current["observedAt"]):
        raise _fail("newer_baseline",
                    "The loaded receipt is newer than the displayed audit. Run a fresh scan before comparing.")
    before = {repository["fullName"]: repository for repository in previous["repositories"]}
    after = {repository["fullName"]: repository for repository in current["repositories"]}
    overlap = [repository for repository in current["repositories"] if repository["fullName"] in before]
    unbounded = ("SAMPLE", "UNAVAILABLE")
    deltas: list[dict[str, Any]] = []
    changed_revision_count = 0
    for repository in overlap:
        old = before[repository["fullName"]]
        if (previous["mode"] not in unbounded and current["mode"] not in unbounded and _pinned(old)
                and _pinned(repository) and old["headSha"] != repository["headSha"]):
            changed_revision_count += 1
        for definition in POLICY_DEFINITIONS:
            first = next(policy for policy in old["policies"] if policy["key"] == definition["key"])
            following = next(policy for policy in repository["policies"] if policy["key"] == definition["key"])
            change = "UNKNOWN"
            reason = "Both observations need full source bindings and known policy evidence."
            if _comparable(previous, old, first) and _comparable(current, repository, following):
                if first["state"] == "ABSENT" and following["state"] != "ABSENT":
                    change, reason = "ADDED", "An effective policy is present in the later complete observation."
                elif first["state"] != "ABSENT" and following["state"] == "ABSENT":
                    change, reason = "REMOVED", "The later complete observation records no effective policy."
                elif _fingerprint(first) == _fingerprint(following):
                    change, reason = "UNCHANGED", "The observed state, location, inheritance, and fingerprint match."
                else:
                    change = "CHANGED"
                    reason = ("The observed content or workflow-set fingerprint differs."
                              if first["blobSha"] != following["blobSha"]
                              else "The policy location or inheritance changed while the observed fingerprint matches.")
            deltas.append({"fullName": repository["fullName"], "key": definition["key"], "label": definition["label"],
                           "change": change, "before": first, "after": following, "reason": reason})
    return {
        "overlapCount": len(overlap),
        "changedRevisionCount": changed_revision_count,
        "enteredCohort": [repository["fullName"] for repository in current["repositories"]
                          if repository["fullName"] not in before],
        "leftCohort": [repository["fullName"] for repository in previous["repositories"]
                       if repository["fullName"] not in after],
        "deltas": deltas,
    }
