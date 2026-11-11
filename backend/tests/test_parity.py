"""TS/Python parity for the audit derivations shared by lib/audit.ts and backend/audit.py.

Node writes the vectors (tests/parity/generate.mts); each vector carries a synthetic input and the
output lib/audit.ts produced for it. This module recomputes every output with backend/audit.py.

Rules:
* Missing, unparsable, stale-schema or short (< 500 vectors) files fail. Nothing is skipped.
* A vector passes when Python equals TS exactly (bool is not a number; -0, NaN and infinities are
  tagged on the wire). Otherwise the mismatch must be *explained*: Python has to equal a pinned
  reference of its current semantics, and TS has to equal the same reference with one or more
  decision switches flipped to TS semantics (or, for scan_organization, after the decision's
  normalisation). An unexplained mismatch fails `test_<function>_parity`.
* Every explained mismatch names an open decision (P15-D1 ... ). Each decision has its own
  `@unittest.expectedFailure` test that asserts the decision has no divergent vectors. Today it
  fails, as expected. Once Stephen decides and one side is aligned, that test passes, which the
  runner reports as an unexpected success and the run fails until the registration, the switch in
  PY_SEMANTICS and the expectedFailure are removed together. A divergence is never passed silently.
"""
from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import math
import re
import sys
import unittest
from pathlib import Path
from typing import Any, Callable

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit  # noqa: E402

VECTOR_DIR = Path(__file__).resolve().parents[2] / "tests" / "parity" / "vectors"
SCHEMA = "curation-atlas.parity-vectors/v1"
MIN_VECTORS = 500
ORG = "szl-holdings"
FUNCTIONS = (
    "js_round", "score_repositories", "classify_agent", "match_policy_changes", "resolve_policies", "scan_organization",
)

# Open decisions (Stephen has not chosen the normative side). Text is the divergence, not a ruling.
DECISIONS = {
    "P15-D1": "Score rounding: TS rounds (a/b)*100 and adds (m/p)*w; Python rounds 100*a/b and adds w*m/p. "
              "js_round is floor(x+0.5), which differs from Math.round outside non-negative safe integers "
              "(-0, 0.49999999999999994, odd values above 2**52, NaN and infinities).",
    "P15-D2": "Sort order: TS sorts workflow-set members with localeCompare (ICU, default locale) and "
              "changedPaths by UTF-16 code unit; Python sorts by code point.",
    "P15-D3": "rate.resetAt format: TS Date.toISOString gives '...:SS.000Z', Python isoformat gives '...:SSZ'.",
    "P15-D4": "Regex flags and defaults: Python re.I folds Unicode (long s, dotless i) and uses Unicode \\b; "
              "Python '$' also matches before a final newline; Python 'or' / 'is None' versus TS '??' and "
              "truthiness (empty blobSha, empty login, missing commit fields, non-string filenames, empty org name).",
    "P15-D6": "Python's stricter source checks: it drops private and foreign inventory items and non-objects, "
              "pins the org login, and refuses a null default branch; TS keeps or audits them.",
    "P15-D7": "NEW (not in the 2026-10-28 list): malformed-source tolerance. Duplicate tree paths (TS first "
              "match wins and the workflow set keeps every copy; Python last copy wins) and x-ratelimit-* values "
              "that are not plain decimal integers (TS Number() or a thrown RangeError; Python int() or null).",
    "P15-D8": "NEW (not in the 2026-10-28 list): request-budget reservation order. TS inspects repositories two "
              "at a time and counts completions as they finish; Python inspects them one by one. When the "
              "remaining GitHub budget falls during a scan, the two withhold policy history for different "
              "repositories.",
}

# Which side's semantics backend/audit.py implements today, per decision switch. When a decision
# is taken and Python changes, flip the entry here and delete the decision's expectedFailure.
PY_SEMANTICS = {"P15-D1": "python", "P15-D2": "python", "P15-D4": "python", "P15-D7": "python"}

_LOADED: dict[str, dict[str, Any]] = {}
_RESULTS: dict[str, list[dict[str, Any]]] = {}


# --------------------------------------------------------------------------------------------
# Loading (fail closed)

def load(name: str) -> dict[str, Any]:
    if name in _LOADED:
        return _LOADED[name]
    path = VECTOR_DIR / f"{name}.json"
    if not path.is_file():
        raise AssertionError(f"missing parity vectors {path}; run node --experimental-strip-types tests/parity/generate.mts")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise AssertionError(f"unreadable parity vectors {path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") != SCHEMA or document.get("function") != name:
        raise AssertionError(f"{path} is not a {SCHEMA} file for {name}")
    vectors = document.get("vectors")
    if not isinstance(vectors, list) or document.get("count") != len(vectors):
        raise AssertionError(f"{path}: count does not match the vector list")
    if len(vectors) < MIN_VECTORS:
        raise AssertionError(f"{path}: {len(vectors)} vectors, need at least {MIN_VECTORS}")
    ids = set()
    for vector in vectors:
        if not isinstance(vector, dict) or set(vector) != {"id", "stratum", "input", "ts"}:
            raise AssertionError(f"{path}: malformed vector {str(vector)[:80]}")
        if vector["id"] in ids:
            raise AssertionError(f"{path}: duplicate vector id {vector['id']}")
        ids.add(vector["id"])
    _LOADED[name] = document
    return document


# --------------------------------------------------------------------------------------------
# Wire form and strict equality

def unwire(value: Any) -> Any:
    if isinstance(value, list):
        return [unwire(item) for item in value]
    if isinstance(value, dict):
        if set(value) == {"$float"}:
            return {"nan": math.nan, "inf": math.inf, "-inf": -math.inf, "-0": -0.0}[value["$float"]]
        return {key: unwire(item) for key, item in value.items()}
    return value


def wire(value: Any) -> Any:
    if isinstance(value, float):
        if math.isnan(value):
            return {"$float": "nan"}
        if math.isinf(value):
            return {"$float": "inf" if value > 0 else "-inf"}
        if value == 0 and math.copysign(1.0, value) < 0:
            return {"$float": "-0"}
        return value
    if isinstance(value, (list, tuple)):
        return [wire(item) for item in value]
    if isinstance(value, dict):
        return {key: wire(item) for key, item in value.items()}
    return value


def capture(run: Callable[[], Any]) -> Any:
    try:
        return wire(run())
    except Exception as exc:  # noqa: BLE001 - a thrown error is an observable outcome
        return {"$error": type(exc).__name__}


def is_error(value: Any) -> bool:
    return isinstance(value, dict) and set(value) == {"$error"}


def same(a: Any, b: Any) -> bool:
    """Exact equality on the wire form: both-error agrees, bool is never a number."""
    if is_error(a) or is_error(b):
        return is_error(a) and is_error(b)
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) or isinstance(b, (int, float)):
        return isinstance(a, (int, float)) and isinstance(b, (int, float)) and a == b
    if isinstance(a, list) or isinstance(b, list):
        return isinstance(a, list) and isinstance(b, list) and len(a) == len(b) and all(map(same, a, b))
    if isinstance(a, dict) or isinstance(b, dict):
        return isinstance(a, dict) and isinstance(b, dict) and a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


# --------------------------------------------------------------------------------------------
# Pinned references. ts=False reproduces backend/audit.py today; ts=True reproduces lib/audit.ts.

def js_math_round(x: float) -> float | int:
    """ECMAScript Math.round, exactly, on doubles."""
    if math.isnan(x) or math.isinf(x):
        return x
    floor = math.floor(x)
    result = floor + 1 if x - floor >= 0.5 else floor
    if result == 0 and (x < 0 or math.copysign(1.0, x) < 0):
        return -0.0
    return result


def round_ref(x: float, ts: bool) -> Any:
    return js_math_round(x) if ts else math.floor(x + 0.5)


def score_ref(repositories: list[dict[str, Any]], order_ts: bool, truth_ts: bool) -> dict[str, Any]:
    def fingerprint(policy: dict[str, Any]) -> Any:
        if policy["state"] == "ABSENT":
            return "MISSING"
        if policy["state"] == "UNKNOWN":
            return None
        return policy["blobSha"]

    def present(value: Any) -> bool:
        return bool(value) if truth_ts else value is not None

    def rnd(x: float) -> Any:
        return js_math_round(x) if order_ts else math.floor(x + 0.5)

    def ratio(part: float, whole: float) -> float:
        return (part / whole) * 100 if order_ts else 100 * part / whole

    rows = []
    for repository in repositories:
        observed = comparable = agreement = applicable = 0.0
        for policy in repository["policies"]:
            weight = policy["weight"]
            applicable += weight
            value = fingerprint(policy)
            if not present(value):
                continue
            observed += weight
            peers = [fingerprint(next(item for item in other["policies"] if item["key"] == policy["key"]))
                     for other in repositories if other is not repository]
            peers = [peer for peer in peers if present(peer)]
            if peers:
                comparable += weight
                matches = peers.count(value)
                agreement += (matches / len(peers)) * weight if order_ts else weight * matches / len(peers)
        rows.append([rnd(ratio(observed, applicable)) if applicable else 0,
                     rnd(ratio(agreement, comparable)) if comparable else None])
    numerator = denominator = 0.0
    for definition in audit.POLICIES:
        counts: dict[Any, int] = {}
        for repository in repositories:
            value = fingerprint(next(item for item in repository["policies"] if item["key"] == definition["key"]))
            if present(value):
                counts[value] = counts.get(value, 0) + 1
        n = sum(counts.values())
        if n >= 2:
            pairs = sum(count * (count - 1) for count in counts.values())
            numerator += (pairs / (n * (n - 1))) * definition["weight"] if order_ts else definition["weight"] * pairs / (n * (n - 1))
            denominator += definition["weight"]
    total = len(repositories) * sum(definition["weight"] for definition in audit.POLICIES)
    observed_all = sum(policy["weight"] for repository in repositories for policy in repository["policies"]
                       if present(fingerprint(policy)))
    return {"repos": rows, "scores": {
        "alignment": None,
        "consistency": rnd(ratio(numerator, denominator)) if denominator else None,
        "evidenceCoverage": rnd(ratio(observed_all, total)) if total else 0,
    }}


PY_AGENT = audit.AGENT_DECLARATION
# JS /i without the u flag never folds a non-ASCII character onto an ASCII one, and its \b is
# ASCII-only: re.ASCII gives exactly that for this pattern ([^\n]* makes \s irrelevant).
TS_AGENT = re.compile(PY_AGENT.pattern, re.IGNORECASE | re.ASCII)
JS_TYPE_ERROR = TypeError


def js_string(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value) if isinstance(value, float) and not value.is_integer() else str(int(value))
    if isinstance(value, str):
        return value
    raise ValueError("unsupported coercion")


def classify_ref(item: dict[str, Any], repository: str, regex_ts: bool, defaults_ts: bool) -> Any:
    pattern = TS_AGENT if regex_ts else PY_AGENT
    if not defaults_ts:
        commit = item.get("commit") or {}
        message = commit.get("message") or ""
        author = item.get("author") or {}
        committer = item.get("committer") or {}
        declared = bool(pattern.search(message))
        automation = author.get("type") == "Bot" or committer.get("type") == "Bot"
        if not declared and not automation:
            return None
        return {
            "classification": "AGENT_ASSISTANCE_DECLARED" if declared else "AUTOMATION_ACTOR_OBSERVED",
            "repository": repository, "path": "", "commitSha": item.get("sha", ""),
            "message": message.split("\n", 1)[0] or "Policy change",
            "actor": author.get("login") or committer.get("login") or "unidentified actor",
            "verified": (commit.get("verification") or {}).get("verified"),
            "url": item.get("html_url", ""),
            "evidence": audit_evidence(declared),
        }
    commit = item.get("commit")
    if not isinstance(commit, dict):
        raise JS_TYPE_ERROR("Cannot read properties of null")
    message = commit.get("message")
    if message is None:
        message = ""
    declared = bool(pattern.search(js_string(message)))
    author, committer = item.get("author"), item.get("committer")
    automation = (isinstance(author, dict) and author.get("type") == "Bot") or (
        isinstance(committer, dict) and committer.get("type") == "Bot")
    if not declared and not automation:
        return None
    actor = author.get("login") if isinstance(author, dict) else None
    if actor is None:
        actor = committer.get("login") if isinstance(committer, dict) else None
    if actor is None:
        actor = "unidentified actor"
    if not isinstance(message, str):
        raise JS_TYPE_ERROR("message.split is not a function")
    verification = commit.get("verification")
    verified = verification.get("verified") if isinstance(verification, dict) else None
    signal = {
        "classification": "AGENT_ASSISTANCE_DECLARED" if declared else "AUTOMATION_ACTOR_OBSERVED",
        "repository": repository, "path": "", "message": message.split("\n")[0] or "Policy change",
        "actor": actor, "verified": verified, "evidence": audit_evidence(declared),
    }
    for source, target in (("sha", "commitSha"), ("html_url", "url")):
        if source in item:
            signal[target] = item[source]
    return signal


def audit_evidence(declared: bool) -> str:
    if declared:
        return "The commit message declares agent assistance. This declaration is not independent verification."
    return "GitHub attributes the action to a Bot/App identity. That does not prove an AI system wrote every changed byte."


def js_truthy(value: Any) -> bool:
    return not (value is None or value is False or value == "" or (isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0))


def yaml_pattern(regex_ts: bool) -> re.Pattern[str]:
    return re.compile(r"\.ya?ml\Z" if regex_ts else r"\.ya?ml$", re.IGNORECASE)


def utf16_key(text: str) -> bytes:
    return text.encode("utf-16-be", "surrogatepass")


def match_ref(files: list[Any], sort_ts: bool, regex_ts: bool, types_ts: bool) -> dict[str, Any]:
    yaml = yaml_pattern(regex_ts)
    paths: set[str] = set()
    keys: set[str] = set()
    for file in files:
        for path in (file.get("filename"), file.get("previous_filename")):
            if types_ts:
                if not js_truthy(path):
                    continue
            elif not isinstance(path, str):
                continue
            for definition in audit.POLICIES:
                prefix = definition.get("setPrefix")
                hit = isinstance(path, str) and path in definition["candidates"]
                if not hit and prefix:
                    if not isinstance(path, str):
                        raise JS_TYPE_ERROR("path.startsWith is not a function")
                    hit = path.startswith(prefix) and bool(yaml.search(path))
                if hit:
                    paths.add(path)
                    keys.add(definition["key"])
    key = utf16_key if sort_ts else None
    return {"changedPaths": sorted(paths, key=key), "policyKeys": sorted(keys, key=key)}


def expand_entries(entries: list[list[str]] | None) -> list[dict[str, Any]] | None:
    if entries is None:
        return None
    return [{"path": path, "type": kind, "sha": sha, "mode": "100644", "url": ""} for path, kind, sha in entries]


def policy_rows(policies: list[dict[str, Any]]) -> list[list[Any]]:
    rows = []
    for policy in policies:
        row = [policy["key"], policy["state"], policy["path"], policy["blobSha"], policy["sourceRepo"]]
        if "memberCount" in policy:
            row.append(policy["memberCount"])
        rows.append(row)
    return rows


def resolve_ref(entries, complete, defaults, default_complete, dupes_ts: bool, regex_ts: bool) -> list[list[Any]]:
    yaml = yaml_pattern(regex_ts)
    default_repo = f"{ORG}/.github"
    blob_list = [entry for entry in entries if entry.get("type") == "blob"]
    default_list = [entry for entry in defaults or [] if entry.get("type") == "blob"]
    if dupes_ts:
        def find(source, path):
            return next((entry for entry in source if entry.get("path") == path), None)
        members_source = blob_list
    else:
        blob_map = {entry.get("path"): entry for entry in blob_list}
        default_map = {entry.get("path"): entry for entry in default_list}

        def find(source, path):
            return (blob_map if source is blob_list else default_map).get(path)
        members_source = list(blob_map.values())
    out = []
    for definition in audit.POLICIES:
        prefix = definition.get("setPrefix")
        if prefix:
            members = sorted((entry for entry in members_source
                              if isinstance(entry.get("path"), str) and entry["path"].startswith(prefix)
                              and yaml.search(entry["path"])), key=lambda entry: entry["path"])
            if members:
                out.append(audit.policy_observation(definition, "LOCAL", {
                    "path": f"{prefix}*",
                    "sha": "set:" + "|".join(f"{entry['path']}:{entry['sha']}" for entry in members),
                }, member_count=len(members)))
            else:
                out.append(audit.policy_observation(definition, "ABSENT" if complete else "UNKNOWN", member_count=0))
            continue
        local = next((hit for path in definition["candidates"] if (hit := find(blob_list, path)) is not None), None)
        if local is not None:
            out.append(audit.policy_observation(definition, "LOCAL", local))
        elif not complete:
            out.append(audit.policy_observation(definition, "UNKNOWN"))
        elif definition["inheritable"] and defaults is not None:
            inherited = next((hit for path in definition["candidates"] if (hit := find(default_list, path)) is not None), None)
            if inherited is not None:
                out.append(audit.policy_observation(definition, "INHERITED", inherited, default_repo))
            elif not default_complete:
                out.append(audit.policy_observation(definition, "UNKNOWN", source_repo=default_repo))
            else:
                out.append(audit.policy_observation(definition, "ABSENT"))
        else:
            out.append(audit.policy_observation(definition, "ABSENT"))
    return policy_rows(out)


def sort_set_members(rows: Any, blob_index: int) -> Any:
    """D2 normalisation: order workflow-set members by code point on both sides."""
    if not isinstance(rows, list):
        return rows
    out = []
    for row in rows:
        if isinstance(row, list) and len(row) > blob_index and isinstance(row[blob_index], str) and row[blob_index].startswith("set:"):
            row = list(row)
            row[blob_index] = "set:" + "|".join(sorted(row[blob_index][4:].split("|")))
        out.append(row)
    return out


# --------------------------------------------------------------------------------------------
# Explanation search shared by the unit-level functions

Switch = tuple[str, str]  # (decision, aspect)


def explain(ts_out: Any, py_out: Any, py_ref: Any, ts_ref: Callable[[frozenset[Switch]], Any],
            switches: tuple[Switch, ...], normalise: dict[Switch, Callable[[Any], Any]] | None = None) -> tuple[str, ...] | None:
    """() when equal; the decisions that explain the mismatch; None when nothing explains it."""
    if same(ts_out, py_out):
        return ()
    if not same(py_out, py_ref):
        return None
    normalise = normalise or {}
    for size in range(1, len(switches) + 1):
        for subset in itertools.combinations(switches, size):
            chosen = frozenset(subset)
            candidate, expected = ts_ref(chosen), ts_out
            for switch in subset:
                if switch in normalise:
                    candidate, expected = normalise[switch](candidate), normalise[switch](expected)
            if same(candidate, expected):
                return tuple(sorted({decision for decision, _ in subset}))
    return None


def on(switches: frozenset[Switch], decision: str, aspect: str) -> bool:
    """True when this switch is flipped to TS semantics (or Python already uses TS semantics)."""
    return (decision, aspect) in switches or PY_SEMANTICS.get(decision) == "ts"


# --------------------------------------------------------------------------------------------
# Runners: one record per vector {id, stratum, ts, py, decisions}

def run_js_round(vector):
    x = unwire(vector["input"])
    py = capture(lambda: audit.js_round(x))
    ref = capture(lambda: round_ref(x, PY_SEMANTICS["P15-D1"] == "ts"))
    sw = (("P15-D1", "round"),)
    return explain(vector["ts"], py, ref, lambda s: capture(lambda: round_ref(x, on(s, "P15-D1", "round"))), sw), py


STATE = {"L": "LOCAL", "I": "INHERITED", "A": "ABSENT", "U": "UNKNOWN"}


def expand_repos(spec: dict[str, Any]) -> list[dict[str, Any]]:
    repos = []
    for index, row in enumerate(spec["repos"]):
        policies = []
        for definition, (letter, blob_sha) in zip(audit.POLICIES, row):
            policies.append({
                "key": definition["key"], "label": definition["label"], "weight": definition["weight"],
                "state": STATE[letter], "path": "p" if letter in "LI" else None, "blobSha": blob_sha,
                "sourceRepo": f"{ORG}/.github" if letter == "I" else None,
            })
        if spec["perm"] is not None:
            policies = [policies[k] for k in spec["perm"]]
        repos.append({"name": f"r{index}", "fullName": f"{ORG}/r{index}", "policies": policies,
                      "consistency": None, "evidenceCoverage": 0, "agentSignals": []})
    return repos


def run_score(vector):
    spec = vector["input"]

    def shipped():
        repos = expand_repos(spec)
        scores = audit.score_repositories(repos)
        return {"repos": [[repo["evidenceCoverage"], repo["consistency"]] for repo in repos], "scores": scores}

    py = capture(shipped)
    sw = (("P15-D1", "order"), ("P15-D4", "truthiness"))

    def ref(s):
        return capture(lambda: score_ref(expand_repos(spec), on(s, "P15-D1", "order"), on(s, "P15-D4", "truthiness")))
    return explain(vector["ts"], py, ref(frozenset()), ref, sw), py


def run_classify(vector):
    item, repository = vector["input"]["item"], vector["input"]["repository"]
    py = capture(lambda: audit.classify_agent(item, repository))
    sw = (("P15-D4", "regex"), ("P15-D4", "defaults"))

    def ref(s):
        return capture(lambda: classify_ref(item, repository, on(s, "P15-D4", "regex"), on(s, "P15-D4", "defaults")))
    return explain(vector["ts"], py, ref(frozenset()), ref, sw), py


def run_match(vector):
    files = vector["input"]["files"]

    def shipped():
        paths, keys = audit.match_policy_changes(files)
        return {"changedPaths": paths, "policyKeys": keys}

    py = capture(shipped)
    sw = (("P15-D2", "utf16"), ("P15-D4", "regex"), ("P15-D4", "types"))

    def ref(s):
        return capture(lambda: match_ref(files, on(s, "P15-D2", "utf16"), on(s, "P15-D4", "regex"), on(s, "P15-D4", "types")))
    return explain(vector["ts"], py, ref(frozenset()), ref, sw), py


def run_resolve(vector):
    spec = vector["input"]
    entries, defaults = expand_entries(spec["entries"]), expand_entries(spec["defaults"])

    def shipped():
        return policy_rows(audit.resolve_policies(entries, spec["complete"], defaults, spec["defaultComplete"], f"{ORG}/.github"))

    py = capture(shipped)
    sw = (("P15-D2", "locale"), ("P15-D4", "regex"), ("P15-D7", "duplicates"))

    def ref(s):
        return capture(lambda: resolve_ref(entries, spec["complete"], defaults, spec["defaultComplete"],
                                           on(s, "P15-D7", "duplicates"), on(s, "P15-D4", "regex")))
    norm = {("P15-D2", "locale"): lambda rows: sort_set_members(rows, 3)}
    return explain(vector["ts"], py, ref(frozenset()), ref, sw, norm), py


# scan_organization: mocked GitHub from the compact spec, compact projection, then normalisations.
REPO_DEFAULTS = {"branch": "main", "archived": False, "disabled": False, "fork": False, "private": False, "protected": False,
                 "truncated": False, "entries": [], "community": None, "rules": None, "commits": [], "branchStatus": 200}
SCAN_FULLNAME, SCAN_EVIDENCE, SCAN_CONSISTENCY, SCAN_POLICIES = 0, 9, 10, 12
# Perturbations whose residual difference is a registered decision (measured; see REPORT.md).
SCAN_PERTURBATION_DECISIONS = {
    "reset_nan": "P15-D7", "reset_fraction": "P15-D7", "reset_year_10000": "P15-D7", "limit_zero": "P15-D7",
    "limit_underscore": "P15-D7", "remaining_word": "P15-D7", "remaining_fraction": "P15-D7",
    "private_repo": "P15-D6", "foreign_repo": "P15-D6", "login_case": "P15-D6", "default_branch_null": "P15-D6",
    "non_object_inventory_item": "P15-D6", "org_name_empty": "P15-D4", "budget_decrement": "P15-D8",
}


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def scan_route(scan: dict[str, Any], path: str, page: int) -> tuple[int, Any]:
    not_found = (404, {"message": "Not Found"})
    lower = path.lower()
    if lower == f"/orgs/{ORG}":
        org = scan["org"]
        if org["status"] != 200:
            return org["status"], {"message": "synthetic org failure"}
        return 200, {"login": org["login"], "name": org["name"], "description": None,
                     "html_url": f"https://github.com/{ORG}", "public_repos": len(scan["repos"])}
    if lower == f"/orgs/{ORG}/repos":
        body = []
        for item in scan["repos"][(page - 1) * 100: page * 100]:
            spec = {**REPO_DEFAULTS, **item}
            body.append(spec["raw"] if "raw" in spec else {
                "name": spec["name"], "full_name": spec["full_name"], "description": None, "default_branch": spec["branch"],
                "archived": spec["archived"], "disabled": spec["disabled"], "fork": spec["fork"], "private": spec["private"],
                "language": None, "updated_at": "2026-11-01T00:00:00Z", "html_url": f"https://github.com/{spec['full_name']}",
            })
        return 200, body
    match = re.match(r"^/repos/([^/]+/[^/]+)/(.+)$", path)
    if not match:
        return not_found
    found = next((item for item in scan["repos"] if "raw" not in item and item["full_name"] == match.group(1)), None)
    if found is None:
        return not_found
    spec = {**REPO_DEFAULTS, **found}
    rest = match.group(2)
    head = spec.get("head") or sha1(f"{spec['full_name']}/head")
    tree = sha1(f"{spec['full_name']}/tree")

    def commit_sha(index: int) -> str:
        return sha1(f"{spec['full_name']}/commit/{index}")

    if rest.startswith("branches/"):
        if spec["branchStatus"] != 200:
            return spec["branchStatus"], {"message": "synthetic branch failure"}
        return 200, {"name": spec["branch"], "protected": spec["protected"], "commit": {"sha": head, "commit": {"tree": {"sha": tree}}}}
    if rest.startswith("git/trees/"):
        body = {"sha": spec.get("treeReply") or tree,
                "tree": [{"path": p, "mode": "100644", "type": "blob", "sha": s, "url": ""} for p, s in spec["entries"]]}
        if spec["truncated"] is not None:
            body["truncated"] = spec["truncated"]
        return 200, body
    if rest == "community/profile":
        return not_found if spec["community"] is None else (200, {"health_percentage": spec["community"]})
    if rest.startswith("rules/branches/"):
        return not_found if spec["rules"] is None else (200, [{"type": "deletion"} for _ in range(spec["rules"])])
    if rest == "commits":
        if isinstance(spec["commits"], int):
            return spec["commits"], {"message": "synthetic history failure"}
        body = []
        for index, commit in enumerate(spec["commits"]):
            sha = commit_sha(index)
            person = {"login": "dependabot[bot]", "type": "Bot"} if commit["bot"] else {"login": "dev", "type": "User"}
            body.append({"sha": sha, "html_url": f"https://github.com/{spec['full_name']}/commit/{sha}", "author": person,
                         "committer": person, "commit": {"message": commit["message"], "verification": {"verified": True}}})
        return 200, body
    if rest.startswith("commits/") and isinstance(spec["commits"], list):
        wanted = rest[len("commits/"):]
        index = next((k for k in range(len(spec["commits"])) if commit_sha(k) == wanted), None)
        if index is None:
            return not_found
        commit = spec["commits"][index]
        if commit.get("detail") and commit["detail"] != 200:
            return commit["detail"], {"message": "synthetic detail failure"}
        files = ([{"filename": f"src/f{k}.ts"} for k in range(100)] if commit.get("files100")
                 else [{"filename": name} for name in commit["files"]])
        return 200, {"sha": commit.get("detailSha") or commit_sha(index), "files": files}
    return not_found


def short(sha: Any) -> Any:
    return sha[:12] if isinstance(sha, str) else sha


def policy_cell(policy: dict[str, Any]) -> Any:
    if policy["path"] is None and policy["blobSha"] is None and policy["sourceRepo"] is None:
        return f"{policy['state']}{policy.get('memberCount', '')}"
    return [policy["state"], policy["path"], policy["blobSha"], policy["sourceRepo"], policy.get("memberCount")]


def scan_project(result: dict[str, Any]) -> Any:
    def history(repo):
        h = repo.get("policyHistory")
        if h is None:
            return None
        return [h["status"], h["commitsExamined"], h["attributedCandidates"], h["detailsExamined"],
                h["unexaminedCandidates"], h["fileListsTruncated"], "error" in h]

    return wire({
        "mode": result["mode"],
        "org": [result["org"]["login"], result["org"]["name"], result["org"]["publicRepos"]],
        "inventory": [result["inventory"][k] for k in ("publicRepos", "active", "archived", "forks")],
        "sampleSize": result["sampleSize"],
        "publicInventory": [[i["fullName"], i["archived"], i["fork"], i["disabled"]] for i in result["publicInventory"]]
        if result.get("publicInventory") is not None else None,
        "scores": [result["scores"]["alignment"], result["scores"]["consistency"], result["scores"]["evidenceCoverage"]],
        "rate": [result["rate"]["limit"], result["rate"]["remaining"], result["rate"]["resetAt"]],
        "sourceUrls": result["sourceUrls"],
        "limitationsCount": len(result["limitations"]),
        "repositories": [[
            repo["fullName"], repo["defaultBranch"], short(repo["headSha"]), short(repo["treeSha"]), repo["treeComplete"],
            repo["protected"], repo["communityHealth"], repo["rulesCount"], repo["workflowCount"], repo["evidenceCoverage"],
            repo["consistency"], "error" in repo, [policy_cell(policy) for policy in repo["policies"]],
            [[s["classification"], short(s["commitSha"]), s["path"], s.get("changedPaths"), s.get("policyKeys"), s["actor"],
              s["verified"], s.get("sourceHeadSha") == repo["headSha"]] for s in repo["agentSignals"]],
            history(repo),
        ] for repo in result["repositories"]],
    })


async def scan_python(scan: dict[str, Any]) -> Any:
    served = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal served
        status, body = scan_route(scan, request.url.path, int(request.url.params.get("page", "1")))
        headers = {**scan["headers"], "content-type": "application/json"}
        if scan.get("decrement"):
            headers["x-ratelimit-remaining"] = str(int(headers["x-ratelimit-remaining"]) - served)
        served += 1
        return httpx.Response(status, content=json.dumps(body).encode(), headers=headers)

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            return scan_project(await audit.scan_organization(audit.GitHubReader(client), scan["sample"]))
    except Exception as exc:  # noqa: BLE001
        return {"$error": type(exc).__name__}


def cell_policy(cell: Any, definition: dict[str, Any]) -> dict[str, Any]:
    if isinstance(cell, str):
        state = re.match(r"[A-Z]+", cell).group(0)
        blob = None
    else:
        state, blob = cell[0], cell[2]
    return {"key": definition["key"], "weight": definition["weight"], "state": state, "blobSha": blob}


def rescore(out: Any, order_ts: bool, truth_ts: bool) -> Any:
    repos = [{"policies": [cell_policy(c, d) for c, d in zip(row[SCAN_POLICIES], audit.POLICIES)]} for row in out["repositories"]]
    return score_ref(repos, order_ts, truth_ts)


def scan_norm_d1(out: Any, own_ts: bool) -> Any:
    """Replace every score with the TS-order recomputation, after checking the side's own scores."""
    if is_error(out):
        return out
    own = rescore(out, own_ts, own_ts)
    current = {"repos": [[row[SCAN_EVIDENCE], row[SCAN_CONSISTENCY]] for row in out["repositories"]],
               "scores": dict(zip(("alignment", "consistency", "evidenceCoverage"), out["scores"]))}
    if not same(wire(own), current):
        return {"$unexplained": "scores do not follow this side's own semantics"}
    target = wire(rescore(out, True, True))
    out = json.loads(json.dumps(out))
    for row, (evidence, consistency) in zip(out["repositories"], target["repos"]):
        row[SCAN_EVIDENCE], row[SCAN_CONSISTENCY] = evidence, consistency
    out["scores"] = [target["scores"]["alignment"], target["scores"]["consistency"], target["scores"]["evidenceCoverage"]]
    return out


def scan_norm_d2(out: Any) -> Any:
    if is_error(out):
        return out
    out = json.loads(json.dumps(out))
    for row in out["repositories"]:
        row[SCAN_POLICIES] = sort_set_members(row[SCAN_POLICIES], 2)
    return out


def scan_norm_d3(out: Any) -> Any:
    if is_error(out) or not isinstance(out["rate"][2], str):
        return out
    out = json.loads(json.dumps(out))
    out["rate"][2] = re.sub(r"\.000Z$", "Z", out["rate"][2])
    return out


def run_scan_all(vectors: list[dict[str, Any]]) -> list[tuple[Any, Any, bool]]:
    async def all_scans():
        return [await scan_python(vector["input"]) for vector in vectors]

    outputs = asyncio.run(all_scans())
    results = []
    for vector, py in zip(vectors, outputs):
        ts = vector["ts"]
        decisions: tuple[str, ...] | None = None
        if same(ts, py):
            decisions = ()
        else:
            steps = {"P15-D3": (scan_norm_d3, scan_norm_d3), "P15-D2": (scan_norm_d2, scan_norm_d2),
                     "P15-D1": (lambda o: scan_norm_d1(o, True), lambda o: scan_norm_d1(o, PY_SEMANTICS["P15-D1"] == "ts"))}
            for size in range(1, 4):
                for subset in itertools.combinations(("P15-D3", "P15-D2", "P15-D1"), size):
                    a, b = ts, py
                    for name in subset:
                        a, b = steps[name][0](a), steps[name][1](b)
                    if same(a, b):
                        decisions = tuple(sorted(subset))
                        break
                if decisions is not None:
                    break
        perturbation = vector["input"].get("perturbation")
        via_tag = decisions is None and perturbation in SCAN_PERTURBATION_DECISIONS
        if via_tag:
            decisions = (SCAN_PERTURBATION_DECISIONS[perturbation],)
        results.append((decisions, py, via_tag))
    return results


RUNNERS = {
    "js_round": run_js_round, "score_repositories": run_score, "classify_agent": run_classify,
    "match_policy_changes": run_match, "resolve_policies": run_resolve,
}


def results(name: str) -> list[dict[str, Any]]:
    if name in _RESULTS:
        return _RESULTS[name]
    vectors = load(name)["vectors"]
    if name == "scan_organization":
        triples = run_scan_all(vectors)
    else:
        triples = [(*RUNNERS[name](vector), False) for vector in vectors]
    records = []
    for vector, (decisions, py, via_tag) in zip(vectors, triples):
        if decisions is not None and any(decision not in DECISIONS for decision in decisions):
            decisions = None  # an unregistered decision explains nothing
        records.append({"id": vector["id"], "stratum": vector["stratum"], "ts": vector["ts"], "py": py,
                        "decisions": decisions, "via_tag": via_tag,
                        "perturbation": vector["input"].get("perturbation") if isinstance(vector["input"], dict) else None})
    _RESULTS[name] = records
    return records


def summary() -> dict[str, Any]:
    """Counts used by the PR report: per function, matches, explained (by decision) and unexplained."""
    out: dict[str, Any] = {}
    for name in FUNCTIONS:
        records = results(name)
        by_decision: dict[str, int] = {}
        by_stratum: dict[str, dict[str, int]] = {}
        for record in records:
            stratum = by_stratum.setdefault(record["stratum"], {"n": 0, "equal": 0, "explained": 0, "unexplained": 0})
            stratum["n"] += 1
            if record["decisions"] == ():
                stratum["equal"] += 1
            elif record["decisions"] is None:
                stratum["unexplained"] += 1
            else:
                stratum["explained"] += 1
                for decision in record["decisions"]:
                    by_decision[decision] = by_decision.get(decision, 0) + 1
        out[name] = {"vectors": len(records), "by_decision": by_decision, "by_stratum": by_stratum,
                     "unexplained_ids": [r["id"] for r in records if r["decisions"] is None][:20]}
    return out


# --------------------------------------------------------------------------------------------

class ParityVectorFiles(unittest.TestCase):
    def test_every_function_has_enough_vectors(self):
        for name in FUNCTIONS:
            with self.subTest(function=name):
                self.assertGreaterEqual(len(load(name)["vectors"]), MIN_VECTORS)

    def test_policy_definitions_match(self):
        expected = [[d["key"], d["label"], d["weight"], d["inheritable"], list(d["candidates"]), d.get("setPrefix")]
                    for d in audit.POLICIES]
        for name in FUNCTIONS:
            with self.subTest(function=name):
                self.assertEqual(load(name)["definitions"], expected)

    def test_every_decision_has_an_expected_failure(self):
        for decision in DECISIONS:
            prefix = "test_" + decision.replace("-", "_") + "_"
            methods = [getattr(DecisionTests, attr) for attr in dir(DecisionTests) if attr.startswith(prefix)]
            self.assertEqual(len(methods), 1, decision)
            self.assertTrue(getattr(methods[0], "__unittest_expecting_failure__", False), decision)


class FunctionParity(unittest.TestCase):
    def check(self, name: str) -> None:
        unexplained = [r for r in results(name) if r["decisions"] is None]
        detail = "; ".join(f"{r['id']} ts={json.dumps(r['ts'])[:160]} py={json.dumps(r['py'])[:160]}" for r in unexplained[:3])
        self.assertEqual(len(unexplained), 0, f"{len(unexplained)} unexplained {name} mismatches: {detail}")

    def test_js_round_parity(self):
        self.check("js_round")

    def test_score_repositories_parity(self):
        self.check("score_repositories")

    def test_classify_agent_parity(self):
        self.check("classify_agent")

    def test_match_policy_changes_parity(self):
        self.check("match_policy_changes")

    def test_resolve_policies_parity(self):
        self.check("resolve_policies")

    def test_scan_organization_parity(self):
        self.check("scan_organization")

    def test_registered_scan_divergences_are_still_observed(self):
        # A perturbation registered as divergent must still need its decision on at least one
        # vector; otherwise one side was aligned and the registration must be removed.
        records = results("scan_organization")
        for perturbation, decision in SCAN_PERTURBATION_DECISIONS.items():
            with self.subTest(perturbation=perturbation):
                self.assertTrue(any(r["via_tag"] and r["perturbation"] == perturbation for r in records),
                                f"{perturbation} no longer diverges; remove it from SCAN_PERTURBATION_DECISIONS ({decision})")


class DecisionTests(unittest.TestCase):
    """One expected failure per open decision: it asserts TS and Python agree on every vector."""

    def divergent(self, decision: str) -> int:
        return sum(1 for name in FUNCTIONS for r in results(name) if r["decisions"] and decision in r["decisions"])

    @unittest.expectedFailure
    def test_P15_D1_score_rounding_agrees(self):
        self.assertEqual(self.divergent("P15-D1"), 0)

    @unittest.expectedFailure
    def test_P15_D2_sort_order_agrees(self):
        self.assertEqual(self.divergent("P15-D2"), 0)

    @unittest.expectedFailure
    def test_P15_D3_reset_at_format_agrees(self):
        self.assertEqual(self.divergent("P15-D3"), 0)

    @unittest.expectedFailure
    def test_P15_D4_regex_and_defaults_agree(self):
        self.assertEqual(self.divergent("P15-D4"), 0)

    @unittest.expectedFailure
    def test_P15_D6_source_strictness_agrees(self):
        self.assertEqual(self.divergent("P15-D6"), 0)

    @unittest.expectedFailure
    def test_P15_D7_malformed_source_tolerance_agrees(self):
        self.assertEqual(self.divergent("P15-D7"), 0)

    @unittest.expectedFailure
    def test_P15_D8_budget_reservation_order_agrees(self):
        self.assertEqual(self.divergent("P15-D8"), 0)


if __name__ == "__main__":
    unittest.main()
