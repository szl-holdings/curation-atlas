"""Bounded, read-only public GitHub observation for Curation Atlas.

This module deliberately does not expose a generic URL fetcher or perform any
provider writes. Its JSON shape mirrors the frontend AuditResult v1 contract.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode

import httpx

ORG = "szl-holdings"
API = "https://api.github.com"
SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
AGENT_DECLARATION = re.compile(
    r"CURSOR_AGENT_PR_BODY|co-authored-by:\s*[^\n]*(?:cursor|claude|copilot|agent|\bai\b)",
    re.IGNORECASE,
)
POLICIES: tuple[dict[str, Any], ...] = (
    {"key": "agent-instructions", "label": "Agent instructions", "weight": 4, "inheritable": False,
     "candidates": ("AGENTS.md", ".github/copilot-instructions.md", "CLAUDE.md", "GEMINI.md")},
    {"key": "codeowners", "label": "Code ownership", "weight": 5, "inheritable": False,
     "candidates": (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")},
    {"key": "security", "label": "Security policy", "weight": 5, "inheritable": True,
     "candidates": (".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md")},
    {"key": "contributing", "label": "Contributing guide", "weight": 3, "inheritable": True,
     "candidates": (".github/CONTRIBUTING.md", "CONTRIBUTING.md", "docs/CONTRIBUTING.md")},
    {"key": "code-of-conduct", "label": "Code of conduct", "weight": 3, "inheritable": True,
     "candidates": (".github/CODE_OF_CONDUCT.md", "CODE_OF_CONDUCT.md", "docs/CODE_OF_CONDUCT.md")},
    {"key": "support", "label": "Support policy", "weight": 2, "inheritable": True,
     "candidates": (".github/SUPPORT.md", "SUPPORT.md", "docs/SUPPORT.md")},
    {"key": "governance", "label": "Governance", "weight": 4, "inheritable": False,
     "candidates": ("GOVERNANCE.md", ".github/GOVERNANCE.md", "docs/GOVERNANCE.md")},
    {"key": "license", "label": "License", "weight": 5, "inheritable": False,
     "candidates": ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")},
    {"key": "dependabot", "label": "Dependency updates", "weight": 4, "inheritable": False,
     "candidates": (".github/dependabot.yml", ".github/dependabot.yaml")},
    {"key": "workflows", "label": "Actions workflows", "weight": 5, "inheritable": False,
     "candidates": (), "setPrefix": ".github/workflows/"},
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def js_round(value: float) -> int:
    """Match JavaScript Math.round for the non-negative scores used here."""
    return math.floor(value + 0.5)


class AuditError(Exception):
    def __init__(self, message: str, status: int = 503, retry_after: str | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class GitHubReader:
    def __init__(self, client: httpx.AsyncClient, token: str | None = None):
        self.client = client
        self.token = token
        self.rate: dict[str, Any] = {"limit": None, "remaining": None, "resetAt": None}

    def _capture_rate(self, headers: httpx.Headers) -> None:
        def integer(name: str) -> int | None:
            value = headers.get(name)
            try:
                return int(value) if value is not None else None
            except ValueError:
                return None

        reset = integer("x-ratelimit-reset")
        reset_at = (
            datetime.fromtimestamp(reset, timezone.utc).isoformat().replace("+00:00", "Z")
            if reset is not None else None
        )
        remaining = integer("x-ratelimit-remaining")
        previous = self.rate
        same_window = not previous["resetAt"] or not reset_at or previous["resetAt"] == reset_at
        if same_window and previous["remaining"] is not None and remaining is not None:
            remaining = min(previous["remaining"], remaining)
        self.rate = {
            "limit": integer("x-ratelimit-limit") or previous["limit"],
            "remaining": remaining if remaining is not None else previous["remaining"],
            "resetAt": reset_at or previous["resetAt"],
        }

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if not path.startswith("/") or path.startswith("//"):
            raise AuditError("Unsafe GitHub API path was rejected.")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SZL-Curation-Atlas/1",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            response = await self.client.get(API + path, params=params, headers=headers)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise AuditError("GitHub source request was unavailable.") from exc
        self._capture_rate(response.headers)
        if response.status_code >= 400:
            if response.status_code == 404:
                raise AuditError("GitHub source was not found.", 404)
            if response.status_code in (403, 429):
                raise AuditError(
                    "GitHub rate or access gate blocked this observation.",
                    429,
                    response.headers.get("retry-after"),
                )
            if response.status_code == 422:
                raise AuditError("GitHub rejected this source request.", 422)
            raise AuditError(f"GitHub source request returned HTTP {response.status_code}.")
        try:
            return response.json()
        except ValueError as exc:
            raise AuditError("GitHub returned an invalid JSON source response.") from exc

    async def maybe(self, path: str, params: dict[str, Any] | None = None) -> Any | None:
        try:
            return await self.get(path, params)
        except AuditError as exc:
            if exc.status in (404, 422):
                return None
            raise


def policy_observation(definition: dict[str, Any], state: str, entry: dict[str, Any] | None = None,
                       source_repo: str | None = None, member_count: int | None = None) -> dict[str, Any]:
    result = {
        "key": definition["key"], "label": definition["label"], "weight": definition["weight"],
        "state": state, "path": entry["path"] if entry else None,
        "blobSha": entry["sha"] if entry else None, "sourceRepo": source_repo,
    }
    if member_count is not None:
        result["memberCount"] = member_count
    return result


def resolve_policies(entries: list[dict[str, Any]], complete: bool,
                     default_entries: list[dict[str, Any]] | None,
                     default_complete: bool, default_repo: str) -> list[dict[str, Any]]:
    blobs = {entry.get("path"): entry for entry in entries if entry.get("type") == "blob"}
    defaults = {entry.get("path"): entry for entry in default_entries or [] if entry.get("type") == "blob"}
    result = []
    for definition in POLICIES:
        prefix = definition.get("setPrefix")
        if prefix:
            members = sorted(
                (entry for path, entry in blobs.items()
                 if isinstance(path, str) and path.startswith(prefix) and re.search(r"\.ya?ml$", path, re.I)),
                key=lambda entry: entry["path"],
            )
            if members:
                result.append(policy_observation(
                    definition, "LOCAL",
                    {"path": f"{prefix}*", "sha": "set:" + "|".join(
                        f"{entry['path']}:{entry['sha']}" for entry in members
                    )}, member_count=len(members),
                ))
            else:
                result.append(policy_observation(
                    definition, "ABSENT" if complete else "UNKNOWN", member_count=0,
                ))
            continue
        local = next((blobs[path] for path in definition["candidates"] if path in blobs), None)
        if local:
            result.append(policy_observation(definition, "LOCAL", local))
        elif not complete:
            result.append(policy_observation(definition, "UNKNOWN"))
        elif definition["inheritable"] and default_entries is not None:
            inherited = next((defaults[path] for path in definition["candidates"] if path in defaults), None)
            if inherited:
                result.append(policy_observation(definition, "INHERITED", inherited, default_repo))
            elif not default_complete:
                result.append(policy_observation(definition, "UNKNOWN", source_repo=default_repo))
            else:
                result.append(policy_observation(definition, "ABSENT"))
        else:
            result.append(policy_observation(definition, "ABSENT"))
    return result


def fingerprint(policy: dict[str, Any]) -> str | None:
    if policy["state"] == "ABSENT":
        return "MISSING"
    if policy["state"] == "UNKNOWN":
        return None
    return policy["blobSha"]


def score_repositories(repositories: list[dict[str, Any]]) -> dict[str, Any]:
    for repository in repositories:
        observed = comparable = agreement = applicable = 0.0
        for policy in repository["policies"]:
            weight = policy["weight"]
            applicable += weight
            value = fingerprint(policy)
            if value is None:
                continue
            observed += weight
            peers = [
                fingerprint(next(item for item in other["policies"] if item["key"] == policy["key"]))
                for other in repositories if other is not repository
            ]
            peers = [peer for peer in peers if peer is not None]
            if peers:
                comparable += weight
                agreement += weight * peers.count(value) / len(peers)
        repository["evidenceCoverage"] = js_round(100 * observed / applicable) if applicable else 0
        repository["consistency"] = js_round(100 * agreement / comparable) if comparable else None
    numerator = denominator = 0.0
    for definition in POLICIES:
        counts: dict[str, int] = {}
        for repository in repositories:
            value = fingerprint(next(item for item in repository["policies"] if item["key"] == definition["key"]))
            if value is not None:
                counts[value] = counts.get(value, 0) + 1
        n = sum(counts.values())
        if n >= 2:
            agree_pairs = sum(count * (count - 1) for count in counts.values())
            numerator += definition["weight"] * agree_pairs / (n * (n - 1))
            denominator += definition["weight"]
    weight_sum = sum(definition["weight"] for definition in POLICIES)
    observed = sum(
        policy["weight"] for repository in repositories for policy in repository["policies"]
        if fingerprint(policy) is not None
    )
    return {
        "alignment": None,
        "consistency": js_round(100 * numerator / denominator) if denominator else None,
        "evidenceCoverage": js_round(100 * observed / (len(repositories) * weight_sum))
        if repositories else 0,
    }


def classify_agent(item: dict[str, Any], repository: str) -> dict[str, Any] | None:
    commit = item.get("commit") or {}
    message = commit.get("message") or ""
    author = item.get("author") or {}
    committer = item.get("committer") or {}
    declared = bool(AGENT_DECLARATION.search(message))
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
        "evidence": (
            "The commit message declares agent assistance. This declaration is not independent verification."
            if declared else
            "GitHub attributes the action to a Bot/App identity. That does not prove an AI system wrote every changed byte."
        ),
    }


def match_policy_changes(files: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    paths: set[str] = set()
    keys: set[str] = set()
    for file in files:
        for path in (file.get("filename"), file.get("previous_filename")):
            if not isinstance(path, str):
                continue
            for definition in POLICIES:
                prefix = definition.get("setPrefix")
                if path in definition["candidates"] or (
                    prefix and path.startswith(prefix) and re.search(r"\.ya?ml$", path, re.I)
                ):
                    paths.add(path)
                    keys.add(definition["key"])
    return sorted(paths), sorted(keys)


def unknown_repo(repository: dict[str, Any], error: str) -> dict[str, Any]:
    return {
        "name": repository["name"], "fullName": repository["full_name"],
        "description": repository.get("description"), "defaultBranch": repository.get("default_branch") or "UNKNOWN",
        "headSha": None, "treeSha": None, "treeComplete": False, "protected": None,
        "archived": repository["archived"], "language": repository.get("language"),
        "updatedAt": repository["updated_at"], "communityHealth": None, "rulesCount": None,
        "workflowCount": 0,
        "policies": [policy_observation(definition, "UNKNOWN") for definition in POLICIES],
        "consistency": None, "evidenceCoverage": 0, "agentSignals": [], "error": error,
        "_entries": [],
    }


async def audit_one(reader: GitHubReader, repository: dict[str, Any], org: str,
                    selected_count: int, completed_count: int) -> dict[str, Any]:
    full_name = repository["full_name"]
    try:
        branch_name = quote(repository["default_branch"], safe="")
        branch = await reader.get(f"/repos/{full_name}/branches/{branch_name}")
        head = branch["commit"]["sha"]
        tree_sha = branch["commit"]["commit"]["tree"]["sha"]
        if not SHA_RE.fullmatch(head) or not SHA_RE.fullmatch(tree_sha):
            raise AuditError("GitHub branch lacked an exact commit and tree SHA.")
        tree = await reader.get(f"/repos/{full_name}/git/trees/{tree_sha}", {"recursive": 1})
        if tree.get("sha") != tree_sha or not isinstance(tree.get("tree"), list):
            raise AuditError("GitHub tree did not match the captured branch tree SHA.")
        entries = tree["tree"]
        complete = not bool(tree.get("truncated"))
        community = await reader.maybe(f"/repos/{full_name}/community/profile")
        rules = await reader.maybe(
            f"/repos/{full_name}/rules/branches/{branch_name}", {"per_page": 100}
        )
        policies = resolve_policies(entries, complete, None, False, f"{org}/.github")
        signals: list[dict[str, Any]] = []
        history: dict[str, Any] = {
            "sourceHeadSha": head, "status": "MEASURED", "commitsExamined": 0,
            "attributedCandidates": 0, "detailsExamined": 0, "unexaminedCandidates": 0,
            "fileListsTruncated": False,
        }
        try:
            reserve = 4 * max(0, selected_count - completed_count - 1)
            remaining = reader.rate["remaining"]
            if remaining is not None and remaining < reserve + 3:
                raise AuditError("GitHub request budget was reserved for remaining source inspections.")
            commits = await reader.maybe(
                f"/repos/{full_name}/commits", {"sha": head, "per_page": 20}
            )
            if not isinstance(commits, list):
                raise AuditError("Recent commit history was unavailable.")
            history["commitsExamined"] = len(commits)
            candidates = list({
                signal["commitSha"]: signal
                for item in commits
                if (signal := classify_agent(item, full_name)) is not None
            }.values())
            history["attributedCandidates"] = len(candidates)
            for candidate in candidates[:2]:
                remaining = reader.rate["remaining"]
                if remaining is not None and remaining < reserve + 1:
                    raise AuditError("GitHub request budget was reserved before commit details.")
                sha = candidate["commitSha"]
                if not SHA_RE.fullmatch(sha):
                    raise AuditError("Attributed candidate lacked an exact commit SHA.")
                detail = await reader.get(
                    f"/repos/{full_name}/commits/{sha}", {"per_page": 100}
                )
                files = detail.get("files")
                if detail.get("sha") != sha or not isinstance(files, list):
                    raise AuditError("Commit file detail lacked an immutable binding.")
                history["detailsExamined"] += 1
                if len(files) >= 100:
                    history["fileListsTruncated"] = True
                paths, keys = match_policy_changes(files)
                if paths:
                    signals.append({
                        **candidate, "path": ", ".join(paths), "sourceHeadSha": head,
                        "changedPaths": paths, "policyKeys": keys,
                    })
            if history["fileListsTruncated"]:
                history["status"] = "BLOCKED"
        except (AuditError, KeyError, TypeError, ValueError) as exc:
            history["status"] = "BLOCKED"
            history["error"] = str(exc)
        history["unexaminedCandidates"] = max(
            0, history["attributedCandidates"] - history["detailsExamined"]
        )
        return {
            "name": repository["name"], "fullName": full_name,
            "description": repository.get("description"), "defaultBranch": repository["default_branch"],
            "headSha": head, "treeSha": tree_sha, "treeComplete": complete,
            "protected": branch.get("protected"), "archived": repository["archived"],
            "language": repository.get("language"), "updatedAt": repository["updated_at"],
            "communityHealth": community.get("health_percentage") if isinstance(community, dict) else None,
            "rulesCount": len(rules) if isinstance(rules, list) else None,
            "workflowCount": next(item for item in policies if item["key"] == "workflows")["memberCount"],
            "policies": policies, "consistency": None, "evidenceCoverage": 0,
            "agentSignals": signals, "policyHistory": history, "_entries": entries,
        }
    except (AuditError, KeyError, TypeError, ValueError) as exc:
        return unknown_repo(repository, str(exc))


async def scan_organization(reader: GitHubReader, sample_size: int) -> dict[str, Any]:
    if sample_size not in (4, 6, 8):
        raise AuditError("Choose a deep sample of 4, 6, or 8 repositories.", 422)
    started = utc_now()
    org_data = await reader.get(f"/orgs/{ORG}")
    if (not isinstance(org_data, dict) or
            not isinstance(org_data.get("login"), str) or
            org_data["login"].lower() != ORG):
        raise AuditError("GitHub organization identity did not match the fixed target.")
    repositories: list[dict[str, Any]] = []
    seen: set[str] = set()
    source_urls = [f"{API}/orgs/{ORG}"]
    for page in range(1, 11):
        path = f"/orgs/{ORG}/repos"
        params = {"type": "public", "sort": "updated", "direction": "desc",
                  "per_page": 100, "page": page}
        batch = await reader.get(path, params)
        source_urls.append(f"{API}{path}?{urlencode(params)}")
        if not isinstance(batch, list):
            raise AuditError("GitHub repository inventory was not a list.")
        for item in batch:
            if not isinstance(item, dict) or item.get("private") is True:
                continue
            full_name = item.get("full_name", "")
            if not isinstance(full_name, str) or not full_name.lower().startswith(f"{ORG}/"):
                continue
            if full_name.lower() not in seen:
                seen.add(full_name.lower())
                repositories.append(item)
        if len(batch) < 100:
            break
    else:
        raise AuditError("Public inventory exceeded the ten-page safety limit.")
    eligible = [
        repository for repository in repositories
        if not repository.get("archived") and not repository.get("disabled") and not repository.get("fork")
    ]
    default_repo = next((repo for repo in eligible if repo.get("name") == ".github"), None)
    selected: list[dict[str, Any]] = []
    if default_repo:
        selected.append(default_repo)
    for repository in eligible:
        if len(selected) >= sample_size:
            break
        if repository not in selected:
            selected.append(repository)
    builds = [
        await audit_one(reader, repository, ORG, len(selected), index)
        for index, repository in enumerate(selected)
    ]
    default_build = next((repo for repo in builds if repo["name"] == ".github"), None)
    for repository in builds:
        default_entries = (
            default_build["_entries"] if default_build is not None and default_build is not repository else None
        )
        repository["policies"] = resolve_policies(
            repository["_entries"], repository["treeComplete"], default_entries,
            default_build["treeComplete"] if default_build else default_repo is None,
            f"{ORG}/.github",
        )
        repository["workflowCount"] = next(
            item for item in repository["policies"] if item["key"] == "workflows"
        )["memberCount"]
    scores = score_repositories(builds)
    completed = utc_now()
    failed = sum("error" in repository for repository in builds)
    truncated = sum("error" not in repository and not repository["treeComplete"] for repository in builds)
    history_blocked = sum(
        repository.get("policyHistory", {}).get("status") == "BLOCKED" for repository in builds
    )
    blocked = failed + truncated + history_blocked
    limitations = [
        "Public repositories only; private and internal repositories are not visible.",
        "The paginated inventory is collected across the scan window, not as one atomic snapshot.",
        f"Deep policy inspection is limited to {len(builds)} active repositories.",
        "No pinned curation manifest was supplied; consistency is descriptive and alignment is suppressed.",
        "Protected branch metadata and public ruleset responses are separate evidence surfaces.",
        "Policy history inspects at most 20 commits per captured head and two attributed candidate file lists.",
    ]
    if history_blocked:
        limitations.append(f"{history_blocked} policy-history inspections were incomplete; mode is BLOCKED.")
    if failed:
        limitations.append(f"{failed} deep source inspections were unavailable; mode is BLOCKED.")
    if truncated:
        limitations.append(f"{truncated} recursive Git trees were truncated; unresolved inputs are UNKNOWN.")
    for repository in builds:
        repository.pop("_entries", None)
    return {
        "schemaVersion": 1, "mode": "BLOCKED" if blocked else "MEASURED",
        "publicOnly": True,
        "org": {
            "login": org_data["login"], "name": org_data.get("name") or ORG,
            "description": org_data.get("description"), "htmlUrl": org_data.get("html_url"),
            "publicRepos": org_data.get("public_repos", len(repositories)),
        },
        "observedAt": completed, "startedAt": started, "completedAt": completed,
        "inventory": {
            "publicRepos": len(repositories),
            "active": sum(not repo.get("archived") and not repo.get("disabled") for repo in repositories),
            "archived": sum(bool(repo.get("archived")) for repo in repositories),
            "forks": sum(bool(repo.get("fork")) for repo in repositories),
        },
        "sampleSize": len(builds),
        "publicInventory": [
            {"fullName": repo["full_name"], "archived": bool(repo.get("archived")),
             "fork": bool(repo.get("fork")), "disabled": bool(repo.get("disabled"))}
            for repo in repositories
        ],
        "repositories": builds, "scores": scores, "rate": reader.rate,
        "sourceUrls": source_urls, "limitations": limitations,
    }
