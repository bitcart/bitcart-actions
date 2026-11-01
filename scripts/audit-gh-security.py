#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "click>=8.1",
#     "httpx>=0.27",
#     "rich>=13.7",
# ]
# ///
"""Read-only audit of a GitHub org's security posture.

Scope: org settings, members, outside collaborators, teams, invitations,
installed GitHub Apps, org + repo secrets/variables, webhooks, environments,
rulesets and branch protection, collaborators, deploy keys, Actions
permissions, code security features. Does NOT modify anything.

Usage:
  ./scripts/audit-gh-security.py                 # default org: bitcart
  ./scripts/audit-gh-security.py bitcart --stale-days 90
  ./scripts/audit-gh-security.py bitcart --repos "bitcart bitcart-sdk"
  ./scripts/audit-gh-security.py --accepted accepted.toml

Each finding prints its ID, `<repo or org>:<check>[:<subject>]`. Findings
listed in the --accepted TOML file are shown dimmed with their reason and not
counted; entries that no longer match anything are reported:
  "org:actions-allowed-all" = "Actions are commit-pinned and Renovate keeps them current"
  "*:deploy-key-write:Forgejo" = "The Forgejo push mirror needs write access"

Requires the `gh` CLI to be authenticated (`gh auth login`) — the token is
read via `gh auth token`. Token scopes needed for full coverage:
  - repo             (read repo secrets/variables/environments/collaborators)
  - admin:org        (org secrets/variables, Actions policy, invitations, apps)
  - admin:org_hook   (org webhooks)
  - read:org         (list org repos, members and teams)
If a section can't be read, the audit says so and why — re-run after
`gh auth refresh -s admin:org,admin:org_hook` to see everything.
"""

from __future__ import annotations

import subprocess
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import click
import httpx
from rich.console import Console
from rich.markup import escape

API = "https://api.github.com"
console = Console(highlight=False)


def gh_token() -> str:
    try:
        out = subprocess.check_output(
            ["gh", "auth", "token"], stderr=subprocess.DEVNULL
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise click.ClickException("gh not authenticated. Run: gh auth login")
    token = out.decode().strip()
    if not token:
        raise click.ClickException("gh auth token returned empty. Run: gh auth login")
    return token


def load_accepted(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as e:
        raise click.ClickException(f"{path}: {e}")
    not_reasons = [k for k, v in data.items() if not isinstance(v, str)]
    if not_reasons:
        raise click.ClickException(
            f"{path}: each entry must map a finding ID to a reason string: "
            + ", ".join(not_reasons)
        )
    return data


@dataclass
class Audit:
    org: str
    stale_days: int
    repos_filter: list[str]
    client: httpx.Client
    accepted: dict[str, str] = field(default_factory=dict)
    warnings: int = 0
    accepted_hits: int = 0
    used_patterns: set[str] = field(default_factory=set)
    audited_scopes: set[str] = field(default_factory=lambda: {"org"})
    scope: str = "org"
    last_error: dict[str, Any] | None = field(default=None, repr=False)
    all_actions_repos: list[str] = field(default_factory=list)
    outside_collaborators: set[str] = field(default_factory=set)
    team_members: dict[str, list[str]] = field(default_factory=dict)

    # ---- UI ------------------------------------------------------------
    def warn(self, key: str, msg: str) -> None:
        finding = f"{self.scope}:{key}"
        pattern = next((p for p in self.accepted if fnmatchcase(finding, p)), None)
        if pattern is not None:
            self.used_patterns.add(pattern)
            self.accepted_hits += 1
            console.print(
                f"  [dim]~  {msg} — accepted: {escape(self.accepted[pattern])}[/dim]"
            )
            return
        console.print(
            f"  [yellow]![/yellow]  {msg}  [dim]{escape(f'[{finding}]')}[/dim]"
        )
        self.warnings += 1

    def ok(self, msg: str) -> None:
        console.print(f"  [green]+[/green]  {msg}")

    def info(self, msg: str) -> None:
        console.print(f"  [cyan]i[/cyan]  {msg}")

    def hdr(self, msg: str) -> None:
        console.print()
        console.print(f"[bold]== {msg} ==[/bold]")

    def sub(self, msg: str) -> None:
        console.print(f"  [bold]{msg}[/bold]")

    def plain(self, msg: str) -> None:
        console.print(f"    {msg}")

    def skipped(self, what: str) -> None:
        err = self.last_error or {}
        self.info(
            f"{what}: skipped (HTTP {err.get('status', '?')}: {err.get('message', 'no data')})"
        )

    # ---- API -----------------------------------------------------------
    def api(self, path: str, *, paginate: bool = False) -> Any:
        """GET a GitHub API path. Returns parsed JSON, or None on error.

        On HTTP 4xx/5xx or a network error the response envelope is stashed in
        `self.last_error` so callers can distinguish "endpoint failed" from
        "endpoint returned an empty result".
        """
        self.last_error = None
        url = path if path.startswith("http") else f"{API}{path}"
        if paginate and "per_page=" not in url:
            url += ("&" if "?" in url else "?") + "per_page=100"
        pages: list[Any] = []

        while url:
            try:
                resp = self.client.get(url)
            except httpx.HTTPError as e:
                self.last_error = {"status": "network", "message": str(e)}
                return None
            if resp.status_code >= 400:
                try:
                    body = resp.json()
                except ValueError:
                    body = {"message": resp.text or resp.reason_phrase}
                if isinstance(body, dict):
                    body.setdefault("status", str(resp.status_code))
                    self.last_error = body
                return None
            try:
                data = resp.json()
            except ValueError:
                return None
            pages.append(data)
            if not paginate:
                return data
            url = resp.links.get("next", {}).get("url")

        if not pages:
            return None
        first = pages[0]
        if isinstance(first, list):
            merged: list[Any] = []
            for p in pages:
                if isinstance(p, list):
                    merged.extend(p)
            return merged
        if isinstance(first, dict):
            merged_obj = dict(first)
            list_key = next(
                (
                    k
                    for k in (
                        "secrets",
                        "variables",
                        "environments",
                        "branch_policies",
                        "installations",
                    )
                    if isinstance(first.get(k), list)
                ),
                None,
            )
            if list_key:
                merged_obj[list_key] = []
                for p in pages:
                    if isinstance(p, dict) and isinstance(p.get(list_key), list):
                        merged_obj[list_key].extend(p[list_key])
            return merged_obj
        return first

    def days_since(self, ts: str | None) -> int | None:
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            return None
        return (datetime.now(UTC) - dt).days

    # ---- driver --------------------------------------------------------
    def run(self) -> None:
        self._banner()
        self._org_settings()
        self._org_secrets_and_vars()
        self._org_access()
        self._org_integrations()
        for repo in self._enumerate_repos():
            self._audit_repo(repo)
        self._summary()

    def _banner(self) -> None:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        console.print("[bold]GitHub security audit[/bold]")
        console.print(f"  org:         {self.org}")
        console.print(f"  stale after: {self.stale_days} days")
        console.print(f"  run at:      {now}")
        if self.repos_filter:
            console.print(f"  repos:       {' '.join(self.repos_filter)}")

    # ---- org-level ----------------------------------------------------
    def _org_settings(self) -> None:
        self.hdr(f"Org {self.org}: settings")

        meta = self.api(f"/orgs/{self.org}")
        if not isinstance(meta, dict):
            self.skipped("Org metadata")
        else:
            two_fa = meta.get("two_factor_requirement_enabled")
            self.plain(
                f"2fa_required={two_fa}  "
                f"default_repository_permission={meta.get('default_repository_permission')}  "
                f"members_can_create_public_repositories={meta.get('members_can_create_public_repositories')}"
            )
            if two_fa is False:
                self.warn("2fa-not-required", "Org does not require 2FA for members")

        aperm = self.api(f"/orgs/{self.org}/actions/permissions")
        if not isinstance(aperm, dict):
            self.skipped("Org Actions policy")
        else:
            self.plain(
                f"Actions: enabled_repositories={aperm.get('enabled_repositories')}  "
                f"allowed_actions={aperm.get('allowed_actions')}  "
                f"sha_pinning_required={aperm.get('sha_pinning_required')}"
            )

        immutable = self.api(f"/orgs/{self.org}/settings/immutable-releases")
        if not isinstance(immutable, dict):
            self.skipped("Org immutable releases policy")
        else:
            self.plain(
                f"Immutable releases: enforced_repositories={immutable.get('enforced_repositories')}"
            )

        wperm = self.api(f"/orgs/{self.org}/actions/permissions/workflow")
        if not isinstance(wperm, dict):
            self.skipped("Org workflow permissions")
        else:
            self.plain(
                f"Workflow permissions: default={wperm.get('default_workflow_permissions')}  "
                f"can_approve_prs={wperm.get('can_approve_pull_request_reviews')}"
            )
            if wperm.get("default_workflow_permissions") == "write":
                self.warn(
                    "workflow-default-write",
                    "Org default_workflow_permissions=write — set 'read'",
                )
            if wperm.get("can_approve_pull_request_reviews"):
                self.warn(
                    "actions-can-approve-prs",
                    "Org lets Actions approve PRs — disable it",
                )

    def _org_secrets_and_vars(self) -> None:
        self.hdr(f"Org {self.org}: secrets & variables")

        secrets = self.api(f"/orgs/{self.org}/actions/secrets", paginate=True)
        if not isinstance(secrets, dict):
            self.skipped("Org secrets")
        elif not secrets.get("secrets"):
            self.info("No org-level secrets.")
        else:
            items = secrets["secrets"]
            self.sub(f"Org secrets ({len(items)}):")
            for s in items:
                name = s.get("name", "?")
                updated = s.get("updated_at", "")
                visibility = s.get("visibility", "?")
                age = self.days_since(updated)
                age_str = f"{age}d" if age is not None else "?"
                line = f"{name}  (updated={updated}, visibility={visibility}, age={age_str})"
                stale = age is not None and age > self.stale_days
                if stale:
                    self.warn(f"secret-stale:{name}", f"stale org secret: {line}")
                if visibility == "all":
                    self.warn(
                        f"secret-visible-all:{name}",
                        f"org secret visible to ALL repos: {line}",
                    )
                if not stale and visibility != "all":
                    self.ok(line)

        org_vars = self.api(f"/orgs/{self.org}/actions/variables", paginate=True)
        if not isinstance(org_vars, dict):
            self.skipped("Org variables")
        elif org_vars.get("variables"):
            var_items = org_vars["variables"]
            self.sub(f"Org variables ({len(var_items)}):")
            for v in var_items:
                self.plain(
                    f"{v.get('name')} = {v.get('value')}  (visibility={v.get('visibility')})"
                )

    def _org_access(self) -> None:
        self.hdr(f"Org {self.org}: people & teams")

        members = self.api(f"/orgs/{self.org}/members", paginate=True)
        admins = self.api(f"/orgs/{self.org}/members?role=admin", paginate=True)
        if not isinstance(members, list):
            self.skipped("Org members")
        else:
            admin_logins = (
                {a.get("login") for a in admins} if isinstance(admins, list) else set()
            )
            self.sub(f"Members ({len(members)}):")
            for m in members:
                login = m.get("login")
                self.plain(
                    f"{login}  (role={'admin' if login in admin_logins else 'member'})"
                )

        outside = self.api(f"/orgs/{self.org}/outside_collaborators", paginate=True)
        if not isinstance(outside, list):
            self.skipped("Outside collaborators")
        elif outside:
            self.outside_collaborators = {o.get("login") for o in outside}
            self.sub(f"Outside collaborators ({len(outside)}):")
            for login in sorted(self.outside_collaborators):
                self.plain(login)

        invitations = self.api(f"/orgs/{self.org}/invitations", paginate=True)
        if not isinstance(invitations, list):
            self.skipped("Org invitations")
        for inv in invitations or []:
            who = inv.get("login") or inv.get("email") or "?"
            self.warn(
                f"invitation-pending:{who}",
                f"pending org invitation for '{who}' (role={inv.get('role')}, "
                f"{self.days_since(inv.get('created_at'))}d old)",
            )

        teams = self.api(f"/orgs/{self.org}/teams", paginate=True)
        if not isinstance(teams, list):
            self.skipped("Teams")
        elif teams:
            self.sub(f"Teams ({len(teams)}):")
            for t in teams:
                slug = t.get("slug", "?")
                team_members = self.api(
                    f"/orgs/{self.org}/teams/{slug}/members", paginate=True
                )
                logins = (
                    [m.get("login") for m in team_members]
                    if isinstance(team_members, list)
                    else []
                )
                self.team_members[slug] = logins
                self.plain(
                    f"{slug}  (privacy={t.get('privacy')}, members={','.join(logins) or '-'})"
                )

    def _org_integrations(self) -> None:
        self.hdr(f"Org {self.org}: apps & webhooks")

        installs = self.api(f"/orgs/{self.org}/installations", paginate=True)
        if not isinstance(installs, dict):
            self.skipped("Installed GitHub Apps")
        elif installs.get("installations"):
            apps = installs["installations"]
            self.sub(f"Installed GitHub Apps ({len(apps)}):")
            for a in apps:
                perms = a.get("permissions") or {}
                writes = sorted(k for k, v in perms.items() if v in ("write", "admin"))
                suspended = "  SUSPENDED" if a.get("suspended_at") else ""
                self.plain(
                    f"{a.get('app_slug')}  (repos={a.get('repository_selection')}, "
                    f"write={','.join(writes) or '-'}){suspended}"
                )

        hooks = self.api(f"/orgs/{self.org}/hooks", paginate=True)
        if not isinstance(hooks, list):
            self.skipped("Org webhooks (needs the admin:org_hook scope)")
        else:
            self._report_hooks(hooks, "Org webhooks")

    def _enumerate_repos(self) -> list[str]:
        self.hdr(f"Repos in {self.org}")
        if self.repos_filter:
            repos = list(self.repos_filter)
        else:
            org_repos = self.api(f"/orgs/{self.org}/repos", paginate=True)
            if isinstance(org_repos, list) and org_repos:
                repos = [r["name"] for r in org_repos if not r.get("archived")]
            else:
                user_repos = self.api(f"/users/{self.org}/repos", paginate=True)
                repos = (
                    [
                        r["name"]
                        for r in user_repos
                        if not r.get("archived") and not r.get("fork")
                    ]
                    if isinstance(user_repos, list)
                    else []
                )
        if not repos:
            raise click.ClickException(
                f"No repos found for {self.org} (or no permission)"
            )
        self.info(f"Found {len(repos)} repos")
        return repos

    # ---- per-repo ------------------------------------------------------
    def _audit_repo(self, repo: str) -> None:
        full = f"{self.org}/{repo}"
        self.scope = repo
        self.audited_scopes.add(repo)
        self.hdr(f"Repo {full}")

        meta = self.api(f"/repos/{full}")
        if not isinstance(meta, dict):
            self.warn("metadata-unreadable", "Cannot read repo metadata")
            return

        default_branch = meta.get("default_branch", "")
        self.info(
            f"default_branch={default_branch}  visibility={meta.get('visibility', '?')}"
            f"{'  fork' if meta.get('fork') else ''}"
        )

        self._repo_secrets(full)
        self._repo_variables(full)
        self._environments(full)
        self._rulesets(full, default_branch)
        self._collaborators(full, private=bool(meta.get("private")))
        self._deploy_keys(full)
        self._webhooks(full)
        self._actions_permissions(full)
        self._workflow_permissions(full)
        self._fork_pr_approval(full)
        self._security_features(full, meta)

    def _repo_secrets(self, full: str) -> None:
        data = self.api(f"/repos/{full}/actions/secrets", paginate=True)
        items = data.get("secrets", []) if isinstance(data, dict) else []
        if not items:
            return
        self.sub(f"Repo secrets ({len(items)}):")
        for s in items:
            name = s.get("name", "?")
            updated = s.get("updated_at", "")
            age = self.days_since(updated)
            age_str = f"{age}d" if age is not None else "?"
            line = f"{name}  (updated={updated}, {age_str} old)"
            if age is not None and age > self.stale_days:
                self.warn(f"secret-stale:{name}", f"stale: {line}")
            else:
                self.ok(line)

    def _repo_variables(self, full: str) -> None:
        data = self.api(f"/repos/{full}/actions/variables", paginate=True)
        items = data.get("variables", []) if isinstance(data, dict) else []
        if not items:
            return
        self.sub(f"Repo variables ({len(items)}):")
        for v in items:
            self.plain(f"{v.get('name')} = {v.get('value')}")

    def _environments(self, full: str) -> None:
        envs = self.api(f"/repos/{full}/environments", paginate=True)
        if not isinstance(envs, dict):
            return
        env_list = envs.get("environments") or []
        if not env_list:
            return
        self.sub(f"Environments ({len(env_list)}):")
        for env in env_list:
            name = env.get("name", "?")
            enc = quote(name, safe="")
            rules = env.get("protection_rules") or []
            has_reviewers = sum(
                1 for r in rules if r.get("type") == "required_reviewers"
            )
            dbp = env.get("deployment_branch_policy") or {}
            if dbp.get("protected_branches"):
                branch_policy = "protected branches"
            elif dbp.get("custom_branch_policies"):
                policies = self.api(
                    f"/repos/{full}/environments/{enc}/deployment-branch-policies",
                    paginate=True,
                )
                patterns = (
                    policies.get("branch_policies", [])
                    if isinstance(policies, dict)
                    else []
                )
                branch_policy = (
                    ",".join(
                        f"{p.get('name')}({p.get('type', 'branch')})" for p in patterns
                    )
                    or "custom (none defined)"
                )
            else:
                branch_policy = None

            env_secrets = self.api(
                f"/repos/{full}/environments/{enc}/secrets", paginate=True
            )
            sec_count = len(
                env_secrets.get("secrets", []) if isinstance(env_secrets, dict) else []
            )

            self.plain(
                f"{name}: reviewers={has_reviewers}, "
                f"branch_policy={branch_policy or 'any'}, "
                f"admins_bypass={str(env.get('can_admins_bypass')).lower()}, "
                f"secrets={sec_count}"
            )
            if sec_count > 0 and has_reviewers == 0:
                self.warn(
                    f"env-no-reviewers:{name}",
                    f"env '{name}' has {sec_count} secret(s) but NO required reviewers",
                )
            if branch_policy is None:
                self.warn(
                    f"env-any-branch:{name}",
                    f"env '{name}' has no deployment branch restriction (any branch can deploy)",
                )

    def _rulesets(self, full: str, default_branch: str) -> None:
        rulesets = self.api(f"/repos/{full}/rulesets", paginate=True)
        err = self.last_error
        if err:
            msg = err.get("message", "")
            if "Upgrade to GitHub Pro" in msg:
                self.info(
                    "Rulesets and branch protection need a paid plan for private repos — skipped"
                )
            else:
                self.warn(
                    "ruleset-api-error",
                    f"Ruleset API returned error (HTTP {err.get('status', '?')}): {msg}",
                )
            return

        normalized = (
            [r for r in rulesets if isinstance(r, dict)]
            if isinstance(rulesets, list)
            else []
        )
        default_refs = {"~ALL", "~DEFAULT_BRANCH", f"refs/heads/{default_branch}"}
        default_covered = False
        if normalized:
            self.sub(f"Rulesets ({len(normalized)}):")
        for rs in normalized:
            rs_id = rs.get("id", "?")
            name = rs.get("name", "unnamed")
            target = rs.get("target", "branch")
            enforcement = rs.get("enforcement", "unknown")
            detail = self.api(f"/repos/{full}/rulesets/{rs_id}") or {}
            rule_types = sorted(
                {r.get("type") for r in (detail.get("rules") or []) if r.get("type")}
            )
            refs = (detail.get("conditions") or {}).get("ref_name") or {}
            includes = refs.get("include") or []
            bypass = detail.get("bypass_actors") or []
            self.plain(
                f"- '{name}' target={target} enforcement={enforcement} "
                f"source={rs.get('source_type', '?')} refs={','.join(includes) or '-'}"
            )
            self.plain(f"  rules: {','.join(rule_types)}")

            required = (
                ("deletion", "update")
                if target == "tag"
                else (
                    "deletion",
                    "non_fast_forward",
                    "required_linear_history",
                    "required_signatures",
                )
            )
            for rule in required:
                if rule not in rule_types:
                    self.warn(
                        f"ruleset-missing-rule:{name}:{rule}",
                        f"ruleset '{name}' missing '{rule}' rule",
                    )
            if enforcement != "active":
                self.warn(
                    f"ruleset-not-active:{name}",
                    f"ruleset '{name}' enforcement={enforcement} (not 'active' — rule is advisory)",
                )
            if bypass:
                self.plain(
                    "  bypass: "
                    + ", ".join(
                        f"{b.get('actor_type')}:{b.get('actor_id')}({b.get('bypass_mode')})"
                        for b in bypass
                    )
                )
            for b in bypass:
                pr_only = b.get("bypass_mode") == "pull_request"
                admin_tag_bypass = (
                    target == "tag" and b.get("actor_type") == "OrganizationAdmin"
                )
                if not pr_only and not admin_tag_bypass:
                    self.warn(
                        f"ruleset-bypass:{name}:{b.get('actor_type')}",
                        f"ruleset '{name}' lets {b.get('actor_type')}:{b.get('actor_id')} "
                        f"bypass it on direct pushes ({b.get('bypass_mode')})",
                    )
            if (
                target == "branch"
                and enforcement == "active"
                and default_refs & set(includes)
            ):
                default_covered = True

        if not default_covered:
            self._classic_protection(
                full, default_branch, has_rulesets=bool(normalized)
            )

        tags = self.api(f"/repos/{full}/tags?per_page=1")
        if tags and not any(r.get("target") == "tag" for r in normalized):
            self.warn(
                "tag-rulesets-missing",
                "No tag rulesets — published version tags can be force-moved or deleted",
            )

    def _classic_protection(
        self, full: str, default_branch: str, *, has_rulesets: bool
    ) -> None:
        branch = quote(default_branch, safe="")
        prot = self.api(f"/repos/{full}/branches/{branch}/protection")
        if isinstance(prot, dict):
            force = (prot.get("allow_force_pushes") or {}).get("enabled")
            deletions = (prot.get("allow_deletions") or {}).get("enabled")
            admins = (prot.get("enforce_admins") or {}).get("enabled")
            self.plain(
                f"Classic protection on {default_branch}: force_pushes={force}, "
                f"deletions={deletions}, enforce_admins={admins}"
            )
            if force or deletions:
                self.warn(
                    "classic-allows-force-or-delete",
                    f"classic protection on {default_branch} allows force pushes or deletion",
                )
        elif has_rulesets:
            self.warn(
                "default-branch-uncovered",
                f"No active branch ruleset or classic protection covers {default_branch}",
            )
        else:
            self.warn(
                "branch-unprotected",
                f"No rulesets or classic protection — default branch ({default_branch}) is unprotected",
            )

    def _collaborators(self, full: str, *, private: bool) -> None:
        collabs = self.api(
            f"/repos/{full}/collaborators?affiliation=direct", paginate=True
        )
        if isinstance(collabs, list) and collabs:
            self.sub(f"Direct collaborators ({len(collabs)}):")
            for c in collabs:
                login = c.get("login")
                outside = "  outside" if login in self.outside_collaborators else ""
                self.plain(f"{login}  (role={c.get('role_name')}){outside}")
            for c in collabs:
                login = c.get("login")
                perms = c.get("permissions") or {}
                if private and login in self.outside_collaborators:
                    self.warn(
                        f"outside-collaborator:{login}",
                        f"outside collaborator '{login}' has {c.get('role_name')} access to this private repo",
                    )
                elif perms.get("push") and not perms.get("admin"):
                    self.warn(
                        f"collaborator-push:{login}",
                        f"direct collaborator '{login}' has {c.get('role_name')} access (can create releases/tags)",
                    )

        teams = self.api(f"/repos/{full}/teams", paginate=True)
        if isinstance(teams, list) and teams:
            self.sub(f"Teams ({len(teams)}):")
            for t in teams:
                slug = t.get("slug", "?")
                members = ",".join(self.team_members.get(slug, [])) or "?"
                self.plain(
                    f"{slug}  (permission={t.get('permission')}, members={members})"
                )

        invitations = self.api(f"/repos/{full}/invitations", paginate=True)
        for inv in invitations if isinstance(invitations, list) else []:
            who = (inv.get("invitee") or {}).get("login") or "?"
            self.warn(
                f"invitation-pending:{who}",
                f"pending invitation for '{who}' ({inv.get('permissions')} access, "
                f"{self.days_since(inv.get('created_at'))}d old)",
            )

    def _deploy_keys(self, full: str) -> None:
        keys = self.api(f"/repos/{full}/keys", paginate=True)
        if not isinstance(keys, list) or not keys:
            return
        self.sub(f"Deploy keys ({len(keys)}):")
        for k in keys:
            title = k.get("title", "?")
            age = self.days_since(k.get("last_used"))
            last_used = f"{age}d ago" if age is not None else "never"
            self.plain(
                f"{title}  (read_only={k.get('read_only')}, last_used={last_used})"
            )
            if not k.get("read_only"):
                self.warn(
                    f"deploy-key-write:{title}",
                    f"deploy key '{title}' has write access",
                )

    def _webhooks(self, full: str) -> None:
        hooks = self.api(f"/repos/{full}/hooks", paginate=True)
        if isinstance(hooks, list) and hooks:
            self._report_hooks(hooks, "Webhooks")

    def _report_hooks(self, hooks: list[dict[str, Any]], title: str) -> None:
        if not hooks:
            self.info(f"No {title.lower()}.")
            return
        self.sub(f"{title} ({len(hooks)}):")
        for h in hooks:
            config = h.get("config") or {}
            host = urlsplit(config.get("url", "")).netloc or "?"
            code = (h.get("last_response") or {}).get("code")
            events = ",".join(h.get("events") or [])
            has_secret = "secret" in config
            self.plain(
                f"{host}  (active={h.get('active')}, last_response={code}, "
                f"secret={has_secret}, created={(h.get('created_at') or '?')[:10]}, "
                f"events={events})"
            )
            if h.get("active") and code is not None and not 200 <= code < 300:
                self.warn(
                    f"webhook-failing:{host}",
                    f"webhook to {host} is failing (HTTP {code}) but still receives events",
                )
            if str(config.get("insecure_ssl")) == "1":
                self.warn(
                    f"webhook-insecure-ssl:{host}",
                    f"webhook to {host} skips TLS certificate verification",
                )
            if not has_secret:
                self.warn(
                    f"webhook-no-secret:{host}",
                    f"webhook to {host} has no secret, so its payloads are unsigned",
                )

    def _actions_permissions(self, full: str) -> None:
        aperm = self.api(f"/repos/{full}/actions/permissions")
        if not isinstance(aperm, dict):
            return
        allowed = aperm.get("allowed_actions", "n/a")
        self.plain(
            f"Actions: enabled={aperm.get('enabled')}  allowed_actions={allowed}  "
            f"sha_pinning_required={aperm.get('sha_pinning_required')}"
        )
        if allowed == "all":
            self.all_actions_repos.append(full)

    def _workflow_permissions(self, full: str) -> None:
        wperm = self.api(f"/repos/{full}/actions/permissions/workflow")
        if not isinstance(wperm, dict):
            return
        default_perms = wperm.get("default_workflow_permissions")
        can_approve = wperm.get("can_approve_pull_request_reviews")
        self.plain(
            f"Workflow permissions: default={default_perms}  can_approve_prs={can_approve}"
        )
        if default_perms == "write":
            self.warn(
                "workflow-default-write",
                "default_workflow_permissions=write — consider 'read' (your workflows set explicit permissions)",
            )
        if can_approve:
            self.warn(
                "actions-can-approve-prs",
                "Actions can approve PRs — disable in Settings > Actions > General",
            )

    def _fork_pr_approval(self, full: str) -> None:
        fp = self.api(f"/repos/{full}/actions/permissions/fork-pr-contributor-approval")
        if not isinstance(fp, dict):
            return
        approval = fp.get("approval_policy", "n/a")
        self.plain(f"Fork PR approval policy: {approval}")
        if approval in (
            "first_time_contributors_new_to_github",
            "first_time_contributors",
        ):
            self.info("Fork PRs from first-time contributors require approval (good)")
        elif approval == "all_external_contributors":
            self.ok("All external contributor PRs require approval")
        else:
            self.warn(
                "fork-pr-no-approval",
                f"Fork PRs from any contributor run without approval (approval_policy={approval})",
            )

    def _security_features(self, full: str, meta: dict[str, Any]) -> None:
        try:
            probe = self.client.get(f"{API}/repos/{full}/vulnerability-alerts")
            alerts_enabled = "true" if probe.status_code == 204 else "false"
        except httpx.HTTPError:
            alerts_enabled = "false"

        saa = meta.get("security_and_analysis") or {}
        scanning = (saa.get("secret_scanning") or {}).get("status", "n/a")
        push_protection = (saa.get("secret_scanning_push_protection") or {}).get(
            "status", "n/a"
        )
        config = self.api(f"/repos/{full}/code-security-configuration")
        config_name = (
            (config.get("configuration") or {}).get("name", "?")
            if isinstance(config, dict)
            else "none"
        )
        immutable = self.api(f"/repos/{full}/immutable-releases")
        if not isinstance(immutable, dict):
            immutable_releases = "?"
        elif immutable.get("enforced_by_owner"):
            immutable_releases = "enforced by org"
        else:
            immutable_releases = str(immutable.get("enabled")).lower()

        self.plain(
            f"security_configuration={config_name}  dependabot_alerts={alerts_enabled}  "
            f"secret_scanning={scanning}  push_protection={push_protection}  "
            f"immutable_releases={immutable_releases}"
        )
        self.plain(
            f"allow_forking={meta.get('allow_forking')}  "
            f"delete_branch_on_merge={str(meta.get('delete_branch_on_merge', False)).lower()}"
        )

    def _unused_accepted(self) -> list[str]:
        return [
            p
            for p in self.accepted
            if p not in self.used_patterns
            and any(fnmatchcase(s, p.split(":", 1)[0]) for s in self.audited_scopes)
        ]

    def _summary(self) -> None:
        self.hdr("Summary")
        self.scope = "org"
        if self.all_actions_repos:
            self.warn(
                "actions-allowed-all",
                f"Actions allowed_actions=all on {len(self.all_actions_repos)} repo(s) — "
                "consider 'selected' with an allowlist in org settings",
            )
        for pattern in self._unused_accepted():
            console.print(
                f"  [yellow]![/yellow]  accepted entry matches no finding — remove it: "
                f"{escape(pattern)}"
            )
            self.warnings += 1
        if self.warnings == 0:
            console.print("[green]No findings.[/green]")
        else:
            console.print(
                f"[yellow]{self.warnings} finding(s) above — review and address.[/yellow]"
            )
        if self.accepted_hits:
            console.print(f"{self.accepted_hits} accepted finding(s) not counted.")
        console.print()
        console.print("Re-run with --stale-days <n> to adjust the staleness threshold.")
        console.print("Re-run with --repos 'repo-a repo-b' to limit scope.")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("org", default="bitcart", required=False)
@click.option(
    "--stale-days",
    type=int,
    default=180,
    envvar="STALE_DAYS",
    show_default=True,
    help="Warn on secrets older than this many days.",
)
@click.option(
    "--repos",
    envvar="REPOS",
    default="",
    help="Space-separated subset of repos to audit (default: every non-archived repo).",
)
@click.option(
    "--accepted",
    envvar="AUDIT_ACCEPTED",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="TOML file mapping finding IDs (glob patterns allowed) to the reason they are accepted.",
)
def main(org: str, stale_days: int, repos: str, accepted: Path | None) -> None:
    """Read-only audit of a GitHub org's security posture."""
    accepted_findings = load_accepted(accepted)
    token = gh_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "audit-gh-security",
    }
    repos_filter = [r for r in repos.split() if r]
    with httpx.Client(headers=headers, timeout=30.0, follow_redirects=True) as client:
        Audit(
            org=org,
            stale_days=stale_days,
            repos_filter=repos_filter,
            client=client,
            accepted=accepted_findings,
        ).run()


if __name__ == "__main__":
    main()
