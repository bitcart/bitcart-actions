"""Summarize package version changes between two uv.lock files as Markdown."""

import argparse
import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path
from typing import NamedTuple

CHANGELOG_LABELS = (
    "changelog",
    "changes",
    "release notes",
    "releases",
    "history",
    "news",
)
KINDS = ["direct", "override", "transitive"]
UPDATES = ["major", "minor", "patch", "added", "removed", "changed"]
DEFAULT_GROUP = "dev"
GITHUB_REPO_RE = re.compile(r"^(https://github\.com/[^/]+/[^/]+?)(?:\.git)?/?$")


class Change(NamedTuple):
    name: str
    kind: str
    update: str
    groups: str
    before: str
    after: str
    version: str


def load(path: str) -> dict:
    text = Path(path).read_text()
    return tomllib.loads(text) if text.strip() else {}


def is_root(package: dict) -> bool:
    source = package.get("source", {})
    return "virtual" in source or "editable" in source


def locked_versions(lock: dict) -> dict[str, set[tuple[str, str]]]:
    versions: dict[str, set[tuple[str, str]]] = {}
    for package in lock.get("package", []):
        if is_root(package):
            continue
        rev = package.get("source", {}).get("git", "").rpartition("#")[2][:10]
        versions.setdefault(package["name"], set()).add(
            (package.get("version", ""), rev)
        )
    return versions


def direct_groups(lock: dict) -> dict[str, set[str]]:
    groups: dict[str, set[str]] = {}
    for package in lock.get("package", []):
        if not is_root(package):
            continue
        for dep in package.get("dependencies", []):
            groups.setdefault(dep["name"], set()).add("project")
        for section in ("optional-dependencies", "dev-dependencies"):
            for group, deps in package.get(section, {}).items():
                for dep in deps:
                    groups.setdefault(dep["name"], set()).add(group)
    return groups


def release(version: str) -> tuple[int, ...]:
    match = re.match(r"\d+(\.\d+)*", version)
    return tuple(int(part) for part in match.group().split(".")) if match else ()


def update_type(before: str, after: str) -> str:
    if not before:
        return "added"
    if not after:
        return "removed"
    if before == after:
        return "changed"
    old, new = (*release(before), 0, 0), (*release(after), 0, 0)
    if old[0] != new[0]:
        return "major"
    if old[1] != new[1]:
        return "minor"
    return "patch"


def describe(entries: set[tuple[str, str]]) -> str:
    return (
        ", ".join(
            f"{version} ({rev})" if rev else version for version, rev in sorted(entries)
        )
        or "–"
    )


def newest(entries: set[tuple[str, str]]) -> str:
    return max((version for version, _ in entries), key=release, default="")


def changes(base: dict, head: dict) -> list[Change]:
    old, new = locked_versions(base), locked_versions(head)
    direct = direct_groups(base) | direct_groups(head)
    overrides = {item["name"] for item in head.get("manifest", {}).get("overrides", [])}
    result = []
    for name in old.keys() | new.keys():
        before, after = old.get(name, set()), new.get(name, set())
        if before == after:
            continue
        kind = (
            "direct"
            if name in direct
            else "override"
            if name in overrides
            else "transitive"
        )
        groups = direct.get(name, set())
        groups = groups - {DEFAULT_GROUP} or groups
        version = newest(after)
        update = update_type(newest(before), version)
        result.append(
            Change(
                name,
                kind,
                update,
                ", ".join(sorted(groups)),
                describe(before),
                describe(after),
                version,
            )
        )
    return sorted(
        result, key=lambda c: (KINDS.index(c.kind), UPDATES.index(c.update), c.name)
    )


def changelog_url(name: str, version: str) -> str:
    fallback = f"https://pypi.org/project/{name}/{version}/"
    try:
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{name}/{version}/json", timeout=10
        ) as response:
            urls = json.load(response)["info"].get("project_urls") or {}
    except (OSError, ValueError, KeyError):
        return fallback
    for label, url in urls.items():
        if any(key in label.lower() for key in CHANGELOG_LABELS):
            return url
    for url in urls.values():
        if match := GITHUB_REPO_RE.match(url):
            return f"{match.group(1)}/releases"
    return fallback


def render(rows: list[Change], *, links: bool) -> str:
    counts = {kind: sum(row.kind == kind for row in rows) for kind in KINDS}
    majors = sum(row.update == "major" for row in rows)
    lines = [
        "## uv.lock changes",
        "",
        (
            f"{len(rows)} packages changed: {counts['direct']} direct, {counts['override']} override, "
            f"{counts['transitive']} transitive. {majors} major."
        ),
        "",
    ]
    review = [row for row in rows if row.kind != "transitive" or row.update == "major"]
    rest = [row for row in rows if row not in review]
    if review:
        lines += [
            "### Needs review",
            "",
            "| Package | Kind | Groups | Update | From | To | Changelog |",
            "|---|---|---|---|---|---|---|",
        ]
        for row in review:
            changelog = (
                f"[link]({changelog_url(row.name, row.version)})"
                if links and row.version
                else "–"
            )
            update = f"**{row.update}**" if row.update == "major" else row.update
            lines.append(
                f"| `{row.name}` | {row.kind} | {row.groups or '–'} | {update} | {row.before} | {row.after} | {changelog} |"
            )
        lines.append("")
    if rest:
        lines += [
            f"<details><summary>{len(rest)} other transitive updates</summary>",
            "",
            "| Package | Update | From | To |",
            "|---|---|---|---|",
            *(
                f"| `{row.name}` | {row.update} | {row.before} | {row.after} |"
                for row in rest
            ),
            "",
            "</details>",
            "",
        ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "base", help="uv.lock before the change (an empty file if it didn't exist)"
    )
    parser.add_argument("head", help="uv.lock after the change")
    parser.add_argument(
        "--no-links", action="store_true", help="don't look up changelog links on PyPI"
    )
    args = parser.parse_args()
    rows = changes(load(args.base), load(args.head))
    if rows:
        print(render(rows, links=not args.no_links))
    for row in rows:
        if row.kind != "transitive" and row.update == "major":
            print(
                f"::warning file={args.head}::{row.name} {row.before} → {row.after} is a major update of the {row.kind} dependency",
                file=sys.stderr,
            )


if __name__ == "__main__":
    main()
