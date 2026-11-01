"""Enforce Bitcart conventions in GitHub/Forgejo workflow files and zizmor config."""

import argparse
import difflib
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

TOP = [
    "name",
    "run-name",
    "on",
    "concurrency",
    "permissions",
    "env",
    "defaults",
    "jobs",
]
TRIGGERS = [
    "push",
    "pull_request",
    "pull_request_target",
    "release",
    "issues",
    "issue_comment",
    "schedule",
    "workflow_run",
    "workflow_dispatch",
    "workflow_call",
]
CALL_SECTIONS = ["inputs", "secrets", "outputs"]
FIELDS = ["description", "type", "required", "default", "options", "value"]
JOB_HEADER = [
    "name",
    "uses",
    "needs",
    "if",
    "runs-on",
    "environment",
    "concurrency",
    "timeout-minutes",
    "continue-on-error",
    "container",
    "outputs",
    "with",
    "secrets",
]
JOB_BLOCKS = ["permissions", "strategy", "services", "env", "defaults", "steps"]
STEP = [
    "name",
    "id",
    "if",
    "uses",
    "with",
    "working-directory",
    "env",
    "shell",
    "run",
    "continue-on-error",
    "timeout-minutes",
]
PERMISSION_COMMENTS = {
    "actions": ["starting the release run on the tag"],
    "artifact-metadata": ["artifact storage metadata (recommended by actions/attest)"],
    "attestations": ["github attestations"],
    "contents": ["creating the tag", "uploading release assets"],
    "id-token": [
        "OIDC token for codecov uploads",
        "OIDC for provenance",
        "OIDC token for pages deployment",
        "OIDC token for pypi trusted publishing",
    ],
    "issues": ["to synchronize issue labels", "to create issues diagram"],
    "packages": ["publishing to GHCR"],
    "pages": ["to publish on github pages"],
    "security-events": ["needed for github advanced security"],
}
SHARED_WORKFLOW_PERMISSIONS = {
    "build-docker-image.yml": {
        "packages": "publishing to GHCR",
        "id-token": "OIDC for provenance",
        "attestations": "github attestations",
        "artifact-metadata": "artifact storage metadata (recommended by actions/attest)",
    },
    "issues-diagram.yml": {"issues": "to create issues diagram"},
    "labels-sync.yml": {"issues": "to synchronize issue labels"},
    "python-tests.yml": {"id-token": "OIDC token for codecov uploads"},
    "workflow-checks.yml": {"security-events": "needed for github advanced security"},
}
SHARED_WORKFLOW_RE = re.compile(
    r"^    uses: bitcart/bitcart-actions/\.github/workflows/([^@\s]+)@"
)
PERMISSION_RE = re.compile(r"^( +)([a-z-]+): (write)(?:\s+#\s*(.*?))?\s*$")
DEFAULT_GLOBS = [
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".forgejo/workflows/*.yml",
    ".forgejo/workflows/*.yaml",
    ".github/zizmor.yml",
    ".forgejo/zizmor.yml",
]
ZIZMOR_CONFIG = """\
rules:
  unpinned-uses:
    config:
      policies:
        "bitcart/*": ref-pin
"""


class LayoutError(Exception):
    pass


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def block_end(lines: list[str], start: int, indent: int) -> int:
    end = start + 1
    while end < len(lines) and (
        not lines[end].strip() or indent_of(lines[end]) > indent
    ):
        end += 1
    while end - 1 > start and not lines[end - 1].strip():
        end -= 1
    return end


def reorder(
    lines: list[str], indent: int, order: list[str], blank_before: set[str], where: str
) -> list[str]:
    key_re = re.compile(rf"^ {{{indent}}}([A-Za-z0-9_-]+):")
    preamble: list[str] = []
    segments: list[tuple[str, list[str]]] = []
    pending: list[str] = []
    for line in lines:
        if match := key_re.match(line):
            segments.append((match.group(1), [*pending, line]))
            pending = []
        elif line.strip().startswith("#") and (
            indent_of(line) == indent or not segments
        ):
            pending.append(line)
        elif line.strip().startswith("#"):
            segments[-1][1].append(line)
        elif not segments:
            (pending if line.strip() else preamble).append(line)
        elif line.strip() and indent_of(line) <= indent:
            raise LayoutError(
                f"{where}: unexpected line at indent {indent_of(line)}: {line.strip()}"
            )
        else:
            segments[-1][1].append(line)
    if not segments:
        return lines
    segments[-1][1].extend(pending)
    unknown = [key for key, _ in segments if key not in order]
    if unknown:
        raise LayoutError(f"{where}: unknown keys {unknown}")
    trailing = len(lines) - len(strip_trailing_blanks(lines))
    out = list(preamble)
    for n, (key, segment) in enumerate(
        sorted(segments, key=lambda s: order.index(s[0]))
    ):
        if n and (key in blank_before):
            out.append("")
        out += strip_trailing_blanks(segment)
    return out + [""] * trailing


def strip_trailing_blanks(lines: list[str]) -> list[str]:
    end = len(lines)
    while end and not lines[end - 1].strip():
        end -= 1
    return lines[:end]


def reorder_children(
    lines: list[str], starts: list[int], child_indent: int, order: list[str], where: str
) -> None:
    for start in reversed(starts):
        end = block_end(lines, start, child_indent - 2)
        label = lines[start].strip().rstrip(":")
        lines[start + 1 : end] = reorder(
            lines[start + 1 : end], child_indent, order, set(), f"{where}.{label}"
        )


def reorder_on(lines: list[str], path: str) -> None:
    if "on:" not in lines:
        return
    start = lines.index("on:")
    end = block_end(lines, start, 0)
    block = lines[start:end]
    fields, section = [], None
    for k, line in enumerate(block):
        if indent_of(line) <= 4 and line.strip():
            section = re.match(r"^    (inputs|secrets|outputs):\s*$", line)
        elif section and re.match(r"^      [A-Za-z0-9_-]+:\s*$", line):
            fields.append(k)
    reorder_children(block, fields, 8, FIELDS, f"{path}: on")
    calls = [
        k for k, line in enumerate(block) if re.match(r"^  workflow_call:\s*$", line)
    ]
    reorder_children(block, calls, 4, CALL_SECTIONS, f"{path}: on")
    reorder_children(block, [0], 2, TRIGGERS, path)
    lines[start:end] = block


def reorder_steps(lines: list[str], path: str, job: str, start: int, end: int) -> None:
    starts = [k for k in range(start, end) if lines[k].startswith("      - ")]
    for n in reversed(range(len(starts))):
        s = starts[n]
        e = starts[n + 1] if n + 1 < len(starts) else end
        while e - 1 > s and not lines[e - 1].strip():
            e -= 1
        step = ["        " + lines[s][8:], *lines[s + 1 : e]]
        keys = re.findall(r"(?m)^ {8}([A-Za-z0-9_-]+):", "\n".join(step))
        label = "name" if "name" in keys else keys[0]
        where = f"{path}: jobs.{job}.steps[{n}]"
        step = reorder(step, 8, [label, *(k for k in STEP if k != label)], set(), where)
        step[0] = "      - " + step[0][8:]
        lines[s:e] = step


def reorder_jobs(lines: list[str], path: str) -> None:
    if "jobs:" not in lines:
        return
    start = lines.index("jobs:")
    end = block_end(lines, start, 0)
    job_starts = [
        k
        for k in range(start + 1, end)
        if re.match(r"^  [A-Za-z0-9_-]+:\s*(#.*)?$", lines[k])
    ]
    for n in reversed(range(len(job_starts))):
        j = job_starts[n]
        e = job_starts[n + 1] if n + 1 < len(job_starts) else end
        name = lines[j].strip().rstrip(":")
        body = lines[j + 1 : e]
        body = reorder(
            body, 4, JOB_HEADER + JOB_BLOCKS, set(JOB_BLOCKS), f"{path}: jobs.{name}"
        )
        lines[j + 1 : e] = body
        steps = next(
            (
                k
                for k in range(j + 1, j + 1 + len(body))
                if re.match(r"^    steps:\s*$", lines[k])
            ),
            None,
        )
        if steps is not None:
            reorder_steps(lines, path, name, steps + 1, block_end(lines, steps, 4))


def content_lines(text: str) -> Counter[str]:
    return Counter(
        line.strip().removeprefix("- ") for line in text.splitlines() if line.strip()
    )


def fix_permission_comments(
    lines: list[str], path: str, defines_shared: dict[str, str] | None
) -> None:
    errors: list[str] = []
    shared: dict[str, str] | None = None
    granted: set[str] = set()
    perm_indent = -1
    for n, line in enumerate(lines):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*(#.*)?$", line):
            shared = None
        if match := SHARED_WORKFLOW_RE.match(line):
            shared = SHARED_WORKFLOW_PERMISSIONS.get(match.group(1))
        if match := re.match(r"^( *)permissions:\s*$", line):
            perm_indent = len(match.group(1)) + 2
            continue
        if line.strip() and indent_of(line) < perm_indent:
            perm_indent = -1
        match = PERMISSION_RE.match(line)
        if not match or len(match.group(1)) != perm_indent:
            continue
        indent, scope, _, comment = match.groups()
        where = f"{path}:{n + 1}: `{scope}: write`"
        allowed = PERMISSION_COMMENTS.get(scope)
        if allowed is None:
            errors.append(f"{where} has no registered justification comments")
            continue
        if defines_shared is not None and perm_indent == 6:
            granted.add(scope)
            expected = defines_shared.get(scope)
            if expected is None:
                errors.append(
                    f"{where} is not listed for this workflow in SHARED_WORKFLOW_PERMISSIONS"
                )
                continue
        else:
            expected = (shared or {}).get(scope) or (
                allowed[0] if len(allowed) == 1 else None
            )
        if expected is not None:
            lines[n] = f"{indent}{scope}: write # {expected}"
        elif comment not in allowed:
            errors.append(
                f"{where} needs one of these comments: {', '.join(repr(c) for c in allowed)}"
            )
    if defines_shared is not None and (missing := set(defines_shared) - granted):
        errors.append(
            f"{path}: SHARED_WORKFLOW_PERMISSIONS lists {sorted(missing)}, which the workflow does not request"
        )
    if errors:
        raise LayoutError("\n".join(errors))


def layout(text: str, path: str = "<workflow>") -> str:
    try:
        original = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise LayoutError(f"{path}: invalid YAML: {e}") from e
    lines = text.split("\n")
    has_newline = lines[-1] == ""
    body = lines[:-1] if has_newline else lines
    body = reorder(body, 0, TOP, set(TOP), path)
    reorder_on(body, path)
    reorder_jobs(body, path)
    laid_out = "\n".join(body)
    defines_shared = None
    if isinstance(original, dict) and "workflow_call" in (
        original.get(True) or original.get("on") or {}
    ):
        defines_shared = SHARED_WORKFLOW_PERMISSIONS.get(Path(path).name)
    fix_permission_comments(body, path, defines_shared)
    new = "\n".join(body) + ("\n" if has_newline else "")
    same_data = original == yaml.safe_load(new)
    same_lines = content_lines(text) == content_lines(laid_out)
    only_comments = all(
        a.split(" #")[0] == b.split(" #")[0]
        for a, b in zip(laid_out.split("\n"), body, strict=True)
    )
    if not (same_data and same_lines and only_comments):
        raise LayoutError(
            f"{path}: refusing to rewrite, the result would change the workflow"
        )
    return new


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="workflow and zizmor files (default: under .github and .forgejo)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report files that need changes instead of rewriting them",
    )
    args = parser.parse_args(argv)
    files = args.files or sorted(
        p for pattern in DEFAULT_GLOBS for p in Path().glob(pattern)
    )
    zizmor_config = Path(".github/zizmor.yml")
    has_github_workflows = any(p.parent == Path(".github/workflows") for p in files)
    if not args.files and has_github_workflows and zizmor_config not in files:
        files.append(zizmor_config)
    status = 0
    for path in files:
        text = path.read_text() if path.exists() else ""
        try:
            is_zizmor_config = (
                path.name == "zizmor.yml" and path.parent.name != "workflows"
            )
            new = ZIZMOR_CONFIG if is_zizmor_config else layout(text, str(path))
        except LayoutError as e:
            print(f"error: {e}", file=sys.stderr)
            status = 2
            continue
        if new == text:
            continue
        status = max(status, 1)
        if args.check:
            sys.stdout.writelines(
                difflib.unified_diff(
                    text.splitlines(True), new.splitlines(True), str(path), str(path)
                )
            )
        else:
            path.write_text(new)
            print(f"fixed {path}")
    return status


if __name__ == "__main__":
    sys.exit(main())
