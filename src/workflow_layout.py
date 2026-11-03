"""Enforce Bitcart conventions in GitHub/Forgejo workflows, composite actions and zizmor config."""

import argparse
import difflib
import json
import re
import subprocess
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
    "enable-openid-connect",
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
    "enable-openid-connect",
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
ACTION_TOP = ["name", "description", "author", "inputs", "outputs", "runs", "branding"]
ACTION_FIELDS = ["description", "required", "default", "deprecationMessage", "value"]
ACTION_RUNS = ["using", "main", "pre", "pre-if", "post", "post-if", "steps"]
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
    "pull-requests": ["comment with the lock diff"],
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
    "lock-diff.yml": {"pull-requests": "comment with the lock diff"},
    "python-tests.yml": {"id-token": "OIDC token for codecov uploads"},
    "workflow-checks.yml": {"security-events": "needed for github advanced security"},
}
PULL_REQUEST_TRIGGERS = {"pull_request", "pull_request_target"}
PULL_REQUEST_CONCURRENCY = {
    "group": "${{ github.workflow_ref }}-${{ github.event.pull_request.number || github.sha }}",
    "cancel-in-progress": True,
}
SERIAL_CONCURRENCY = {
    "group": "${{ github.workflow_ref }}",
    "cancel-in-progress": False,
}
QUEUED_CONCURRENCY = {**SERIAL_CONCURRENCY, "queue": "max"}
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
    "actions/*/action.yml",
    "actions/*/action.yaml",
    ".github/actions/*/action.yml",
    ".github/actions/*/action.yaml",
]
JOB_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MINOR_WORDS = {
    "a",
    "an",
    "and",
    "as",
    "at",
    "by",
    "for",
    "from",
    "in",
    "of",
    "on",
    "or",
    "the",
    "to",
    "via",
    "with",
}
RUNNER = "ubuntu-latest"
SHARED = "bitcart/bitcart-actions/"
DEFAULTS = {"run": {"shell": "bash"}}
STEP_SHELL = "        shell: bash"
UNPINNED = [
    (re.compile(r"@latest\b"), "`@latest`"),
    (re.compile(r":latest\b"), "a `:latest` image"),
    (re.compile(r"/releases/latest\b"), "`releases/latest`"),
    (
        re.compile(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba)?sh\b"),
        "a download piped into a shell",
    ),
]
PIP_INSTALL_RE = re.compile(r"\bpip install\b([^\n;&|]*)")
PIP_VALUE_OPTIONS = {
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "--python",
}
SHELLCHECK_EXCLUDES = "SC1091,SC2194,SC2050,SC2153,SC2154,SC2157,SC2043"
ACTION_GLOBS = DEFAULT_GLOBS[-4:]
WORKFLOW_NAME_PREFIXES = ("name: ", "    name: ", "      - name: ", "        name: ")
ACTION_NAME_PREFIXES = ("name: ", "    - name: ", "      name: ")
DOUBLE_QUOTED_RE = re.compile(r'^"(?:[^"\\]|\\.)*"$')
SINGLE_QUOTED_RE = re.compile(r"^'(?:[^']|'')*'$")
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


def reorder_steps(
    lines: list[str], where: str, start: int, end: int, indent: int = 6
) -> None:
    dash, keys_at = " " * indent + "- ", indent + 2
    starts = [k for k in range(start, end) if lines[k].startswith(dash)]
    for n in reversed(range(len(starts))):
        s = starts[n]
        e = starts[n + 1] if n + 1 < len(starts) else end
        while e - 1 > s and not lines[e - 1].strip():
            e -= 1
        step = [" " * keys_at + lines[s][keys_at:], *lines[s + 1 : e]]
        keys = re.findall(rf"(?m)^ {{{keys_at}}}([A-Za-z0-9_-]+):", "\n".join(step))
        label = "name" if "name" in keys else keys[0]
        order = [label, *(k for k in STEP if k != label)]
        step = reorder(step, keys_at, order, set(), f"{where}.steps[{n}]")
        step[0] = dash + step[0][keys_at:]
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
            end = block_end(lines, steps, 4)
            reorder_steps(lines, f"{path}: jobs.{name}", steps + 1, end)


def scalar(value: str) -> object:
    try:
        return yaml.safe_load(f"key: {value}")["key"]
    except yaml.YAMLError:
        return None


def unquoted(value: str) -> str:
    if not (DOUBLE_QUOTED_RE.match(value) or SINGLE_QUOTED_RE.match(value)):
        return value
    text = scalar(value)
    plain = isinstance(text, str) and text == text.strip() and scalar(text) == text
    return text if plain else value


def double_quoted(value: str) -> str:
    if DOUBLE_QUOTED_RE.match(value):
        return value
    if not SINGLE_QUOTED_RE.match(value) and (
        value[0] in "|>[{&*!'\"" or " #" in value
    ):
        return value
    text = scalar(value)
    return json.dumps(text, ensure_ascii=False) if isinstance(text, str) else value


def fix_quoting(lines: list[str], name_prefixes: tuple[str, ...]) -> list[str]:
    fixed = []
    for line in lines:
        if prefix := next((p for p in name_prefixes if line.startswith(p)), None):
            line = prefix + unquoted(line[len(prefix) :])
        elif match := re.match(r"^( *(?:- )?description: )(\S.*)$", line):
            line = match.group(1) + double_quoted(match.group(2))
        fixed.append(line)
    return fixed


def layout_action(text: str, path: str) -> str:
    original = load(text, path)
    lines = text.split("\n")
    has_newline = lines[-1] == ""
    body = fix_quoting(lines[:-1] if has_newline else lines, ACTION_NAME_PREFIXES)
    baseline = "\n".join(body)
    body = reorder(body, 0, ACTION_TOP, set(ACTION_TOP), path)
    for section in ("inputs", "outputs"):
        if f"{section}:" in body:
            start = body.index(f"{section}:")
            end = block_end(body, start, 0)
            fields = [
                k
                for k in range(start + 1, end)
                if re.match(r"^  [A-Za-z0-9_-]+:\s*$", body[k])
            ]
            block = body[start:end]
            starts = [k - start for k in fields]
            reorder_children(block, starts, 4, ACTION_FIELDS, f"{path}: {section}")
            body[start:end] = block
    if "runs:" in body:
        start = body.index("runs:")
        reorder_children(body, [start], 2, ACTION_RUNS, path)
        if "  steps:" in body:
            steps = body.index("  steps:")
            end = block_end(body, steps, 2)
            reorder_steps(body, f"{path}: runs", steps + 1, end, indent=4)
    new = "\n".join(body) + ("\n" if has_newline else "")
    if original != yaml.safe_load(new) or content_lines(baseline) != content_lines(new):
        raise LayoutError(
            f"{path}: refusing to rewrite, the result would change the action"
        )
    return new


def load(text: str, path: str) -> object:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise LayoutError(f"{path}: invalid YAML: {e}") from e


def title_case(word: str, first: bool) -> str:
    if not first and word.lower() in MINOR_WORDS:
        return word.lower()
    return word[:1].upper() + word[1:]


def title_case_error(name: object, where: str) -> list[str]:
    words = str(name or "").split()
    fixed = " ".join(title_case(w, n == 0) for n, w in enumerate(words))
    if fixed == " ".join(words):
        return []
    return [f"{where}: name {name!r} should be Title Case ({fixed!r})"]


def unpinned_packages(script: str) -> list[str]:
    packages = []
    for match in PIP_INSTALL_RE.finditer(script):
        args = match.group(1).split()
        for n, arg in enumerate(args):
            if arg.startswith("-") or (n and args[n - 1] in PIP_VALUE_OPTIONS):
                continue
            if "==" not in arg and re.match(
                r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[.*\])?$", arg
            ):
                packages.append(arg)
    return packages


def unpinned_errors(text: str, where: str) -> list[str]:
    errors = [
        f"{where}: uses {what}" for pattern, what in UNPINNED if pattern.search(text)
    ]
    errors += [
        f"{where}: installs {package!r} without pinning a version"
        for package in unpinned_packages(text)
    ]
    return errors


def value_errors(values: object, where: str) -> list[str]:
    if not isinstance(values, dict):
        return []
    return [
        error
        for key, value in values.items()
        if isinstance(value, str)
        for error in unpinned_errors(value, f"{where}.{key}")
    ]


def input_default_errors(inputs: object, where: str) -> list[str]:
    if not isinstance(inputs, dict):
        return []
    return value_errors(
        {
            key: spec.get("default")
            for key, spec in inputs.items()
            if isinstance(spec, dict)
        },
        where,
    )


def step_errors(steps: object, where: str) -> list[str]:
    errors = []
    for n, step in enumerate(steps if isinstance(steps, list) else []):
        if not isinstance(step, dict):
            continue
        if str(step.get("uses", "")).startswith(SHARED):
            errors += value_errors(step.get("with"), f"{where}.steps[{n}].with")
        if "run" not in step:
            continue
        if "name" not in step:
            errors.append(f"{where}.steps[{n}]: a `run` step needs a `name`")
        errors += unpinned_errors(str(step["run"]), f"{where}.steps[{n}]")
    return errors


def convention_errors(data: object, path: str) -> list[str]:
    if not isinstance(data, dict):
        return []
    if Path(path).name in ("action.yml", "action.yaml"):
        steps = (data.get("runs") or {}).get("steps")
        return (
            title_case_error(data.get("name"), path)
            + input_default_errors(data.get("inputs"), f"{path}: inputs")
            + step_errors(steps, f"{path}: runs")
        )
    errors = title_case_error(data.get("name"), path)
    on = triggers(data)
    if "schedule" in on and "workflow_dispatch" not in on:
        errors.append(f"{path}: a scheduled workflow also needs `workflow_dispatch`")
    call = (data.get(True) or data.get("on") or {}) if "workflow_call" in on else {}
    if isinstance(call, dict) and isinstance(call.get("workflow_call"), dict):
        errors += input_default_errors(
            call["workflow_call"].get("inputs"), f"{path}: on.workflow_call.inputs"
        )
    for job_id, job in (data.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        where = f"{path}: jobs.{job_id}"
        name = job.get("name")
        if not JOB_ID_RE.match(job_id):
            errors.append(f"{where}: job ids are kebab-case")
        if name is None:
            errors.append(f"{where}: needs `name: {job_id}`")
        elif name != job_id and "${{" not in str(name):
            errors.append(f"{where}: `name` must match the job id ({job_id!r})")
        runs_on = job.get("runs-on")
        if runs_on is not None and runs_on != RUNNER and "${{" not in str(runs_on):
            errors.append(f"{where}: `runs-on` must be {RUNNER} or an expression")
        if str(job.get("uses", "")).startswith(SHARED):
            errors += value_errors(job.get("with"), f"{where}.with")
        errors += step_errors(job.get("steps"), where)
        images = [job.get("container")] + list((job.get("services") or {}).values())
        for image in images:
            image = image.get("image") if isinstance(image, dict) else image
            if isinstance(image, str):
                errors += unpinned_errors(image, f"{where}: image {image!r}")
    return errors


def action_scripts(path: Path) -> list[tuple[str, str, str]]:
    data = load(path.read_text(), str(path))
    steps = ((data or {}).get("runs") or {}).get("steps") or []
    return [
        (f"{path}: runs.steps[{n}]", step["shell"], str(step["run"]))
        for n, step in enumerate(steps)
        if isinstance(step, dict)
        and "run" in step
        and step.get("shell") in ("bash", "sh")
    ]


def shellcheck_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run shellcheck on the `run` scripts of composite actions, as actionlint does for workflows"
    )
    parser.add_argument(
        "files", nargs="*", type=Path, help="action files (default: all in the repo)"
    )
    parser.add_argument(
        "--shellcheck", default="shellcheck", help="shellcheck executable"
    )
    args = parser.parse_args(argv)
    files = args.files or sorted(
        p for pattern in ACTION_GLOBS for p in Path().glob(pattern)
    )
    status = 0
    for path in files:
        try:
            scripts = action_scripts(path)
        except LayoutError as e:
            print(f"error: {e}", file=sys.stderr)
            status = 2
            continue
        for where, shell, script in scripts:
            setup = "set -eo pipefail" if shell == "bash" else "set -e"
            sanitized = re.sub(
                r"\$\{\{.*?\}\}",
                lambda m: re.sub(r"[^\n]", "_", m.group(0)),
                script,
                flags=re.DOTALL,
            )
            result = subprocess.run(
                [
                    args.shellcheck,
                    "--norc",
                    "-f",
                    "gcc",
                    "-x",
                    "--shell",
                    shell,
                    "-e",
                    SHELLCHECK_EXCLUDES,
                    "-",
                ],
                input=f"{setup}\n{sanitized}\n",
                check=False,
                capture_output=True,
                text=True,
            )
            for line in result.stdout.splitlines():
                _, row, rest = line.split(":", 2)
                print(f"{where}: line {int(row) - 1}:{rest}")
            if result.returncode:
                status = max(status, 1)
    return status


def triggers(workflow: object) -> set[str]:
    if not isinstance(workflow, dict):
        return set()
    on = workflow.get(True) or workflow.get("on") or {}
    return {on} if isinstance(on, str) else set(on)


def publishes_versions(workflow: dict) -> bool:
    on = workflow.get(True) or workflow.get("on") or {}
    push = on.get("push") if isinstance(on, dict) else None
    return "release" in triggers(workflow) or (
        isinstance(push, dict) and "tags" in push
    )


def expected_concurrency(workflow: object, path: str) -> dict[str, object] | None:
    on = triggers(workflow)
    if not on or "workflow_call" in on:
        return None
    if on & PULL_REQUEST_TRIGGERS:
        return PULL_REQUEST_CONCURRENCY
    if Path(path).parent.parent.name == ".github" and publishes_versions(workflow):
        return QUEUED_CONCURRENCY
    return SERIAL_CONCURRENCY


def fix_concurrency(lines: list[str], path: str, workflow: object) -> list[str]:
    expected = expected_concurrency(workflow, path)
    current = workflow.get("concurrency") if isinstance(workflow, dict) else None
    if expected is None:
        if current is not None and "workflow_call" in triggers(workflow):
            raise LayoutError(
                f"{path}: a workflow_call workflow must not set concurrency, its callers own it"
            )
        return lines
    if current == expected:
        return lines
    block = [
        "concurrency:",
        f"  group: {expected['group']}",
        f"  cancel-in-progress: {str(expected['cancel-in-progress']).lower()}",
        *([f"  queue: {expected['queue']}"] if "queue" in expected else []),
    ]

    def top_level(key: str) -> int | None:
        return next((n for n, line in enumerate(lines) if line.startswith(key)), None)

    if (start := top_level("concurrency:")) is not None:
        end = block_end(lines, start, 0)
    elif (on := top_level("on:")) is not None:
        start = end = block_end(lines, on, 0)
    else:
        raise LayoutError(f"{path}: no `on:` block to add concurrency after")
    return lines[:start] + block + lines[end:]


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


def has_run_steps(workflow: object) -> bool:
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    return any(
        isinstance(step, dict) and "run" in step
        for job in (jobs or {}).values()
        if isinstance(job, dict)
        for step in job.get("steps") or []
    )


def fix_shell(lines: list[str], path: str, workflow: object) -> list[str]:
    if not has_run_steps(workflow) or workflow.get("defaults") == DEFAULTS:
        return lines
    if "defaults" in workflow:
        raise LayoutError(f"{path}: `defaults` must be exactly `run: {{shell: bash}}`")
    if "jobs:" not in lines:
        raise LayoutError(f"{path}: no `jobs:` block to add defaults before")
    start = lines.index("jobs:")
    return [
        *lines[:start],
        "defaults:",
        "  run:",
        "    shell: bash",
        "",
        *lines[start:],
    ]


def drop_step_shells(lines: list[str]) -> list[str]:
    result, in_steps = [], False
    for line in lines:
        if line.strip() and len(line) - len(line.lstrip()) <= 4:
            in_steps = line == "    steps:"
        if not (in_steps and line.rstrip() == STEP_SHELL):
            result.append(line)
    return result


def without_step_shells(workflow: dict) -> dict:
    jobs = {
        name: {
            **job,
            "steps": [
                {k: v for k, v in step.items() if (k, v) != ("shell", "bash")}
                if isinstance(step, dict)
                else step
                for step in job["steps"]
            ],
        }
        if isinstance(job, dict) and job.get("steps")
        else job
        for name, job in (workflow.get("jobs") or {}).items()
    }
    return {**workflow, "jobs": jobs}


def layout(text: str, path: str = "<workflow>") -> str:
    original = load(text, path)
    lines = text.split("\n")
    has_newline = lines[-1] == ""
    body = lines[:-1] if has_newline else lines
    body = fix_concurrency(body, path, original)
    body = fix_shell(body, path, original)
    if has_run_steps(original):
        body = drop_step_shells(body)
    body = fix_quoting(body, WORKFLOW_NAME_PREFIXES)
    baseline = "\n".join(body)
    expected = original
    if concurrency := expected_concurrency(original, path):
        expected = {**expected, "concurrency": concurrency}
    if has_run_steps(original):
        expected = {**without_step_shells(expected), "defaults": DEFAULTS}
    body = reorder(body, 0, TOP, set(TOP), path)
    reorder_on(body, path)
    reorder_jobs(body, path)
    laid_out = "\n".join(body)
    defines_shared = None
    if "workflow_call" in triggers(original):
        defines_shared = SHARED_WORKFLOW_PERMISSIONS.get(Path(path).name)
    fix_permission_comments(body, path, defines_shared)
    new = "\n".join(body) + ("\n" if has_newline else "")
    same_data = expected == yaml.safe_load(new)
    same_lines = content_lines(baseline) == content_lines(laid_out)
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
        help="workflow, composite action and zizmor files (default: all of them in the repo)",
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
    workflow_dirs = (Path(".github/workflows"), Path(".forgejo/workflows"))
    zizmor_config = Path(".github/zizmor.yml")
    has_workflows = any(p.parent in workflow_dirs for p in files)
    if not args.files and has_workflows and zizmor_config not in files:
        files.append(zizmor_config)
    status = 0
    if not args.files and Path(".forgejo/zizmor.yml").exists():
        print(
            f"error: .forgejo/zizmor.yml: zizmor never reads it, use {zizmor_config}",
            file=sys.stderr,
        )
        status = 2
    for path in files:
        text = path.read_text() if path.exists() else ""
        try:
            is_zizmor_config = (
                path.name == "zizmor.yml" and path.parent.name != "workflows"
            )
            if is_zizmor_config:
                new = ZIZMOR_CONFIG
            elif path.name in ("action.yml", "action.yaml"):
                new = layout_action(text, str(path))
            else:
                new = layout(text, str(path))
            errors = (
                []
                if is_zizmor_config
                else convention_errors(load(new, str(path)), str(path))
            )
        except LayoutError as e:
            errors, new = [str(e)], text
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
            status = 2
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
