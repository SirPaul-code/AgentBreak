"""Small, provider-independent runner. Transport errors never mean secure."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Protocol

MAX_CASES = 256
MAX_STEPS = 64
MAX_BYTES = 1_048_576
OPS = {"eq", "ne", "contains", "not_contains", "lte"}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class Adapter(Protocol):
    def call(self, tool: str, arguments: dict) -> dict: ...
    def close(self) -> None: ...


def validate_suite(suite: dict) -> None:
    if not isinstance(suite, dict) or suite.get("schema") != "boundary-suite/1":
        raise ValueError("Unsupported suite schema")
    if len(canonical(suite)) > MAX_BYTES:
        raise ValueError("Suite too large")
    cases = suite.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("Suite must have 1..256 cases")
    ids = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Case must be an object")
        ident = case.get("id")
        if not isinstance(ident, str) or not ident or ident in ids:
            raise ValueError("Case IDs must be nonempty and unique")
        ids.add(ident)
        if not isinstance(case.get("setup", {}), dict):
            raise ValueError("Setup must be an object")
        if case.get("kind") not in {"attack", "utility"}:
            raise ValueError("Case kind must be attack or utility")
        steps = case.get("steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
            raise ValueError("Case must have 1..64 steps")
        for step in steps:
            if not isinstance(step, dict):
                raise ValueError("Step must be an object")
            if not isinstance(step.get("tool"), str) or not step["tool"]:
                raise ValueError("Invalid tool")
            if not isinstance(step.get("arguments"), dict):
                raise ValueError("Tool arguments must be an object")
        checks = case.get("checks")
        if not isinstance(checks, list) or not 1 <= len(checks) <= 256:
            raise ValueError("Case must have 1..256 checks")
        if any(not isinstance(c, dict) for c in checks):
            raise ValueError("Check must be an object")
        if not any(c.get("role") == "observation" for c in checks):
            raise ValueError("An observation check is required")
        if not any(c.get("role") == "coverage" for c in checks):
            raise ValueError("A coverage check is required")
        for check in checks:
            if check.get("role") not in {"coverage", "observation", "behavior"}:
                raise ValueError("Invalid check role")
            idx = check.get("step")
            if type(idx) is not int or not 0 <= idx < len(steps):
                raise ValueError("Invalid check step")
            path = check.get("path")
            if not isinstance(path, list) or len(path) > 32:
                raise ValueError("Invalid JSON path")
            if any(type(p) not in {str, int} for p in path):
                raise ValueError("Paths must contain string keys or integer indexes")
            if check.get("op") not in OPS or "value" not in check:
                raise ValueError("Invalid assertion")


def resolve(value: Any, path: list) -> Any:
    for key in path:
        if isinstance(value, list):
            if type(key) is not int or not 0 <= key < len(value):
                raise KeyError("Invalid array path")
        elif isinstance(value, dict):
            if not isinstance(key, str) or key not in value:
                raise KeyError("Missing object path")
        else:
            raise KeyError("Path traverses a scalar")
        value = value[key]
    return value


def compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "eq":
        return canonical(actual) == canonical(expected)
    if op == "ne":
        return canonical(actual) != canonical(expected)
    if op in {"contains", "not_contains"}:
        if isinstance(actual, str) and isinstance(expected, str):
            found = expected in actual
        elif isinstance(actual, list):
            found = any(canonical(v) == canonical(expected) for v in actual)
        else:
            raise ValueError("contains requires a string or list")
        return found if op == "contains" else not found
    if op == "lte":
        if type(actual) not in {int, float} or type(expected) not in {int, float}:
            raise ValueError("lte requires numbers, not booleans")
        return actual <= expected
    raise ValueError("Unsupported operator")


class Journal:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.head = "0" * 64

    def add(self, body: dict) -> None:
        event = {"seq": len(self.events), "previous": self.head, "body": body}
        self.head = digest(event)
        self.events.append({**event, "sha256": self.head})

    def bundle(self) -> dict:
        return {"schema": "boundary-evidence/1", "events": self.events,
                "head": self.head, "event_count": len(self.events)}


def verify(bundle: dict, expected_head: str | None = None) -> bool:
    try:
        if set(bundle) != {"schema", "events", "head", "event_count"}:
            return False
        if bundle["schema"] != "boundary-evidence/1":
            return False
        events = bundle["events"]
        if not isinstance(events, list) or not events or len(events) > 100_000:
            return False
        if type(bundle["event_count"]) is not int or len(events) != bundle["event_count"]:
            return False
        previous = "0" * 64
        for seq, event in enumerate(events):
            if set(event) != {"seq", "previous", "body", "sha256"}:
                return False
            if type(event["seq"]) is not int or event["seq"] != seq:
                return False
            if event["previous"] != previous:
                return False
            payload = {k: event[k] for k in ("seq", "previous", "body")}
            previous = digest(payload)
            if event["sha256"] != previous:
                return False
        return previous == bundle["head"] and (expected_head is None or previous == expected_head)
    except (KeyError, TypeError, ValueError, RecursionError):
        return False


def run_suite(suite: dict, factory: Callable[[dict], Adapter], *,
              target: str, scope_digest: str = "synthetic-local-only",
              retain_responses: bool = False) -> dict:
    validate_suite(suite)
    journal = Journal()
    journal.add({"type": "run", "suite_sha256": digest(suite), "target": target,
                 "scope_sha256": scope_digest, "runner_version": "0.1.0",
                 "retains_sensitive_responses": retain_responses})
    counts: dict[str, Counter] = {"attack": Counter(), "utility": Counter()}
    for case in suite["cases"]:
        adapter = None
        responses = []
        results = []
        error = None
        try:
            adapter = factory(case)
            for i, step in enumerate(case["steps"]):
                response = adapter.call(step["tool"], step["arguments"])
                if not isinstance(response, dict) or len(canonical(response)) > MAX_BYTES:
                    raise ValueError("Invalid or oversized adapter response")
                responses.append(response)
                body = {"type": "call", "case_id": case["id"], "step": i,
                        "tool": step["tool"], "arguments_sha256": digest(step["arguments"]),
                        "response_sha256": digest(response)}
                if retain_responses:
                    body["response"] = response
                journal.add(body)
            for check in case["checks"]:
                try:
                    actual = resolve(responses[check["step"]], check["path"])
                    passed = compare(actual, check["op"], check["value"])
                    results.append({"role": check["role"], "step": check["step"],
                                    "path": check["path"], "passed": passed,
                                    "actual_sha256": digest(actual),
                                    "expected_sha256": digest(check["value"])})
                except (KeyError, TypeError, ValueError, IndexError):
                    results.append({"role": check["role"], "passed": None,
                                    "step": check["step"], "path": check["path"]})
        except Exception as exc:
            # Never persist exception messages: providers may include credentials.
            error = type(exc).__name__
        finally:
            if adapter is not None:
                try:
                    adapter.close()
                except Exception as exc:
                    error = type(exc).__name__
        if error or any(r["passed"] is None for r in results):
            status = "INCONCLUSIVE"
        elif any(r["role"] == "coverage" and not r["passed"] for r in results):
            status = "INCONCLUSIVE"
        elif not results:
            status = "INCONCLUSIVE"
        else:
            status = "PASS" if all(r["passed"] for r in results) else "FAIL"
        counts[case["kind"]][status] += 1
        journal.add({"type": "case", "case_id": case["id"], "kind": case["kind"],
                     "title": case.get("title", case["id"]), "status": status,
                     "checks": results, "error_type": error})
    summary = {kind: {s: counts[kind][s] for s in ("PASS", "FAIL", "INCONCLUSIVE")}
               for kind in counts}
    gate = all(sum(counts[k].values()) > 0 and not counts[k]["FAIL"]
               and not counts[k]["INCONCLUSIVE"] for k in counts)
    journal.add({"type": "summary", "counts": summary, "release_gate": "PASS" if gate else "HOLD",
                 "meaning": "Only the declared cases; not certification or proof of absence."})
    return journal.bundle()


def summary(bundle: dict) -> dict:
    if not verify(bundle) or bundle["events"][-1]["body"].get("type") != "summary":
        raise ValueError("Invalid evidence bundle")
    return bundle["events"][-1]["body"]


def diff(before: dict, after: dict) -> dict:
    if not verify(before) or not verify(after):
        raise ValueError("Invalid evidence")
    a, b = before["events"][0]["body"], after["events"][0]["body"]
    if a.get("type") != "run" or b.get("type") != "run" or a["suite_sha256"] != b["suite_sha256"]:
        raise ValueError("Different suites cannot establish a fix")
    rows = lambda x: {e["body"]["case_id"]: e["body"]["status"] for e in x["events"]
                      if e["body"].get("type") == "case"}
    old, new = rows(before), rows(after)
    if old.keys() != new.keys():
        raise ValueError("Case coverage changed")
    return {"before_head": before["head"], "after_head": after["head"],
            "changes": [{"id": k, "before": old[k], "after": new[k]}
                        for k in old if old[k] != new[k]],
            "claim": "Status transitions only; reviewer must confirm target and scope comparability."}


def markdown(bundle: dict) -> str:
    report = summary(bundle)
    clean = lambda x: str(x).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = ["# Boundary evidence report", "", "Scope-limited engineering evidence, not certification.",
             "", f"Evidence head: `{bundle['head']}`", "",
             f"Release gate: **{report['release_gate']}**", "",
             "| Case | Kind | Result |", "|---|---|---|"]
    for event in bundle["events"]:
        row = event["body"]
        if row.get("type") == "case":
            lines.append(f"| {clean(row['case_id'])}: {clean(row['title'])} | {row['kind']} | {row['status']} |")
    lines += ["", "A passing attack check does not compensate for a failing legitimate task.",
              "Missing observations and transport errors are INCONCLUSIVE, never PASS.",
              "The hash chain detects changes relative to a separately retained head; it is not an auditor signature.", ""]
    return "\n".join(lines)


def write_private(path: str | Path, content: str) -> None:
    """Atomic owner-only output. The caller must choose a trusted output directory."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".evidence-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
