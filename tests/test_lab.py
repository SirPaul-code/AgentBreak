import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentbreak.core import (canonical, compare, diff, digest, markdown, resolve,
                             run_suite, summary, validate_suite, verify, write_private)
from agentbreak.fixtures import Fixture, suite
from agentbreak.mcp import Server


def run(mode="guarded", data=None):
    return run_suite(data or suite(), lambda c: Fixture(mode, c.get("setup")), target="synthetic:" + mode)


class EvidenceTests(unittest.TestCase):
    def test_guarded_all_pass(self):
        report = summary(run())
        self.assertEqual(report["counts"]["attack"], {"PASS": 10, "FAIL": 0, "INCONCLUSIVE": 0})
        self.assertEqual(report["counts"]["utility"]["PASS"], 4)
        self.assertEqual(report["release_gate"], "PASS")

    def test_vulnerable_exposes_all_known_faults(self):
        report = summary(run("vulnerable"))
        self.assertEqual(report["counts"]["attack"]["FAIL"], 10)
        self.assertEqual(report["counts"]["utility"]["PASS"], 4)
        self.assertEqual(report["release_gate"], "HOLD")

    def test_deny_all_cannot_win(self):
        report = summary(run("deny_all"))
        self.assertEqual(report["counts"]["utility"]["PASS"], 0)
        self.assertEqual(report["release_gate"], "HOLD")

    def test_deterministic(self):
        self.assertEqual(run(), run())

    def test_mutation_detected(self):
        bundle = run()
        bundle["events"][1]["body"]["tool"] = "modified"
        self.assertFalse(verify(bundle))

    def test_deletion_detected(self):
        bundle = run()
        bundle["events"].pop(1)
        self.assertFalse(verify(bundle))

    def test_external_head_detects_replacement(self):
        a, b = run(), run("vulnerable")
        self.assertFalse(verify(b, a["head"]))

    def test_unknown_bundle_metadata_rejected(self):
        bundle = run()
        bundle["certified"] = True
        self.assertFalse(verify(bundle))

    def test_summary_is_inside_chain(self):
        bundle = run()
        bundle["events"][-1]["body"]["release_gate"] = "forged"
        self.assertFalse(verify(bundle))

    def test_empty_chain_rejected(self):
        self.assertFalse(verify({"schema": "boundary-evidence/1", "events": [], "head": "0" * 64, "event_count": 0}))

    def test_booleans_not_numbers(self):
        self.assertFalse(compare(True, "eq", 1))
        with self.assertRaises(ValueError):
            compare(True, "lte", 3)

    def test_missing_path_is_inconclusive(self):
        data = suite()
        data["cases"][0]["checks"][1]["path"] = ["missing"]
        self.assertEqual(summary(run(data=data))["counts"]["utility"]["INCONCLUSIVE"], 1)

    def test_incomplete_observation_is_inconclusive(self):
        class Incomplete(Fixture):
            def call(self, tool, args):
                result = super().call(tool, args)
                if tool == "observe":
                    result["complete"] = False
                return result
        bundle = run_suite(suite(), lambda c: Incomplete("guarded", c.get("setup")), target="incomplete")
        self.assertEqual(summary(bundle)["counts"]["attack"]["INCONCLUSIVE"], 10)

    def test_adapter_errors_not_security_success(self):
        class Broken(Fixture):
            def call(self, tool, args):
                raise TimeoutError("SECRET_MUST_NOT_BE_PERSISTED")
        bundle = run_suite(suite(), lambda c: Broken(), target="broken")
        self.assertEqual(summary(bundle)["counts"]["attack"]["INCONCLUSIVE"], 10)
        self.assertNotIn("SECRET_MUST_NOT_BE_PERSISTED", canonical(bundle).decode())

    def test_no_raw_responses_by_default(self):
        self.assertNotIn("CANARY_OTHER_TENANT", canonical(run("vulnerable")).decode())

    def test_explicit_sensitive_capture(self):
        bundle = run_suite(suite(), lambda c: Fixture("vulnerable", c.get("setup")),
                           target="synthetic", retain_responses=True)
        self.assertIn("CANARY_OTHER_TENANT", canonical(bundle).decode())

    def test_diff_records_ten_retests(self):
        changes = diff(run("vulnerable"), run())["changes"]
        self.assertEqual(len(changes), 10)
        self.assertTrue(all(x["before"] == "FAIL" and x["after"] == "PASS" for x in changes))

    def test_diff_rejects_changed_suite(self):
        data = suite()
        data["name"] = "different"
        with self.assertRaises(ValueError):
            diff(run(), run(data=data))

    def test_duplicate_case_rejected(self):
        data = suite()
        data["cases"].append(copy.deepcopy(data["cases"][0]))
        with self.assertRaises(ValueError):
            validate_suite(data)

    def test_nonobject_case_rejected(self):
        data = suite()
        data["cases"][0] = "invalid"
        with self.assertRaises(ValueError):
            validate_suite(data)

    def test_nonobject_step_rejected(self):
        data = suite()
        data["cases"][0]["steps"][0] = 2
        with self.assertRaises(ValueError):
            validate_suite(data)

    def test_nonobject_check_rejected(self):
        data = suite()
        data["cases"][0]["checks"][0] = "invalid"
        with self.assertRaises(ValueError):
            validate_suite(data)

    def test_empty_suite_rejected(self):
        with self.assertRaises(ValueError):
            validate_suite({"schema": "boundary-suite/1", "cases": []})

    def test_no_checks_rejected(self):
        data = suite()
        data["cases"][0]["checks"] = []
        with self.assertRaises(ValueError):
            validate_suite(data)

    def test_no_coverage_check_rejected(self):
        data = suite()
        data["cases"][0]["checks"] = data["cases"][0]["checks"][1:]
        with self.assertRaises(ValueError):
            validate_suite(data)

    def test_out_of_range_step_rejected(self):
        data = suite()
        data["cases"][0]["checks"][0]["step"] = 1000
        with self.assertRaises(ValueError):
            validate_suite(data)

    def test_negative_array_path_rejected(self):
        with self.assertRaises(KeyError):
            resolve([1], [-1])

    def test_nan_rejected(self):
        with self.assertRaises(ValueError):
            canonical({"n": float("nan")})

    def test_atomic_owner_only_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.json"
            write_private(path, "{}")
            self.assertEqual(path.read_text(), "{}")
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_report_has_no_certification_claim(self):
        self.assertIn("not certification", markdown(run()))

    def test_security_only_suite_does_not_pass_gate(self):
        data = suite()
        data["cases"] = [c for c in data["cases"] if c["kind"] == "attack"]
        self.assertEqual(summary(run(data=data))["release_gate"], "HOLD")


class MCPTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()

    def ready(self):
        self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": "2025-06-18"}})
        self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, name, args=None):
        return self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                   "params": {"name": name, "arguments": args or {}}})

    def test_lifecycle_enforced(self):
        self.assertEqual(self.call("case_catalog")["error"]["code"], -32002)

    def test_catalog(self):
        self.ready()
        result = self.call("case_catalog")["result"]["structuredContent"]
        self.assertEqual(len(result["cases"]), 14)

    def test_lab_tool(self):
        self.ready()
        result = self.call("lab_run", {"mode": "guarded"})["result"]["structuredContent"]
        self.assertTrue(verify(result))

    def test_invalid_mode(self):
        self.ready()
        self.assertIn("error", self.call("lab_run", {"mode": "anything"}))

    def test_cannot_supply_remote_target(self):
        self.ready()
        self.assertIn("error", self.call("lab_run", {"url": "https://example.invalid"}))

    def test_no_arbitrary_shell_tool(self):
        self.ready()
        self.assertIn("error", self.call("shell", {"command": "id"}))

    def test_invalid_request(self):
        self.assertEqual(self.server.handle([])["error"]["code"], -32600)

    def test_notification_has_no_response(self):
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_duplicate_initialization(self):
        self.ready()
        self.assertIn("error", self.server.handle({"jsonrpc": "2.0", "id": 4, "method": "initialize"}))

    def test_stdio_real_process(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "lab_run", "arguments": {"mode": "guarded"}}}]
        result = subprocess.run([sys.executable, "-m", "agentbreak.mcp"],
                                input=b"\n".join(canonical(r) for r in requests) + b"\n",
                                capture_output=True, timeout=10, check=True)
        output = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(output), 2)
        self.assertEqual(output[1]["id"], 2)
        self.assertTrue(verify(output[1]["result"]["structuredContent"]))

    def test_oversized_message_bounded(self):
        result = subprocess.run([sys.executable, "-m", "agentbreak.mcp"],
                                input=b"x" * 1_048_578 + b"\n", capture_output=True, timeout=10)
        self.assertIn("error", json.loads(result.stdout))


if __name__ == "__main__":
    unittest.main()
