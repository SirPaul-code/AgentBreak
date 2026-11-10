# Boundary Evidence Lab (AgentBreak working repository)

A dependency-free reference lab for **authority boundaries that must hold even when an agent proposes an unsafe action**. Python 3.11+.

**Status: v0.1 engineering foundation, not a production pentest service or certification.** The AgentBreak name is provisional: other unrelated projects already use it. This repository is not affiliated with them. No PyPI package has been published.

## What actually runs

- 14 synthetic cases: 10 negative security cases and 4 legitimate-task controls.
- Three in-memory targets: deliberately vulnerable, guarded, and deny-everything.
- Checks for tenant separation, forged identity arguments, approval binding, expiration, session separation, one-use approval, registry drift, and action budgets.
- Separate security and utility results. A system that refuses everything cannot pass the release gate.
- Missing observations, transport failures, and invalid responses are INCONCLUSIVE, not secure.
- Canonical, hash-chained evidence; comparison of before/after runs using an identical suite.
- A bounded stdio MCP server with `case_catalog`, `lab_run`, and `bundle_verify`.
- No model/API key, training, external network connection, or inference cost for the lab.

The fixtures execute scripted actions against in-memory state. They **do not measure real LLM prompt-injection resistance**. A passing fixture proves the harness recognizes its known examples, not that a customer's agent is safe.

## Run without installing dependencies

From this repository:

```sh
python -m unittest discover -s tests -v
python -m agentbreak demo --mode guarded --out runs/guarded
python -m agentbreak demo --mode vulnerable --out runs/vulnerable
python -m agentbreak demo --mode deny_all --out runs/deny-all
python -m agentbreak diff runs/vulnerable/evidence.json runs/guarded/evidence.json
```

The vulnerable and deny-all commands intentionally exit **1** (HOLD). Invalid configuration exits **2**. Guarded exits **0** for this declared suite only.

Expected synthetic results:

| Target | Security PASS / FAIL | Utility PASS | Gate |
|---|---|---|---|
| Vulnerable | 0 / 10 | 4 / 4 | HOLD |
| Guarded | 10 / 0 | 4 / 4 | PASS |
| Deny everything | 9 / 1 | 0 / 4 | HOLD |

## Connect an MCP-capable coding agent

The server implements a bounded **stdio subset of MCP 2025-06-18** (initialize, initialized notification, ping, tools/list, tools/call). It is not a complete protocol conformance implementation. It has no HTTP/OAuth endpoint.

```sh
python -m agentbreak.mcp
```

After installing the local package into a virtual environment (`python -m pip install -e .`), use that environment's absolute Python path:

```sh
claude mcp add --transport stdio boundary-lab -- /absolute/path/to/python -m agentbreak.mcp
codex mcp add boundary-lab -- /absolute/path/to/python -m agentbreak.mcp
```

Client command syntax: [Claude Code](https://code.claude.com/docs/en/mcp), [Codex](https://learn.chatgpt.com/docs/extend/mcp). The wire tests pass locally; interactive Claude/Codex sessions have not been tested in this build.

Ask the agent: "Run all three synthetic modes. Explain security failures separately from legitimate-task failures. Do not describe a hash receipt as certification."

The public MCP server cannot select external targets, invoke a shell, read arbitrary files, or make payments.

## Custom adapters and suites

`agentbreak.core.run_suite(suite, factory, target=...)` accepts an adapter with `call(tool, arguments) -> dict` and `close()`. Each case gets a fresh adapter. Export the reference schema using:

```sh
python -m agentbreak export-suite --out runs/suite.json
```

Each case must include coverage checks and observation checks. For a write action, use a trusted state/log observer or synthetic sink, not the agent's statement that it did or did not act. The harness cannot turn a lying or incomplete observer into authoritative evidence. Target-specific instrumentation and analyst review remain necessary.

A model refusal that prevents observation is an incomplete test. An authorized cybersecurity task is not rejected merely because it contains cybersecurity terminology. This does not authorize tests outside an owner's agreed scope.

## Evidence limits

Responses are hashed, not retained, by default. This reduces accidental disclosure but **hashes are not anonymization**, and metadata may still be sensitive. Without explicitly retained responses, offline observation replay is not possible; reproduce by rerunning the pinned suite against the pinned target. Sensitive response capture must be separately authorized.

```sh
python -m agentbreak verify runs/guarded/evidence.json --expected-head COPY_HEAD_FROM_TRUSTED_RECORD
```

Without a separately trusted head, verification checks internal consistency only. An attacker who can replace the whole bundle can recompute an unanchored hash chain. There is no digital auditor signature, identity proof, certification, or guarantee of absence of vulnerabilities.

## Not implemented

Real-model attack generation, indirect-injection campaigns, arbitrary web pentesting, HTTP/SSE/OAuth assessment, cloud deployment, third-party scanner adapters, accredited attestation, and customer-tested integrations are not delivered in v0.1.

Read `SECURITY.md` before adapting this lab to anything outside its synthetic fixtures.
