# Security and trust boundaries

Use only systems you own or are explicitly authorized to test. Public fixtures operate entirely in memory and use synthetic records and `.invalid` destinations. They perform no real email, shell, file, payment, or network actions.

Do not expose the deliberately vulnerable fixture on a public network. Do not add real credentials or customer data to fixtures, issue reports, CI logs, or public commits. Never scan a public project merely because its source is open.

The public MCP interface accepts no arbitrary target, command, file path, or provider credentials. It is a local stdio interface, not a multi-user hosted service.

A custom adapter is executable trusted code. A process allowlist is not an OS sandbox. For customer software use a disposable VM/container, restricted egress, synthetic data, and independent observation credentials. Review transitive dependencies and the whole launch context.

Coverage assertions must originate from a trustworthy observer. Model text and a tool's claim of success are not independent proof of a side effect. This library does not verify the truthfulness of an observer.

Evidence output can be sensitive even when response bodies are omitted. Store outside version control, restrict access, establish retention with the owner, and preserve the evidence head independently. Hashes alone neither establish identity nor make low-entropy values confidential.

No certification, legal compliance, or complete security coverage is claimed. Do not publish findings on live third-party systems without coordinated disclosure and explicit permission.
