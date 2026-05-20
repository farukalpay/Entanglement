# Runtime Architecture Audit

`ent-runtime-audit` is the Entanglement-owned path for auditing agent-runtime
architecture. It reads a workspace, emits a component/flow ledger, and can be
paired with explicit `.ent` runtime rows for certificate-level contracts.

The ledger tracks:

- runtime core and session admission
- turn scheduling and task lanes
- event ledgers and durable stores
- tool surfaces, execution policy, and sandbox boundaries
- hook runtimes, skill registries, plugin registries, and MCP bridges
- model providers, app servers, API protocols, and realtime channels
- patch engines and review gates

The design tracks architecture, not product names. Source-package identifiers
remain evidence only; every exported component is owned by `entanglement` and
receives a `runtime:*` id. This keeps reports stable even when the audited
workspace has a different crate or package layout.

Runtime contracts can be written explicitly as `runtime-ledger`,
`runtime-policy`, `runtime-session`, `runtime-tool`, `runtime-turn`,
`runtime-hook`, and `runtime-bridge` rows. Proof rules tie each row back to the
same kernel path used by other certificate domains.
