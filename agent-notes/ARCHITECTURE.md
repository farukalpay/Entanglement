# Entanglement Architecture Notes

Entanglement is built as a language core with domain libraries around it. The
compiler accepts explicit rows from `.ent` worlds, lowers them into certificate
schema v9, and asks the kernel to check row shape plus matching proof scripts.

The current domain rows are:

| Domain | Rows |
| --- | --- |
| Resource/effect | `state`, `effect`, `external`, `workspace` |
| Program transformation | `parser`, `select`, `transform`, `validator` |
| Tensor runtime boundary | `tensor`, `accelerator`, `dataset`, `canonical`, `artifact`, `lowering`, `executor`, `model`, `training`, `witness` |
| Machine contracts | `machine`, `memory`, `instruction`, `abi`, `proof-artifact` |
| Graphics | `graphics`, `render-target`, `render-pipeline`, `benchmark` |
| Runtime architecture | `runtime-ledger`, `runtime-policy`, `runtime-session`, `runtime-tool`, `runtime-turn`, `runtime-hook`, `runtime-bridge` |

The tensor path follows the same boundary as the rest of the system: contracts
are checked by the kernel, execution belongs to a runtime crate. `ent-tensor`
loads a verified certificate, validates canonical artifact manifests, generates
Python bindings, verifies runtime witnesses, parses the declared model op graph,
executes a CPU reverse-mode AD tape, and reports the training loss trajectory.

Dataset and artifact rows are intentionally separate. A `dataset` row describes
the semantic training input selected by a training contract. An `artifact` row
binds concrete runtime files through a canonical manifest digest. Witness proof
rules consume related rows together; a witness cannot prove trace equivalence or
contract satisfaction from its own row alone.

Portable CPU targets are first-class (`macos-cpu`, `linux-cpu`, `windows-cpu`).
Apple acceleration is represented through public accelerator capability rows.
Private ANE artifacts remain explicit build artifacts and require an explicit
`--ane private` selection; product code should prefer Metal/MPSGraph-style public
graph backends when acceleration is implemented.

The runtime-audit path extracts agent-runtime architecture from
Rust/TypeScript/Python/TOML/Markdown workspaces into an Entanglement-owned
ledger of components and flows: session runtime, turn scheduler, event ledger,
tool surface, execution policy, sandbox boundary, hook runtime, skill and
plugin registries, MCP bridge, app server, realtime bridge, patch engine, and
review gates. Selected rows can now be represented directly in `.ent` worlds as
runtime ledgers, policies, sessions, tools, turns, hooks, and bridges.
