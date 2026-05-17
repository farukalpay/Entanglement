# Entanglement Architecture Notes

Entanglement is built as a language core with domain libraries around it. The
compiler accepts explicit rows from `.ent` worlds, lowers them into certificate
schema v6, and asks the kernel to check row shape plus matching proof scripts.

The current domain rows are:

| Domain | Rows |
| --- | --- |
| Resource/effect | `state`, `effect`, `external`, `workspace` |
| Program transformation | `parser`, `select`, `transform`, `validator` |
| Tensor training | `tensor`, `accelerator`, `dataset`, `model`, `training` |
| Machine contracts | `machine`, `memory`, `instruction`, `abi`, `proof-artifact` |
| Graphics | `graphics`, `render-target`, `render-pipeline`, `benchmark` |

The tensor path follows the same boundary as the rest of the system: contracts
are checked by the kernel, execution belongs to a runtime crate. `ent-tensor`
loads a verified certificate, parses the declared model op graph, executes a CPU
reverse-mode AD tape, and reports the training loss trajectory.

Portable CPU targets are first-class (`macos-cpu`, `linux-cpu`, `windows-cpu`).
Apple acceleration is represented through public accelerator capability rows.
Private ANE artifacts remain explicit build artifacts and require an explicit
`--ane private` selection; product code should prefer Metal/MPSGraph-style public
graph backends when acceleration is implemented.
