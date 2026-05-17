# Entanglement

Entanglement is a certificate-native `.ent` language for executable programs
whose important semantic rows are visible to the compiler and checked by a small
kernel. The current surface covers resources, effects, external capabilities,
machine contracts, graphics workloads, and tensor training graphs.

The language is organized around three layers:

| Layer | Role |
| --- | --- |
| `.ent` source | Functions, worlds, tensor/model contracts, proofs, and library imports |
| Compiler kernel | Parses, elaborates, checks certificate rows, and verifies proof scripts |
| Runtime libraries | Execute selected domains such as tensor training or headless graphics |

## Install

macOS and Linux:

```bash
./scripts/install.sh
entc doctor
```

Windows PowerShell:

```powershell
.\scripts\install.ps1
entc doctor
```

During development, the same binary can be run from Cargo:

```bash
cargo run -p ent-cli -- check examples/tensor-xor.ent
```

VS Code language metadata for `.ent` files lives in
`tooling/vscode/entanglement`. The `doctor` command prints the local path and
the supported build targets.

## Tensor Example

`examples/tensor-xor.ent` defines tensors, an accelerator capability, an inline
dataset, an MLP op graph, and a training contract. The reusable Ent library code
for tensor shape/NN/optimizer helpers lives under `entlib/tensor/`.

```bash
entc check examples/tensor-xor.ent --json
entc tensor-bench examples/tensor-xor.ent --iterations 1 --json
```

The tensor runtime executes the checked model graph with a reverse-mode AD tape
and SGD update loop. Accelerator rows are explicit capabilities; the current
executor is CPU, with Metal/MPS-style graph execution modeled as a public backend
boundary for future implementation.

## General Commands

```bash
entc check examples/capability-store.ent
entc emit-cert examples/tensor-xor.ent --output build/tensor-xor.cert.json
entc build examples/cpu-audit.ent --target linux-cpu --output build/cpu-audit.entgraph
entc build examples/cpu-audit.ent --target macos-cpu --output build/cpu-audit.entgraph
entc verify-bundle build/cpu-audit.entgraph --json
```

Graphics remains a library/runtime capability:

```bash
entc render tests/graphics/mountain/scene.ent --mode native --width 1280 --height 720 --output assets/figures/mountain.png --json
entc bench benchmarks/graphics --modes interpret,ir,native --warmup 1 --iterations 2 --width 320 --height 180 --output assets/benchmarks/graphics.json --json
```

## Architecture

The compiler produces certificate schema v6. Tensor rows add shape, dtype,
gradient, layout, dataset, model, accelerator, and training contracts to the same
proof-carrying path used by resources and machine contracts.

| Crate | Responsibility |
| --- | --- |
| `ent-parser` / `ent-elab` | Parse `.ent` worlds and lower explicit rows into certificates |
| `ent-kernel` / `ent-proof` | Check relation tables, domain rows, and proof scripts |
| `ent-tensor` | Execute checked tensor model graphs with reverse-mode AD on CPU |
| `ent-graphics` | Execute `.ent` graphics libraries and write deterministic images |
| `ent-transform` | Apply verified workspace transforms |
| `ent-cli` | Shared command surface for check, build, tensor bench, render, and doctor |

Design notes and research anchors are in `agent-notes/`.
