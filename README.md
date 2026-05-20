# Entanglement

Entanglement is a certificate-native `.ent` language for executable programs
whose important semantic rows are visible to the compiler and checked by a small
kernel. The current surface covers resources, effects, external capabilities,
workspace protocols, machine contracts, tensor training boundaries, and
graphics workloads.

The language is organized around three layers:

| Layer | Role |
| --- | --- |
| `.ent` source | Functions, worlds, runtime boundary rows, proofs, and library imports |
| Compiler kernel | Parses, elaborates, checks certificate rows, and verifies proof scripts |
| Runtime libraries | Execute selected domains, bind runtime artifacts, and verify witnesses |

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

`examples/tensor-xor.ent` defines tensors, a semantic dataset row, a separately
bound dataset artifact, a lowering contract, a Python executor boundary, an MLP
op graph, and a runtime witness requirement. The reusable Ent library code for
tensor shape/NN/optimizer helpers lives under `entlib/tensor/`.

```bash
entc check examples/tensor-xor.ent --json
entc verify-artifact examples/tensor-xor.ent --json
entc bind examples/tensor-xor.ent --target python --framework pytorch_fx --output build/ent_xor_contract.py
entc verify-witness examples/tensor-xor.ent examples/artifacts/xor_run.witness.json --json
entc tensor-bench examples/tensor-xor.ent --iterations 1 --json
```

The artifact digest is the sha256 of canonical JSON with schema
`ent.tensor-manifest.v1`; it binds tensor shape, dtype, layout, and per-tensor
byte digests. Generated Python bindings force runtime tensors through that same
manifest digest before training can seal a witness. Witness proof rules are
structural: trace equivalence consumes witness, model, and lowering rows;
witness satisfaction consumes witness, training, artifact, and executor rows.

## General Commands

```bash
entc check examples/capability-store.ent
entc plan examples/workspace-protocol.ent --json
entc inspect . --markdown --output build/workspace-map.md
entc apply examples/repo-cleanup.ent --repo path/to/repo --dry-run --json
entc emit-cert examples/tensor-xor.ent --output build/tensor-xor.cert.json
entc build examples/cpu-audit.ent --target linux-cpu --output build/cpu-audit.entgraph
entc build examples/cpu-audit.ent --target macos-cpu --output build/cpu-audit.entgraph
entc verify-bundle build/cpu-audit.entgraph --json
```

`examples/workspace-protocol.ent` adds checked objectives, milestones, tasks,
gates, decisions, and notes to the same certificate path as workspace
transforms. `entc plan` prints those rows as a reviewable report, while
`entc apply --dry-run` stages transforms and validators without writing target
files.

`entc inspect` maps `.ent`, Rust, C, and C++ sources into one deterministic
report: verified worlds, declaration counts, proof coverage, source symbols,
include/use edges, call edges, diagnostics, and readiness signals.

Graphics remains a library/runtime capability:

```bash
entc render tests/graphics/mountain/scene.ent --mode native --width 1280 --height 720 --output assets/figures/mountain.png --json
entc bench benchmarks/graphics --modes interpret,ir,native --warmup 1 --iterations 2 --width 320 --height 180 --output assets/benchmarks/graphics.json --json
```

## Architecture

The compiler produces certificate schema v8. Protocol rows add objectives,
milestones, tasks, gates, decisions, and notes to the same proof-carrying path
used by resources, workspace transforms, and machine contracts. Tensor rows add
shape, dtype, gradient, layout, dataset, model, accelerator, training,
canonical, artifact, lowering, executor, and witness contracts.

| Crate | Responsibility |
| --- | --- |
| `ent-parser` / `ent-elab` | Parse `.ent` worlds and lower explicit rows into certificates |
| `ent-kernel` / `ent-proof` | Check relation tables, domain rows, and proof scripts |
| `ent-tensor` | Verify tensor manifests/witnesses and execute checked tensor graphs on CPU |
| `ent-graphics` | Execute `.ent` graphics libraries and write deterministic images |
| `ent-transform` | Apply verified workspace transforms |
| `ent-cli` | Shared command surface for check, build, plan, apply, tensor bench, render, and doctor |

Design notes and research anchors are in `agent-notes/`.
