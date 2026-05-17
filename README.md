# Entanglement

Entanglement is a certificate-native systems language prototype. A `.ent` program declares semantic structure, runtime effects, backend contracts, and native proof scripts; the compiler elaborates that structure into a versioned JSON certificate; the Rust kernel accepts only certificate rows and proof steps it can audit mechanically; runtime bundles are loaded only after manifest and checksum verification.

The project is intentionally not a general-purpose theorem prover. Its production contract is narrower and owned end to end: keep the trusted checker small, make every runtime-facing claim explicit, prove claims through Entanglement's own proof calculus, reject opaque gaps, and fail closed when a backend capability cannot be established.

## Quick Start

```bash
cargo run -p ent-cli -- check examples/capability-store.ent
cargo run -p ent-cli -- check examples/proof-gap.ent --json
cargo run -p ent-cli -- check examples/capability-store.ent --json
cargo run -p ent-cli -- emit-cert examples/capability-store.ent --output /tmp/capability-cert.json
cargo run -p ent-cli -- build examples/capability-store.ent --target apple-m4-metal --ane private --output /tmp/capability-store.entgraph
cargo run -p ent-cli -- verify-bundle /tmp/capability-store.entgraph --json
cargo run -p ent-cli -- check examples/repo-cleanup.ent --json
cargo run -p ent-cli -- apply examples/repo-cleanup.ent --repo /path/to/repo --json
cargo run -p ent-cli -- machine-check examples/riscv-core.ent --json
cargo run -p ent-cli -- prove examples/riscv-core.ent --json
cargo run -p ent-cli -- stress examples --json
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift run ent-run /tmp/capability-store.entgraph
```

Linux is supported for the Rust kernel, parser, elaborator, CLI, and CPU-only bundle validation:

```bash
cargo run -p ent-cli -- build examples/cpu-audit.ent --target linux-cpu --ane off --output /tmp/cpu-audit.entgraph
```

Private ANE is a first-class Apple Silicon backend. It is never substituted on Linux and it requires `--ane private` when a certificate contains a `private-ane` backend row.

## RISC-V Machine Contracts

Certificate schema v4 adds explicit machine-level rows. A `.ent` file can now declare an ISA source, memory contract, instruction semantics, ABI boundary, and Rocq proof artifact. The first supported demo is intentionally small: `examples/riscv-core.ent` checks an RV64/Sail-flavored `ADD` instruction contract, a host memory frame, and a Windows x64 ABI skeleton against `proofs/rocq/EntanglementRiscV.v`.

```bash
cargo run -p ent-cli -- machine-check examples/riscv-core.ent --json
cargo run -p ent-cli -- prove examples/riscv-core.ent --json
```

`machine-check` first replays the Rust kernel, then verifies every Rocq artifact digest and runs `coqc`. The kernel itself remains a small row checker: it verifies that machine, memory, instruction, ABI, and proof-artifact rows are explicit, non-ambiguous, and backed by proof obligations; Rocq discharges the semantic proof content.

The Windows row is a structural ABI contract only. It records target triple, PE/COFF object format, calling convention, and external-boundary policy, but the project does not yet claim a Windows runtime loader.

## Surface Example

```ent
world CapabilityStore(agent Client, agent Runtime) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<Client>] preserves truth changes heap[c]
  law step[c] ; step[d] == step[c union d]

  invariant auth_preserved(heap) before 1.0 after 1.0 tolerance 0.0 evidence auth_trace
  effect put uses heap write evidence heap_put_single_writer
  evolve put(dt: f32) by metal differentiable evidence metal_put_contract
  ad put tangent d_put adjoint adj_put law identity evidence put_ad_contract
  evolve secure_eval(dt: f32) by private-ane evidence ane_secure_contract
  measure branch_prob weights allow=0.5, deny=0.5 tolerance 0.000001 evidence branch_mass_trace
  external ffi interface runtime_call uses heap read evidence ffi_manifest_trace

  theorem causal_step : dev_frame(step)
  theorem linear_heap : resource_linear(heap)
  theorem branch_mass : probability_normalizes(branch_prob)
  theorem auth_ok : invariant_preserved(auth_preserved)
  theorem put_backend : backend_admissible(put)
  theorem secure_backend : backend_admissible(secure_eval)
  theorem ffi_boundary : external_admissible(ffi)
  proof causal_step {
    let row = row relation step
    let fact = rule dev_frame_from_relation(row)
    qed fact
  }
  proof linear_heap {
    let row = row resource heap
    let fact = rule resource_linear_from_resource(row)
    qed fact
  }
  proof branch_mass {
    let row = row probability branch_prob
    let fact = rule probability_normalizes_from_probability(row)
    qed fact
  }
  proof auth_ok {
    let row = row invariant auth_preserved
    let fact = rule invariant_preserved_from_invariant(row)
    qed fact
  }
  proof put_backend {
    let row = row backend put
    let fact = rule backend_admissible_from_backend(row)
    qed fact
  }
  proof secure_backend {
    let row = row backend secure_eval
    let fact = rule backend_admissible_from_backend(row)
    qed fact
  }
  proof ffi_boundary {
    let row = row external ffi
    let fact = rule external_admissible_from_external(row)
    qed fact
  }
}
```

Proof blocks are checked scripts, not declarations of trust. A proof first binds a checked certificate row with `let <name> = row <kind> <subject>`, applies one of the kernel's primitive proof rules with `let <name> = rule <rule>(<row>)`, and closes with `qed <fact>`. The resulting proposition must exactly match the theorem. External boundaries are not opaque axioms: they must be declared with `external <name> interface <abi> uses <resource> <read|write> evidence <row>` and then proven through `external_admissible(<name>)`.

## Workspace Transformations

Entanglement can describe repository edits as certificate rows instead of ad hoc CLI scripts. A transform program declares a writable filesystem workspace, explicit parser/document adapters, file selections, transforms, validators, and proof blocks. `entc apply` verifies the `.ent` certificate first, stages changes in a temporary mirror, runs declared validators there, and only then writes the validated file changes back to the target repository.

```ent
world RepoCleanup(agent Operator, space Workspace) {
  state tree : Resource
  state syntax : Semantic

  workspace repo uses filesystem write evidence repo_boundary
  parser rust language rust via tree-sitter evidence rust_parser_contract
  parser c language c via tree-sitter evidence c_parser_contract
  parser cpp language cpp via tree-sitter evidence cpp_parser_contract
  parser ent language ent via native evidence ent_parser_contract
  document markdown via pulldown_cmark evidence markdown_contract

  select native_code = files where parsed_by(rust, c, cpp) evidence native_parser_coverage
  select rust_code = files where parsed_by(rust) evidence rust_parser_coverage
  select ent_code = files where parsed_by(ent) evidence ent_parser_coverage
  select removable_docs = files where markdown_heading("Remove Me") evidence markdown_heading_scope

  transform strip_native_comments remove_comments on native_code evidence native_comment_ranges
  transform strip_ent_comments remove_comments on ent_code evidence ent_comment_ranges
  transform flatten_rust flatten_modules on rust_code into "flat" evidence rust_module_rewrite
  transform drop_docs delete_files on removable_docs evidence doc_delete
  transform readme_lines delete_lines on file("README.md") where contains_word("legacy") evidence line_delete
  transform rename_readme replace_word on file("README.md") from "old" to "new" evidence word_replace
  validator build argv ["cargo", "test"] evidence build_still_passes
}
```

Every parser, selection, transform, and validator row must have a matching proof, using `parser_admissible`, `selection_admissible`, `transform_admissible`, or `validator_admissible`. The complete example is in `examples/repo-cleanup.ent`.

The initial adapter registry is deliberately finite and explicit:

- `rust` via `tree-sitter`: removes Rust comment nodes without touching string literals, validates rewritten syntax, and supports Rust module flattening with `#[path = "..."]` rewrites.
- `c` via `tree-sitter`: removes C comment nodes from `.c` and `.h` files while preserving string literals and validating rewritten syntax.
- `cpp` via `tree-sitter`: removes C++ comment nodes from `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`, and `.hxx` files while preserving string literals and validating rewritten syntax.
- `ent` via `native`: removes `.ent` line comments and replays the native parser before accepting the rewrite.
- `markdown` via `pulldown_cmark`: supports heading-based file selection for document deletion.

Unsupported files or adapters fail closed. For example, selecting Python files for `remove_comments` without a registered parser adapter rejects the whole apply run before target files are changed. If both C and C++ parsers are declared and a `.h` file matches both, apply rejects the ambiguous header instead of silently choosing one grammar; use unambiguous extensions such as `.hpp` or split the selection until a dedicated disambiguation predicate is added.

## Architecture

- `crates/ent-core`: versioned certificate data structures, modal labels, resource/probability/backend/external-capability rows, machine/ABI/proof-artifact rows, native proof certificates, and verification reports.
- `crates/ent-proof`: first-party proof proposition model, proof-script AST, proof-script parser, primitive rule contracts, and proof checker.
- `crates/ent-parser`: span-carrying parser for the `.ent` surface language.
- `crates/ent-elab`: untrusted elaborator from explicit source declarations to certificate v4. It does not synthesize invariant, probability, AD, resource, backend, machine, ABI, external, or proof evidence.
- `crates/ent-kernel`: trusted Rust checker for finite modal relations, union composition, modal truth, coordinate separation, resource linearity, probability normalization, AD rows, backend admissibility, external capability admissibility, machine-contract admissibility, and native/Rocq-backed proof-script validity.
- `crates/ent-opt`: untrusted certificate canonicalizer. Its output is replayed through the kernel before it can be used.
- `crates/ent-transform`: reusable workspace transformation planner/applicator. It consumes only kernel-verified certificate rows, stages repository changes, runs declared validators, and applies validated writes/deletes.
- `crates/ent-cli`: product-facing command line wrapper for checking, certificate emission, and production bundle generation.
- `runtime/Sources/RuntimeKit`: Swift runtime loader for Apple targets. It verifies `manifest.json` artifact hashes before trusting `graph.json`, then probes Metal/private-ANE capability and fails closed.
- `proofs/rocq`: Rocq proof artifacts used by machine-level certificate rows. These are checked by digest and by `coqc` through `entc prove` / `entc machine-check`.

## Bundle Contract

`entc build` emits:

- `cert.json`: checked certificate v4.
- `graph.json`: backend execution graph.
- `resource_layout.json`: runtime resource layout.
- `manifest.json`: schema version, target platform, source hash, certificate hash, verification report hash, resource layout hash, backend capabilities, external capabilities, and artifact checksums.
- `checksums.sha256`: bundle-wide checksums.
- backend artifacts under `kernels/` and, when enabled, `ane/`.

The Swift runtime rejects a bundle if `manifest.json` is missing, malformed, or if any manifest-listed artifact hash does not match.

The Rust CLI can verify the same bundle contract without invoking the Swift runtime:

```bash
cargo run -p ent-cli -- verify-bundle /tmp/capability-store.entgraph
```

## Verification

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift run runtime-self-test
```

The local Command Line Tools Swift toolchain may not expose XCTest. Use the full Xcode developer directory for `swift test` on macOS.

## Trust Boundary

Entanglement's trust boundary is native to this repository: producers may parse, elaborate, canonicalize, and emit bundles, but consumers accept only versioned certificate rows and proof scripts checked by the Rust kernel. Machine-level rows additionally name Rocq proof artifacts by module path, digest, and obligation ids; product-facing commands verify those artifacts with `coqc`. Proof rules are explicit contracts over checked rows, not topic-specific mappings or external proof claims.

The proof calculus is deliberately small. It currently covers the theorem families that affect runtime acceptance, workspace transformation acceptance, and machine-contract acceptance: `dev_frame`, `resource_linear`, `probability_normalizes`, `invariant_preserved`, `backend_admissible`, `external_admissible`, `machine_admissible`, `memory_admissible`, `instruction_refines`, `abi_admissible`, `proof_artifact_checked`, `parser_admissible`, `selection_admissible`, `transform_admissible`, and `validator_admissible`. New theorem families must add a typed proposition, a certificate row contract, a primitive proof rule, and kernel tests before the CLI can emit them.
