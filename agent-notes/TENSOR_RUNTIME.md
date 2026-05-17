# Tensor Runtime Notes

The tensor extension is structural. It adds language-level rows for tensors,
accelerators, semantic datasets, bound artifacts, model lowerings, executor
boundaries, runtime witnesses, and training runs, then keeps execution in the
`ent-tensor` library.

`examples/tensor-xor.ent` is the first end-to-end workload:

- Declares concrete f32 tensors and tracked parameters.
- Declares a CPU accelerator capability with supported symbolic ops.
- Declares a semantic dataset row for the training bundle.
- Declares a separate `artifact` row for the runtime-bound dataset manifest.
- Declares a `lowering` row for the expected PyTorch FX primitive trace.
- Declares an `executor` row for the Python runtime boundary.
- Declares a `witness` row for the sealed runtime result.
- Declares an MLP graph using `linear`, `relu`, and
  `softmax_cross_entropy` ops.
- Declares an SGD training contract and proves rows through primitive proof
  scripts, including structural witness/model/lowering and
  witness/training/artifact/executor rules.

The manifest digest is not an inline source-string hash. It is the sha256 of
canonical JSON with schema `ent.tensor-manifest.v1`, including tensor shape,
dtype, layout, and per-tensor byte digests. Generated Python bindings reproduce
that digest before returning runtime tensors to user code.

The runtime currently supports concrete CPU tensors. Future GPU/MPS work should
lower the same model op graph to a public graph backend and preserve the same
certificate rows rather than adding platform-specific syntax.
