# Tensor Runtime Notes

The tensor extension is structural. It adds language-level rows for tensors,
accelerators, datasets, models, and training runs, then keeps execution in the
`ent-tensor` library.

`examples/tensor-xor.ent` is the first end-to-end workload:

- Declares concrete f32 tensors and tracked parameters.
- Declares a CPU accelerator capability with supported symbolic ops.
- Declares an inline dataset with a sha256 digest.
- Declares an MLP graph using `linear`, `relu`, and
  `softmax_cross_entropy` ops.
- Declares an SGD training contract and proves each row through primitive proof
  scripts.

The runtime currently supports concrete CPU tensors. Future GPU/MPS work should
lower the same model op graph to a public graph backend and preserve the same
certificate rows rather than adding platform-specific syntax.
