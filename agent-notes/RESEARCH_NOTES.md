# Research Notes

These notes explain the architecture choices behind the tensor extension.

- PyTorch autograd records operations during the forward pass and uses the graph
  to compute gradients by reverse traversal. Entanglement adopts that idea in
  `ent-tensor`: runtime values carry op history, and `backward` propagates
  gradients from scalar loss to tracked parameter leaves.
  Source: https://docs.pytorch.org/docs/main/notes/autograd.html
- PyTorch ATen acts as the foundational tensor operation library. Entanglement
  mirrors the separation at a smaller scale: tensor contracts live in the
  compiler certificate, while tensor math and AD live in `ent-tensor` and
  reusable `.ent` helpers under `entlib/tensor/`.
  Source: https://docs.pytorch.org/cppdocs/api/aten/index.html
- TensorFlow graph execution represents operations and tensors as a graph that
  can be saved, optimized, and executed apart from Python. Entanglement uses an
  explicit `.ent` model row with `ops [...]` so the graph is inspectable before
  execution.
  Source: https://www.tensorflow.org/guide/intro_to_graphs
- `tf.function` shows the practical split between eager debugging and graph
  execution. Entanglement keeps the checked graph explicit and leaves future
  lowering/fusion work to runtime backends.
  Source: https://www.tensorflow.org/guide/function
- Apple MPSGraph exposes symbolic compute graphs over tensors and can compile
  them for platform devices. Entanglement models this as a public accelerator
  capability boundary instead of embedding hardware-specific behavior in the
  language kernel.
  Source: https://developer.apple.com/documentation/metalperformanceshadersgraph
- MLX emphasizes unified memory and lazy computation on Apple silicon.
  Entanglement records accelerator memory/precision/supports rows so a future
  backend can make device planning inspectable.
  Source: https://ml-explore.github.io/mlx/build/html/
