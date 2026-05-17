# Benchmark Protocol Notes

Entanglement has two benchmark surfaces.

Tensor benchmark:

```bash
entc tensor-bench examples/tensor-xor.ent --iterations 1 --json
```

Graphics benchmark:

```bash
entc bench benchmarks/graphics --modes interpret,ir,native --warmup 1 --iterations 2 --width 320 --height 180 --output assets/benchmarks/graphics.json --json
```

The graphics chart artifact can be regenerated with:

```bash
entc render tests/graphics/benchmark/figure.ent --mode native --width 1280 --height 720 --output assets/figures/benchmark.png --json
```

Benchmarks report workload shape and runtime behavior for local development.
Performance claims should be tied to command line, host, iteration count, and
checked certificate rows.
