# Benchmark Figure Fixture

`figure.ent` is a graphics runtime fixture for chart text, bars, and gridlines.
It is kept under tests so visual output can be regenerated deterministically
when the renderer changes.

```bash
entc render tests/graphics/benchmark/figure.ent --mode native --width 1280 --height 720 --output assets/figures/benchmark.png --json
```

The chart places benchmark values in an aligned table to keep labels readable.
