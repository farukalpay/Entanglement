# Graphics Runtime Notes

Graphics is one runtime library, alongside tensor execution and workspace
transforms.

`ent-graphics` loads `.ent` functions, resolves `entlib/graphics/*` imports,
evaluates numeric scene code, batches triangles for IR/native modes, and writes
deterministic headless images. The kernel checks only the declared graphics
contracts and proof scripts.

The benchmark figure keeps numeric values in an aligned table inside the chart.
That keeps the rendering fixture readable while the README leads with language
and tensor workflow.
