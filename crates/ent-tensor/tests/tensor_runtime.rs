use ent_tensor::{run_tensor_benchmark, TensorBenchOptions};

#[test]
fn tensor_runtime_trains_xor_contract() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let report = run_tensor_benchmark(
        &workspace.join("examples/tensor-xor.ent"),
        TensorBenchOptions { iterations: 1 },
    )
    .expect("tensor benchmark runs");

    assert_eq!(report.world, "TensorXor");
    assert_eq!(report.backend.executor, "ent-tensor-cpu");
    assert_eq!(report.op_count, 4);
    assert_eq!(report.parameter_count, 4);
    assert!(report.runs[0].final_loss < report.runs[0].first_loss);
}
