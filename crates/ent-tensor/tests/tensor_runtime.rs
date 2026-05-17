use ent_tensor::{
    generate_python_binding, run_tensor_benchmark, verify_artifact_manifest, verify_witness,
    TensorBenchOptions,
};

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

#[test]
fn tensor_runtime_verifies_artifact_witness_and_binding() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let source = workspace.join("examples/tensor-xor.ent");
    let witness = workspace.join("examples/artifacts/xor_run.witness.json");

    let artifact = verify_artifact_manifest(&source, None).expect("artifact manifest verifies");
    assert_eq!(artifact.artifact, "xor_data_artifact");
    assert_eq!(artifact.tensors.len(), 2);

    let witness_report = verify_witness(&source, &witness).expect("runtime witness verifies");
    assert_eq!(witness_report.artifact, "xor_data_artifact");
    assert_eq!(witness_report.trace_ops.len(), 6);

    let out = workspace.join("target/test-ent-xor-contract.py");
    let binding =
        generate_python_binding(&source, &out, "pytorch_fx").expect("binding should generate");
    assert_eq!(binding.artifact, "xor_data_artifact");
    assert!(out.exists());
}
