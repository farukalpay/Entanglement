use ent_core::CERTIFICATE_SCHEMA_VERSION;
use std::fs;
use std::process::Command;

fn entc_command() -> Command {
    if let Some(candidate) = std::env::var("CARGO_BIN_EXE_entc")
        .ok()
        .filter(|path| std::path::Path::new(path).exists())
    {
        Command::new(candidate)
    } else {
        let mut command = Command::new(env!("CARGO"));
        command.args(["run", "-q", "-p", "ent-cli", "--"]);
        command
    }
}

#[test]
fn entc_emits_certificate_and_builds_runtime_bundle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("simulation.ent");
    fs::write(
        &source,
        r#"
world Simulation(agent A, space X) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<A>] preserves truth changes heap[c]
  law step[c] ; step[d] == step[c union d]
  invariant auth_preserved(heap) before 1.0 after 1.0 tolerance 0.0 evidence auth_trace
  effect put uses heap write evidence heap_put_single_writer
  evolve put(dt: f32) by metal differentiable evidence metal_put_contract
  ad put tangent d_put adjoint adj_put law identity evidence put_ad_contract
  evolve secure_eval(dt: f32) by private-ane evidence ane_secure_contract
  measure branch_prob weights allow=0.5, deny=0.5 tolerance 0.000001 evidence branch_mass_trace
  theorem causal_step : dev_frame(step)
  theorem linear_heap : resource_linear(heap)
  theorem branch_mass : probability_normalizes(branch_prob)
  theorem auth_ok : invariant_preserved(auth_preserved)
  theorem put_backend : backend_admissible(put)
  theorem secure_backend : backend_admissible(secure_eval)
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
}
"#,
    )
    .expect("write source");

    let cert = temp.path().join("cert.json");
    let check = entc_command()
        .args(["check", source.to_str().unwrap(), "--json"])
        .output()
        .expect("run entc check");
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let check_json: serde_json::Value =
        serde_json::from_slice(&check.stdout).expect("check --json should print report JSON");
    assert_eq!(check_json["world"], "Simulation");
    assert_eq!(check_json["checked_rows"]["proofs"], 6);

    let emit = entc_command()
        .args([
            "emit-cert",
            source.to_str().unwrap(),
            "--output",
            cert.to_str().unwrap(),
        ])
        .output()
        .expect("run entc emit-cert");
    assert!(
        emit.status.success(),
        "{}",
        String::from_utf8_lossy(&emit.stderr)
    );
    assert!(cert.exists());

    let bundle = temp.path().join(".entgraph");
    let build = entc_command()
        .args([
            "build",
            source.to_str().unwrap(),
            "--target",
            "apple-m4-metal",
            "--ane",
            "private",
            "--output",
            bundle.to_str().unwrap(),
        ])
        .output()
        .expect("run entc build");
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(bundle.join("cert.json").exists());
    assert!(bundle.join("graph.json").exists());
    assert!(bundle.join("manifest.json").exists());
    assert!(bundle.join("kernels/put.metal").exists());
    assert!(bundle.join("ane/secure_eval.mil").exists());
    assert!(bundle.join("checksums.sha256").exists());
    assert!(!bundle.join("render").exists());

    let graph: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(bundle.join("graph.json")).expect("graph json"))
            .expect("parse graph json");
    assert_eq!(graph["requires_private_ane"], true);
    assert_eq!(graph["nodes"][0]["backend"], "metal");
    assert_eq!(graph["nodes"][1]["backend"], "private-ane");

    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(bundle.join("manifest.json")).expect("manifest json"),
    )
    .expect("parse manifest json");
    assert_eq!(manifest["schema_version"], CERTIFICATE_SCHEMA_VERSION);
    assert_eq!(manifest["target"]["platform"], "apple-silicon-macos");
    assert!(manifest["source_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(manifest["certificate_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(manifest["verification_report_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(
        manifest["backend_capabilities"][1]["capability"],
        "private-ane"
    );
    assert_eq!(
        manifest["artifact_checksums"]["graph.json"],
        graph_hash(&bundle)
    );

    let verify_bundle = entc_command()
        .args(["verify-bundle", bundle.to_str().unwrap(), "--json"])
        .output()
        .expect("run entc verify-bundle");
    assert!(
        verify_bundle.status.success(),
        "{}",
        String::from_utf8_lossy(&verify_bundle.stderr)
    );
    let verify_json: serde_json::Value =
        serde_json::from_slice(&verify_bundle.stdout).expect("verify-bundle json");
    assert_eq!(verify_json["world"], "Simulation");
    assert_eq!(verify_json["schema_version"], CERTIFICATE_SCHEMA_VERSION);
    assert_eq!(
        verify_json["certificate_version"],
        CERTIFICATE_SCHEMA_VERSION
    );
    assert_eq!(verify_json["artifact_count"], 5);
    assert_eq!(verify_json["target"]["platform"], "apple-silicon-macos");
}

#[test]
fn entc_builds_linux_cpu_bundle_without_ane_substitution() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("cpu.ent");
    fs::write(
        &source,
        r#"
world CpuOnly(agent A) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<A>] preserves truth changes heap[c]
  law step[c] ; step[d] == step[c union d]
  invariant truth_preserved(truth) before 1.0 after 1.0 tolerance 0.0 evidence truth_trace
  effect eval uses heap read evidence heap_eval_reader
  evolve eval(dt: f32) by cpu evidence cpu_eval_contract
  measure branch_prob weights done=1.0 tolerance 0.000001 evidence deterministic_mass_trace
  theorem causal_step : dev_frame(step)
  theorem mass_branch : probability_normalizes(branch_prob)
  theorem truth_ok : invariant_preserved(truth_preserved)
  theorem eval_backend : backend_admissible(eval)
  proof causal_step {
    let row = row relation step
    let fact = rule dev_frame_from_relation(row)
    qed fact
  }
  proof mass_branch {
    let row = row probability branch_prob
    let fact = rule probability_normalizes_from_probability(row)
    qed fact
  }
  proof truth_ok {
    let row = row invariant truth_preserved
    let fact = rule invariant_preserved_from_invariant(row)
    qed fact
  }
  proof eval_backend {
    let row = row backend eval
    let fact = rule backend_admissible_from_backend(row)
    qed fact
  }
}
"#,
    )
    .expect("write source");

    let bundle = temp.path().join("cpu.entgraph");
    let build = entc_command()
        .args([
            "build",
            source.to_str().unwrap(),
            "--target",
            "linux-cpu",
            "--ane",
            "off",
            "--output",
            bundle.to_str().unwrap(),
        ])
        .output()
        .expect("run entc linux build");
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let graph: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(bundle.join("graph.json")).expect("graph json"))
            .expect("parse graph json");
    assert_eq!(graph["requires_private_ane"], false);
    assert_eq!(graph["nodes"][0]["backend"], "cpu");
    assert!(!bundle.join("ane").exists());

    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(bundle.join("manifest.json")).expect("manifest json"),
    )
    .expect("parse manifest json");
    assert_eq!(manifest["target"]["platform"], "linux");
    assert_eq!(manifest["backend_capabilities"][0]["capability"], "cpu");
}

#[test]
fn entc_renders_previews_and_benchmarks_graphics_sources() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("graphics.ent");
    fs::write(
        &source,
        r#"
world GraphicsSmoke(agent Viewer) {
  state pixels : Resource
  graphics scene entry main evidence graphics_trace {
    fn main() -> f64 {
      begin_frame(width(), height())
      clear(0.02, 0.03, 0.04)
      draw_triangle(8.0, 8.0, 0.5, 0.9, 0.2, 0.2, 56.0, 12.0, 0.5, 0.2, 0.9, 0.2, 20.0, 50.0, 0.5, 0.2, 0.2, 0.9)
      flush()
      return 1.0
    }
  }
  render-target frame width 64 height 64 format rgba8 evidence target_trace
  render-pipeline pipe graphics scene target frame entry main mode native evidence pipe_trace
  benchmark bench graphics scene entry main warmup 0 iterations 1 evidence bench_trace
  theorem scene_ok : graphics_admissible(scene)
  theorem target_ok : render_target_admissible(frame)
  theorem pipe_ok : render_pipeline_admissible(pipe)
  theorem bench_ok : benchmark_admissible(bench)
  proof scene_ok {
    let row = row graphics scene
    let fact = rule graphics_admissible_from_graphics(row)
    qed fact
  }
  proof target_ok {
    let row = row render-target frame
    let fact = rule render_target_admissible_from_render_target(row)
    qed fact
  }
  proof pipe_ok {
    let row = row render-pipeline pipe
    let fact = rule render_pipeline_admissible_from_render_pipeline(row)
    qed fact
  }
  proof bench_ok {
    let row = row benchmark bench
    let fact = rule benchmark_admissible_from_benchmark(row)
    qed fact
  }
}
"#,
    )
    .expect("write graphics source");

    let output = temp.path().join("frame.ppm");
    let render = entc_command()
        .args([
            "render",
            source.to_str().unwrap(),
            "--mode",
            "native",
            "--width",
            "64",
            "--height",
            "64",
            "--output",
            output.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run entc render");
    assert!(
        render.status.success(),
        "{}",
        String::from_utf8_lossy(&render.stderr)
    );
    assert!(output.exists());
    let render_json: serde_json::Value =
        serde_json::from_slice(&render.stdout).expect("render json");
    assert_eq!(render_json["mode"], "native");
    assert!(render_json["triangles_rasterized"].as_u64().unwrap() > 0);

    let preview = entc_command()
        .args([
            "preview",
            source.to_str().unwrap(),
            "--mode",
            "native",
            "--width",
            "64",
            "--height",
            "64",
            "--smoke-test",
            "--json",
        ])
        .output()
        .expect("run entc preview");
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );

    let bench_output = temp.path().join("bench.json");
    let bench = entc_command()
        .args([
            "bench",
            temp.path().to_str().unwrap(),
            "--modes",
            "interpret,ir,native",
            "--warmup",
            "0",
            "--iterations",
            "1",
            "--width",
            "64",
            "--height",
            "64",
            "--output",
            bench_output.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run entc bench");
    assert!(
        bench.status.success(),
        "{}",
        String::from_utf8_lossy(&bench.stderr)
    );
    assert!(bench_output.exists());
    let bench_json: serde_json::Value = serde_json::from_slice(&bench.stdout).expect("bench json");
    assert_eq!(bench_json["files"][0]["modes"].as_array().unwrap().len(), 3);
}

#[test]
fn entc_accepts_explicit_external_boundary_example() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let source = workspace.join("examples/proof-gap.ent");
    let check = entc_command()
        .args(["check", source.to_str().unwrap(), "--json"])
        .output()
        .expect("run entc check");
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let check_json: serde_json::Value =
        serde_json::from_slice(&check.stdout).expect("check --json should print report JSON");
    assert_eq!(check_json["checked_rows"]["external_capabilities"], 1);
    assert_eq!(check_json["checked_rows"]["proofs"], 2);

    let bundle = temp.path().join("external.entgraph");
    let build = entc_command()
        .args([
            "build",
            source.to_str().unwrap(),
            "--target",
            "apple-m4-metal",
            "--ane",
            "off",
            "--output",
            bundle.to_str().unwrap(),
        ])
        .output()
        .expect("run entc build");
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(bundle.join("manifest.json")).expect("manifest json"),
    )
    .expect("parse manifest json");
    assert_eq!(manifest["external_capabilities"][0]["name"], "ffi");
    assert_eq!(
        manifest["external_capabilities"][0]["evidence"],
        "ffi_manifest_trace"
    );
}

#[test]
fn entc_runs_tensor_benchmark_and_reports_editor_tooling() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let source = workspace.join("examples/tensor-xor.ent");

    let check = entc_command()
        .args(["check", source.to_str().unwrap(), "--json"])
        .current_dir(workspace)
        .output()
        .expect("run entc check");
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let check_json: serde_json::Value = serde_json::from_slice(&check.stdout).expect("check json");
    assert_eq!(check_json["checked_rows"]["tensors"], 8);
    assert_eq!(check_json["checked_rows"]["trainings"], 1);
    assert_eq!(check_json["checked_rows"]["artifacts"], 1);
    assert_eq!(check_json["checked_rows"]["witnesses"], 1);

    let verify_artifact = entc_command()
        .args(["verify-artifact", source.to_str().unwrap(), "--json"])
        .current_dir(workspace)
        .output()
        .expect("run entc verify-artifact");
    assert!(
        verify_artifact.status.success(),
        "{}",
        String::from_utf8_lossy(&verify_artifact.stderr)
    );
    let artifact_json: serde_json::Value =
        serde_json::from_slice(&verify_artifact.stdout).expect("artifact json");
    assert_eq!(artifact_json["artifact"], "xor_data_artifact");

    let binding = workspace.join("target/test-ent-xor-contract.py");
    let bind = entc_command()
        .args([
            "bind",
            source.to_str().unwrap(),
            "--target",
            "python",
            "--framework",
            "pytorch_fx",
            "--output",
            binding.to_str().unwrap(),
            "--json",
        ])
        .current_dir(workspace)
        .output()
        .expect("run entc bind");
    assert!(
        bind.status.success(),
        "{}",
        String::from_utf8_lossy(&bind.stderr)
    );
    assert!(binding.exists());

    let verify_witness = entc_command()
        .args([
            "verify-witness",
            source.to_str().unwrap(),
            "examples/artifacts/xor_run.witness.json",
            "--json",
        ])
        .current_dir(workspace)
        .output()
        .expect("run entc verify-witness");
    assert!(
        verify_witness.status.success(),
        "{}",
        String::from_utf8_lossy(&verify_witness.stderr)
    );
    let witness_json: serde_json::Value =
        serde_json::from_slice(&verify_witness.stdout).expect("witness json");
    assert_eq!(witness_json["artifact"], "xor_data_artifact");

    let tensor_bench = entc_command()
        .args([
            "tensor-bench",
            source.to_str().unwrap(),
            "--iterations",
            "1",
            "--json",
        ])
        .current_dir(workspace)
        .output()
        .expect("run entc tensor-bench");
    assert!(
        tensor_bench.status.success(),
        "{}",
        String::from_utf8_lossy(&tensor_bench.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&tensor_bench.stdout).expect("tensor bench JSON");
    assert_eq!(report["backend"]["executor"], "ent-tensor-cpu");
    assert!(
        report["runs"][0]["final_loss"].as_f64().unwrap()
            < report["runs"][0]["first_loss"].as_f64().unwrap()
    );

    let doctor = entc_command()
        .args(["doctor", "--json"])
        .current_dir(workspace)
        .output()
        .expect("run entc doctor");
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let doctor_json: serde_json::Value =
        serde_json::from_slice(&doctor.stdout).expect("doctor JSON");
    assert_eq!(doctor_json["editor"]["file_extensions"][0], ".ent");
}

#[test]
fn entc_machine_check_runs_rocq_backed_riscv_contract() {
    if Command::new("coqc").arg("-v").output().is_err() {
        return;
    }
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let source = workspace.join("examples/riscv-core.ent");

    let machine_check = entc_command()
        .args(["machine-check", source.to_str().unwrap(), "--json"])
        .current_dir(workspace)
        .output()
        .expect("run entc machine-check");
    assert!(
        machine_check.status.success(),
        "{}",
        String::from_utf8_lossy(&machine_check.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&machine_check.stdout).expect("machine-check JSON");
    assert_eq!(report["world"], "RiscVCore");
    assert_eq!(report["checked_rows"]["machines"], 1);
    assert_eq!(report["checked_rows"]["instructions"], 1);
    assert_eq!(report["proof_artifacts"][0]["checked"], true);

    let stress = entc_command()
        .args(["stress", "examples", "--json"])
        .current_dir(workspace)
        .output()
        .expect("run entc stress");
    assert!(
        stress.status.success(),
        "{}",
        String::from_utf8_lossy(&stress.stderr)
    );
    let stress_report: serde_json::Value =
        serde_json::from_slice(&stress.stdout).expect("stress JSON");
    assert!(stress_report["files_checked"].as_u64().unwrap() >= 1);
    assert!(
        stress_report["negative_mutations_rejected"]
            .as_u64()
            .unwrap()
            >= 1
    );
}

#[test]
fn entc_verify_bundle_rejects_tampered_artifacts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("cpu.ent");
    fs::write(
        &source,
        r#"
world CpuOnly(agent A) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<A>] preserves truth changes heap[c]
  law step[c] ; step[d] == step[c union d]
  invariant truth_preserved(truth) before 1.0 after 1.0 tolerance 0.0 evidence truth_trace
  effect eval uses heap read evidence heap_eval_reader
  evolve eval(dt: f32) by cpu evidence cpu_eval_contract
  measure branch_prob weights done=1.0 tolerance 0.000001 evidence deterministic_mass_trace
  theorem causal_step : dev_frame(step)
  theorem mass_branch : probability_normalizes(branch_prob)
  theorem truth_ok : invariant_preserved(truth_preserved)
  theorem eval_backend : backend_admissible(eval)
  proof causal_step {
    let row = row relation step
    let fact = rule dev_frame_from_relation(row)
    qed fact
  }
  proof mass_branch {
    let row = row probability branch_prob
    let fact = rule probability_normalizes_from_probability(row)
    qed fact
  }
  proof truth_ok {
    let row = row invariant truth_preserved
    let fact = rule invariant_preserved_from_invariant(row)
    qed fact
  }
  proof eval_backend {
    let row = row backend eval
    let fact = rule backend_admissible_from_backend(row)
    qed fact
  }
}
"#,
    )
    .expect("write source");

    let bundle = temp.path().join("cpu.entgraph");
    let build = entc_command()
        .args([
            "build",
            source.to_str().unwrap(),
            "--target",
            "linux-cpu",
            "--ane",
            "off",
            "--output",
            bundle.to_str().unwrap(),
        ])
        .output()
        .expect("run entc build");
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );

    fs::write(bundle.join("graph.json"), "{\"tampered\":true}\n").expect("tamper graph");
    let verify_bundle = entc_command()
        .args(["verify-bundle", bundle.to_str().unwrap()])
        .output()
        .expect("run entc verify-bundle");
    assert!(!verify_bundle.status.success());
    assert!(String::from_utf8_lossy(&verify_bundle.stderr).contains("checksum mismatch"));
}

#[test]
fn entc_apply_executes_verified_workspace_transform() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    fs::write(repo.join("README.md"), "keep\nremove legacy\n").expect("readme");
    let source = temp.path().join("cleanup.ent");
    fs::write(
        &source,
        r#"
world CliCleanup(agent Operator) {
  state tree : Resource
  workspace repo uses filesystem write evidence repo_boundary
  select readme = files where file("README.md") evidence explicit_file
  transform cleanup delete_lines on file("README.md") where contains_word("legacy") evidence line_delete
  theorem readme_selection : selection_admissible(readme)
  theorem cleanup_safe : transform_admissible(cleanup)
  proof readme_selection {
    let row = row selection readme
    let fact = rule selection_admissible_from_selection(row)
    qed fact
  }
  proof cleanup_safe {
    let row = row transform cleanup
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
}
"#,
    )
    .expect("source");

    let dry_run = entc_command()
        .args([
            "apply",
            source.to_str().unwrap(),
            "--repo",
            repo.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run entc apply --dry-run");
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_run_report: serde_json::Value =
        serde_json::from_slice(&dry_run.stdout).expect("apply --dry-run --json report");
    assert_eq!(dry_run_report["dry_run"], true);
    assert_eq!(dry_run_report["changed_files"][0]["path"], "README.md");
    assert_eq!(
        fs::read_to_string(repo.join("README.md")).unwrap(),
        "keep\nremove legacy\n"
    );

    let apply = entc_command()
        .args([
            "apply",
            source.to_str().unwrap(),
            "--repo",
            repo.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run entc apply");
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&apply.stdout).expect("apply --json report");
    assert_eq!(report["world"], "CliCleanup");
    assert_eq!(report["changed_files"][0]["path"], "README.md");
    assert_eq!(
        fs::read_to_string(repo.join("README.md")).unwrap(),
        "keep\n"
    );
}

#[test]
fn entc_plan_reports_protocol_rows() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("plan.ent");
    fs::write(
        &source,
        r#"
world PlanRows(role Maintainer, space Workspace) {
  state tree : Resource
  validator cargo_test argv ["cargo", "test"] evidence validator_record
  objective workspace_upgrade priority critical summary "Make checked workspace changes easier to stage and review" evidence roadmap_record
  milestone reviewable_changes objective workspace_upgrade state active due "2026-06-01" evidence schedule_record
  task dry_run_report milestone reviewable_changes kind implement state ready owner maintainer requires [] outputs ["apply-report"] title "Report changes before writing them" evidence task_record
  gate dry_run_checks task dry_run_report check "validator:cargo_test" expect "pass" evidence gate_record
  decision report_shape scope task:dry_run_report choose "reuse apply report" because "one report shape keeps review and write paths comparable" alternatives ["separate summary"] evidence decision_record
  note review_note scope gate:dry_run_checks text "Validators run against the staged tree before writes are materialized" tags [workspace,review] evidence note_record
  theorem validator_safe : validator_admissible(cargo_test)
  theorem objective_safe : objective_admissible(workspace_upgrade)
  theorem milestone_safe : milestone_admissible(reviewable_changes)
  theorem task_safe : task_admissible(dry_run_report)
  theorem gate_safe : gate_admissible(dry_run_checks)
  theorem decision_safe : decision_admissible(report_shape)
  theorem note_safe : note_admissible(review_note)
  proof validator_safe {
    let row = row validator cargo_test
    let fact = rule validator_admissible_from_validator(row)
    qed fact
  }
  proof objective_safe {
    let row = row objective workspace_upgrade
    let fact = rule objective_admissible_from_objective(row)
    qed fact
  }
  proof milestone_safe {
    let row = row milestone reviewable_changes
    let fact = rule milestone_admissible_from_milestone(row)
    qed fact
  }
  proof task_safe {
    let row = row task dry_run_report
    let fact = rule task_admissible_from_task(row)
    qed fact
  }
  proof gate_safe {
    let row = row gate dry_run_checks
    let fact = rule gate_admissible_from_gate(row)
    qed fact
  }
  proof decision_safe {
    let row = row decision report_shape
    let fact = rule decision_admissible_from_decision(row)
    qed fact
  }
  proof note_safe {
    let row = row note review_note
    let fact = rule note_admissible_from_note(row)
    qed fact
  }
}
"#,
    )
    .expect("source");

    let plan = entc_command()
        .args(["plan", source.to_str().unwrap(), "--json"])
        .output()
        .expect("run entc plan");
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&plan.stdout).expect("plan --json report");
    assert_eq!(report["world"], "PlanRows");
    assert_eq!(report["counts"]["tasks"], 1);
    assert_eq!(report["tasks_by_state"]["ready"], 1);
    assert_eq!(
        report["gates_by_task"]["dry_run_report"][0],
        "dry_run_checks"
    );
    assert_eq!(report["checked_rows"]["gates"], 1);
}

#[test]
fn entc_inspect_reports_workspace_map() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("inspectable.ent");
    fs::write(
        &source,
        r#"
world CliInspect(space Workspace) {
  state tree : Resource
}
"#,
    )
    .expect("source");

    let inspect = entc_command()
        .args(["inspect", temp.path().to_str().unwrap(), "--json"])
        .output()
        .expect("run entc inspect");
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&inspect.stdout).expect("inspect --json report");
    assert_eq!(report["summary"]["source_file_count"], 1);
    assert_eq!(report["summary"]["verified_file_count"], 1);
    assert_eq!(report["declaration_counts"]["states"], 1);
    assert_eq!(report["files"][0]["world"], "CliInspect");

    let markdown = temp.path().join("inspect.md");
    let render = entc_command()
        .args([
            "inspect",
            temp.path().to_str().unwrap(),
            "--markdown",
            "--output",
            markdown.to_str().unwrap(),
        ])
        .output()
        .expect("run entc inspect markdown");
    assert!(
        render.status.success(),
        "{}",
        String::from_utf8_lossy(&render.stderr)
    );
    let markdown_text = fs::read_to_string(markdown).expect("markdown");
    assert!(markdown_text.contains("Entanglement Inspection"));
    assert!(markdown_text.contains("inspectable.ent"));
}

fn graph_hash(bundle: &std::path::Path) -> serde_json::Value {
    let checksum_rows =
        fs::read_to_string(bundle.join("checksums.sha256")).expect("checksums should exist");
    let graph_row = checksum_rows
        .lines()
        .find(|line| line.ends_with("  graph.json"))
        .expect("graph checksum row");
    serde_json::Value::String(format!("sha256:{}", &graph_row[..64]))
}
