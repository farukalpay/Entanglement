use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use ent_core::{BackendKind, CERTIFICATE_SCHEMA_VERSION};
use ent_elab::elaborate_source;
use ent_graphics::{bench_path, render_file, RenderMode, RenderOptions};
use ent_kernel::verify;
use ent_tensor::{run_tensor_benchmark, TensorBenchOptions};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

#[derive(Parser)]
#[command(name = "entc")]
#[command(about = "Entanglement semantic elaborator and verified bundle compiler")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Check {
        source: PathBuf,
        #[arg(long)]
        json: bool,
    },
    EmitCert {
        source: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
    },
    Build {
        source: PathBuf,
        #[arg(long)]
        target: Target,
        #[arg(long, default_value = "off")]
        ane: AneMode,
        #[arg(long, short)]
        output: PathBuf,
    },
    VerifyBundle {
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    MachineCheck {
        source: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Prove {
        source: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Stress {
        corpus: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Apply {
        source: PathBuf,
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Render {
        source: PathBuf,
        #[arg(long, default_value = "native")]
        mode: GraphicsMode,
        #[arg(long)]
        width: u32,
        #[arg(long)]
        height: u32,
        #[arg(long, short)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Preview {
        source: PathBuf,
        #[arg(long, default_value = "native")]
        mode: GraphicsMode,
        #[arg(long)]
        width: u32,
        #[arg(long)]
        height: u32,
        #[arg(long)]
        smoke_test: bool,
        #[arg(long)]
        json: bool,
    },
    Bench {
        path: PathBuf,
        #[arg(long, default_value = "interpret,ir,native")]
        modes: String,
        #[arg(long, default_value_t = 5)]
        warmup: u32,
        #[arg(long, default_value_t = 30)]
        iterations: u32,
        #[arg(long, default_value_t = 640)]
        width: u32,
        #[arg(long, default_value_t = 360)]
        height: u32,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    TensorBench {
        source: PathBuf,
        #[arg(long, default_value_t = 1)]
        iterations: u32,
        #[arg(long)]
        json: bool,
    },
    Doctor {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum Target {
    #[value(name = "apple-m4-metal")]
    AppleM4Metal,
    #[value(name = "macos-cpu")]
    MacosCpu,
    #[value(name = "linux-cpu")]
    LinuxCpu,
    #[value(name = "windows-cpu")]
    WindowsCpu,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
enum AneMode {
    Off,
    Private,
}

#[derive(Clone, Debug, ValueEnum)]
enum GraphicsMode {
    Interpret,
    Ir,
    Native,
}

impl From<GraphicsMode> for RenderMode {
    fn from(value: GraphicsMode) -> Self {
        match value {
            GraphicsMode::Interpret => RenderMode::Interpret,
            GraphicsMode::Ir => RenderMode::Ir,
            GraphicsMode::Native => RenderMode::Native,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check { source, json } => {
            let cert = load_and_elaborate(&source)?;
            let report = verify(&cert)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ACCEPT world={} union_rows={}",
                    report.world, report.checked_rows.union_composition
                );
            }
        }
        Command::EmitCert { source, output } => {
            let cert = load_and_elaborate(&source)?;
            verify(&cert)?;
            write_json(&output, &cert)?;
        }
        Command::Build {
            source,
            target,
            ane,
            output,
        } => {
            let source_bytes = fs::read(&source)
                .with_context(|| format!("failed to read source {}", source.display()))?;
            let cert = elaborate_source(std::str::from_utf8(&source_bytes)?)
                .context("elaboration failed")?;
            let report = verify(&cert)?;
            emit_bundle(&output, target, ane, &source_bytes, &cert, &report)?;
        }
        Command::VerifyBundle { bundle, json } => {
            let report = verify_bundle(&bundle)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "BUNDLE OK world={} artifacts={}",
                    report["world"], report["artifact_count"]
                );
            }
        }
        Command::MachineCheck { source, json } => {
            let cert = load_and_elaborate(&source)?;
            let report = verify(&cert)?;
            let rocq = verify_rocq_artifacts(&source, &cert)?;
            let result = json!({
                "world": report.world,
                "checked_rows": report.checked_rows,
                "machines": cert.machines,
                "memory": cert.memory,
                "instructions": cert.instructions,
                "abis": cert.abis,
                "proof_artifacts": rocq,
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "MACHINE OK world={} machines={} instructions={} rocq_artifacts={}",
                    result["world"],
                    result["machines"].as_array().map_or(0, Vec::len),
                    result["instructions"].as_array().map_or(0, Vec::len),
                    result["proof_artifacts"].as_array().map_or(0, Vec::len)
                );
            }
        }
        Command::Prove { source, json } => {
            let cert = load_and_elaborate(&source)?;
            verify(&cert)?;
            let rocq = verify_rocq_artifacts(&source, &cert)?;
            let result = json!({
                "world": cert.world,
                "proof_artifacts": rocq,
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "PROOF OK world={} rocq_artifacts={}",
                    result["world"],
                    result["proof_artifacts"].as_array().map_or(0, Vec::len)
                );
            }
        }
        Command::Stress { corpus, json } => {
            let result = stress_corpus(&corpus)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "STRESS OK files={} negative_mutations={}",
                    result["files_checked"], result["negative_mutations_rejected"]
                );
            }
        }
        Command::Apply { source, repo, json } => {
            let cert = load_and_elaborate(&source)?;
            verify(&cert)?;
            let report = ent_transform::apply_certificate(&cert, &repo)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "APPLY world={} changed_files={} validators={}",
                    report.world,
                    report.changed_files.len(),
                    report.validators.len()
                );
            }
        }
        Command::Render {
            source,
            mode,
            width,
            height,
            output,
            json,
        } => {
            let mode = RenderMode::from(mode);
            let report = render_file(
                &source,
                RenderOptions {
                    mode,
                    width,
                    height,
                    output: Some(output),
                    source_path: Some(source.clone()),
                    library_roots: vec![],
                    smoke_test: true,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "RENDER OK world={} mode={} triangles={} pixels={}",
                    report.world,
                    report.mode.label(),
                    report.triangles_rasterized,
                    report.pixels_touched
                );
            }
        }
        Command::Preview {
            source,
            mode,
            width,
            height,
            smoke_test,
            json,
        } => {
            let mode = RenderMode::from(mode);
            let report = render_file(
                &source,
                RenderOptions {
                    mode,
                    width,
                    height,
                    output: None,
                    source_path: Some(source.clone()),
                    library_roots: vec![],
                    smoke_test,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "PREVIEW OK world={} mode={} triangles={}",
                    report.world,
                    report.mode.label(),
                    report.triangles_rasterized
                );
            }
        }
        Command::Bench {
            path,
            modes,
            warmup,
            iterations,
            width,
            height,
            output,
            json,
        } => {
            let modes = parse_graphics_modes(&modes)?;
            let report = bench_path(&path, &modes, warmup, iterations, width, height)?;
            if let Some(output) = output {
                write_json(&output, &report)?;
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let file_count = report.files.len();
                println!("BENCH OK files={file_count} modes={}", modes.len());
            }
        }
        Command::TensorBench {
            source,
            iterations,
            json,
        } => {
            let report = run_tensor_benchmark(&source, TensorBenchOptions { iterations })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let last = report
                    .runs
                    .last()
                    .context("tensor benchmark produced no runs")?;
                println!(
                    "TENSOR OK world={} training={} final_loss={:.6} executor={}",
                    report.world, report.training, last.final_loss, report.backend.executor
                );
            }
        }
        Command::Doctor { json } => {
            let report = doctor_report();
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ENTC platform={} arch={} targets={} extension={}",
                    report["host"]["os"],
                    report["host"]["arch"],
                    report["targets"].as_array().map_or(0, Vec::len),
                    report["editor"]["vscode_extension"]
                );
            }
        }
    }
    Ok(())
}

fn parse_graphics_modes(input: &str) -> Result<Vec<RenderMode>> {
    input
        .split(',')
        .map(str::trim)
        .filter(|mode| !mode.is_empty())
        .map(|mode| match mode {
            "interpret" => Ok(RenderMode::Interpret),
            "ir" => Ok(RenderMode::Ir),
            "native" => Ok(RenderMode::Native),
            other => anyhow::bail!("unsupported graphics mode: {other}"),
        })
        .collect()
}

fn doctor_report() -> Value {
    let workspace = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| ".".to_owned());
    json!({
        "host": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "toolchain": {
            "entc": env!("CARGO_PKG_VERSION"),
            "rustc": rustc_version(),
        },
        "targets": [
            target_manifest(&Target::MacosCpu),
            target_manifest(&Target::LinuxCpu),
            target_manifest(&Target::WindowsCpu),
            target_manifest(&Target::AppleM4Metal),
        ],
        "commands": {
            "check": "entc check path/to/main.ent",
            "build_cpu": "entc build path/to/main.ent --target linux-cpu --output build/main.entgraph",
            "tensor_bench": "entc tensor-bench path/to/model.ent --json",
        },
        "editor": {
            "vscode_extension": format!("{workspace}/tooling/vscode/entanglement"),
            "language_id": "entanglement",
            "file_extensions": [".ent"],
        }
    })
}

fn load_and_elaborate(path: &Path) -> Result<ent_core::Certificate> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read source {}", path.display()))?;
    elaborate_source(&source).context("elaboration failed")
}

fn emit_bundle(
    output: &Path,
    target: Target,
    ane: AneMode,
    source_bytes: &[u8],
    cert: &ent_core::Certificate,
    report: &ent_core::VerificationReport,
) -> Result<()> {
    validate_target_backend_policy(&target, &ane, cert)?;
    if output.exists() {
        fs::remove_dir_all(output)
            .with_context(|| format!("failed to clear bundle {}", output.display()))?;
    }
    fs::create_dir_all(output.join("kernels"))?;
    if ane == AneMode::Private {
        fs::create_dir_all(output.join("ane"))?;
    }

    write_json(&output.join("cert.json"), cert)?;
    let nodes = cert
        .backends
        .iter()
        .map(|backend| {
            json!({
                "id": backend.node,
                "backend": backend_label(&backend.backend),
                "differentiable": cert.ad.iter().any(|row| row.primal == backend.node),
            })
        })
        .collect::<Vec<_>>();
    write_json(
        &output.join("graph.json"),
        &json!({
            "world": cert.world,
            "target": target_label(&target),
            "ane_mode": ane_label(&ane),
            "requires_private_ane": cert.backends.iter().any(|backend| matches!(&backend.backend, BackendKind::PrivateAne)),
            "verified_rows": report.checked_rows,
            "external_capabilities": external_capability_rows(cert),
            "tensors": &cert.tensors,
            "accelerators": &cert.accelerators,
            "datasets": cert.datasets.iter().map(|dataset| {
                json!({
                    "name": &dataset.name,
                    "tensors": &dataset.tensors,
                    "source_digest": &dataset.source_digest,
                    "evidence": &dataset.evidence,
                })
            }).collect::<Vec<_>>(),
            "models": &cert.models,
            "trainings": &cert.trainings,
            "nodes": nodes,
        }),
    )?;
    write_json(
        &output.join("resource_layout.json"),
        &json!({
            "unified_memory": true,
            "resources": cert.resources,
            "external_capabilities": external_capability_rows(cert),
            "synchronization": "verified-graph-dependencies",
        }),
    )?;
    for backend in &cert.backends {
        let artifact = artifact_name(&backend.node);
        match &backend.backend {
            BackendKind::Metal => {
                fs::write(
                    output.join(format!("kernels/{artifact}.metal")),
                    metal_kernel(&backend.node),
                )?;
            }
            BackendKind::PrivateAne if ane == AneMode::Private => {
                fs::write(
                    output.join(format!("ane/{artifact}.mil")),
                    private_ane_mil(&backend.node),
                )?;
            }
            BackendKind::PrivateAne | BackendKind::Cpu => {}
            BackendKind::Capability(_) => {}
        }
    }
    let artifact_checksums = artifact_checksums(output)?;
    write_json(
        &output.join("manifest.json"),
        &json!({
            "schema_version": CERTIFICATE_SCHEMA_VERSION,
            "world": cert.world,
            "target": target_manifest(&target),
            "ane_mode": ane_label(&ane),
            "source_hash": format!("sha256:{}", sha256_hex(source_bytes)),
            "certificate_hash": file_sha256_uri(&output.join("cert.json"))?,
            "verification_report_hash": format!("sha256:{}", sha256_json(report)?),
            "resource_layout_hash": file_sha256_uri(&output.join("resource_layout.json"))?,
            "toolchain": {
                "entanglement": env!("CARGO_PKG_VERSION"),
                "rustc": rustc_version(),
            },
            "backend_capabilities": cert.backends.iter().map(|backend| {
                json!({
                    "node": backend.node,
                    "capability": backend_label(&backend.backend),
                    "evidence": backend.evidence,
                    "admissible": backend.admissible,
                })
            }).collect::<Vec<_>>(),
            "tensor_capabilities": {
                "tensors": &cert.tensors,
                "accelerators": &cert.accelerators,
                "models": &cert.models,
                "trainings": &cert.trainings,
            },
            "external_capabilities": external_capability_rows(cert),
            "artifact_checksums": artifact_checksums,
        }),
    )?;
    write_checksums(output)?;
    Ok(())
}

fn validate_target_backend_policy(
    target: &Target,
    ane: &AneMode,
    cert: &ent_core::Certificate,
) -> Result<()> {
    let has_private_ane = cert
        .backends
        .iter()
        .any(|backend| matches!(backend.backend, BackendKind::PrivateAne));
    let has_non_cpu = cert
        .backends
        .iter()
        .any(|backend| !matches!(backend.backend, BackendKind::Cpu));
    match target {
        Target::AppleM4Metal => {
            if has_private_ane && ane != &AneMode::Private {
                anyhow::bail!(
                    "private ANE backend requires --ane private for apple-m4-metal target"
                );
            }
        }
        Target::MacosCpu | Target::LinuxCpu | Target::WindowsCpu => {
            if has_private_ane || has_non_cpu || ane != &AneMode::Off {
                anyhow::bail!("portable CPU targets accept only CPU backends and --ane off");
            }
        }
    }
    Ok(())
}

fn verify_bundle(bundle: &Path) -> Result<Value> {
    let manifest_path = bundle.join("manifest.json");
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?,
    )
    .context("failed to parse manifest.json")?;
    if manifest["schema_version"] != CERTIFICATE_SCHEMA_VERSION {
        anyhow::bail!("unsupported bundle manifest schema version");
    }

    verify_manifest_hash_field(bundle, &manifest, "certificate_hash", "cert.json")?;
    verify_manifest_hash_field(
        bundle,
        &manifest,
        "resource_layout_hash",
        "resource_layout.json",
    )?;

    let artifact_checksums = manifest
        .get("artifact_checksums")
        .and_then(Value::as_object)
        .context("manifest lacks artifact_checksums object")?;
    let checksum_rows = read_checksum_rows(&bundle.join("checksums.sha256"))?;
    for (file, expected_value) in artifact_checksums {
        let expected = expected_value
            .as_str()
            .with_context(|| format!("artifact checksum for {file} is not a string"))?;
        let actual = file_sha256_uri(&bundle.join(file))?;
        if actual != expected {
            anyhow::bail!("checksum mismatch for {file}: expected {expected}, got {actual}");
        }
        if let Some(checksum_row) = checksum_rows.get(file) {
            let checksum_uri = format!("sha256:{checksum_row}");
            if checksum_uri != expected {
                anyhow::bail!(
                    "checksum mismatch for {file}: manifest has {expected}, checksums.sha256 has {checksum_uri}"
                );
            }
        } else {
            anyhow::bail!("checksums.sha256 lacks artifact row for {file}");
        }
    }

    let cert: ent_core::Certificate = serde_json::from_str(
        &fs::read_to_string(bundle.join("cert.json")).context("failed to read cert.json")?,
    )
    .context("failed to parse cert.json")?;
    let kernel_report = verify(&cert).context("bundle certificate rejected by kernel")?;

    Ok(json!({
        "schema_version": CERTIFICATE_SCHEMA_VERSION,
        "world": manifest["world"],
        "target": manifest["target"],
        "artifact_count": artifact_checksums.len(),
        "certificate_version": cert.version,
        "checked_rows": kernel_report.checked_rows,
    }))
}

fn verify_rocq_artifacts(source: &Path, cert: &ent_core::Certificate) -> Result<Vec<Value>> {
    let repo_root = std::env::current_dir().context("failed to determine current directory")?;
    let source_dir = source.parent().unwrap_or_else(|| Path::new("."));
    cert.proof_artifacts
        .iter()
        .map(|artifact| {
            if !matches!(&artifact.prover, ent_core::ProverKind::Rocq) {
                anyhow::bail!("unsupported prover for artifact {}", artifact.name);
            }
            let source_relative = source_dir.join(&artifact.module);
            let module_path = if source_relative.exists() {
                source_relative
            } else {
                repo_root.join(&artifact.module)
            };
            let actual = file_sha256_uri(&module_path).with_context(|| {
                format!(
                    "failed to hash Rocq proof artifact {} at {}",
                    artifact.name,
                    module_path.display()
                )
            })?;
            if actual != artifact.digest {
                anyhow::bail!(
                    "Rocq proof artifact {} digest mismatch: expected {}, got {}",
                    artifact.name,
                    artifact.digest,
                    actual
                );
            }
            let output = ProcessCommand::new("coqc")
                .arg(&module_path)
                .output()
                .with_context(|| {
                    format!(
                        "failed to run coqc for Rocq proof artifact {}",
                        artifact.name
                    )
                })?;
            if !output.status.success() {
                anyhow::bail!(
                    "coqc rejected {}: {}{}",
                    artifact.module,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Ok(json!({
                "name": artifact.name,
                "prover": "rocq",
                "module": artifact.module,
                "digest": artifact.digest,
                "obligations": artifact.obligations,
                "checked": true,
            }))
        })
        .collect()
}

fn stress_corpus(corpus: &Path) -> Result<Value> {
    let mut files = Vec::new();
    collect_ent_sources(corpus, &mut files)?;
    files.sort();
    let mut mutation_rejections = 0usize;
    for file in &files {
        let source = fs::read_to_string(file)
            .with_context(|| format!("failed to read stress source {}", file.display()))?;
        let cert = elaborate_source(&source)
            .with_context(|| format!("stress source failed to elaborate: {}", file.display()))?;
        verify(&cert).with_context(|| format!("stress source rejected: {}", file.display()))?;
        mutation_rejections += stress_negative_mutations(&source, file)?;
    }
    Ok(json!({
        "files_checked": files.len(),
        "negative_mutations_rejected": mutation_rejections,
    }))
}

fn collect_ent_sources(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if dir.is_file() {
        if dir.extension().is_some_and(|extension| extension == "ent") {
            files.push(dir.to_path_buf());
        }
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_ent_sources(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "ent") {
            files.push(path);
        }
    }
    Ok(())
}

fn stress_negative_mutations(source: &str, file: &Path) -> Result<usize> {
    let mut rejected = 0usize;
    let mutations = [
        source.replacen(" evidence ", " ", 1),
        source.replacen("qed ", "stuck ", 1),
    ];
    for mutated in mutations {
        if mutated == source {
            continue;
        }
        let accepted = elaborate_source(&mutated)
            .ok()
            .and_then(|cert| verify(&cert).ok())
            .is_some();
        if accepted {
            anyhow::bail!(
                "stress mutation unexpectedly verified for {}",
                file.display()
            );
        } else {
            rejected += 1;
        }
    }
    Ok(rejected)
}

fn verify_manifest_hash_field(
    bundle: &Path,
    manifest: &Value,
    field: &str,
    file: &str,
) -> Result<()> {
    let expected = manifest
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("manifest lacks {field}"))?;
    let actual = file_sha256_uri(&bundle.join(file))?;
    if actual != expected {
        anyhow::bail!("checksum mismatch for {file}: expected {expected}, got {actual}");
    }
    Ok(())
}

fn read_checksum_rows(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut rows = BTreeMap::new();
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let (digest, file) = line
            .split_once("  ")
            .with_context(|| format!("malformed checksum row: {line}"))?;
        rows.insert(file.to_owned(), digest.to_owned());
    }
    Ok(rows)
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, format!("{json}\n"))?;
    Ok(())
}

fn metal_kernel(node: &str) -> String {
    format!(
        r#"#include <metal_stdlib>
using namespace metal;

kernel void {kernel_name}(device const float* input [[buffer(0)]],
                          device float* output [[buffer(1)]],
                          uint id [[thread_position_in_grid]]) {{
    output[id] = input[id];
}}
"#,
        kernel_name = artifact_name(node)
    )
}

fn private_ane_mil(node: &str) -> String {
    format!(
        r#"# Entanglement private ANE boundary artifact.
# Emitted only for certificate rows that explicitly target the private ANE backend.
program {program_name}(%x: tensor<1xf16>) -> tensor<1xf16> {{
  return %x
}}
"#,
        program_name = artifact_name(node)
    )
}

fn artifact_name(name: &str) -> String {
    let sanitized = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "node".to_owned()
    } else {
        sanitized
    }
}

fn backend_label(kind: &BackendKind) -> String {
    match kind {
        BackendKind::Cpu => "cpu".to_owned(),
        BackendKind::Metal => "metal".to_owned(),
        BackendKind::PrivateAne => "private-ane".to_owned(),
        BackendKind::Capability(name) => name.clone(),
    }
}

fn resource_access_label(access: &ent_core::ResourceAccess) -> &'static str {
    match access {
        ent_core::ResourceAccess::Read => "read",
        ent_core::ResourceAccess::Write => "write",
    }
}

fn external_capability_rows(cert: &ent_core::Certificate) -> Vec<Value> {
    cert.external_capabilities
        .iter()
        .map(|external| {
            json!({
                "name": external.name,
                "interface": external.interface,
                "resource": external.resource,
                "access": resource_access_label(&external.access),
                "evidence": external.evidence,
                "admissible": external.admissible,
            })
        })
        .collect()
}

fn target_label(target: &Target) -> &'static str {
    match target {
        Target::AppleM4Metal => "apple-m4-metal",
        Target::MacosCpu => "macos-cpu",
        Target::LinuxCpu => "linux-cpu",
        Target::WindowsCpu => "windows-cpu",
    }
}

fn ane_label(ane: &AneMode) -> &'static str {
    match ane {
        AneMode::Off => "off",
        AneMode::Private => "private",
    }
}

fn target_manifest(target: &Target) -> Value {
    match target {
        Target::AppleM4Metal => json!({
            "id": "apple-m4-metal",
            "platform": "apple-silicon-macos",
            "architecture": "arm64",
        }),
        Target::MacosCpu => json!({
            "id": "macos-cpu",
            "platform": "macos",
            "architecture": "portable-cpu",
        }),
        Target::LinuxCpu => json!({
            "id": "linux-cpu",
            "platform": "linux",
            "architecture": "portable-cpu",
        }),
        Target::WindowsCpu => json!({
            "id": "windows-cpu",
            "platform": "windows",
            "architecture": "portable-cpu",
        }),
    }
}

fn artifact_checksums(root: &Path) -> Result<Map<String, Value>> {
    let mut rows = Vec::new();
    collect_artifact_checksum_rows(root, root, &mut rows)?;
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(rows
        .into_iter()
        .map(|(file, digest)| (file, Value::String(format!("sha256:{digest}"))))
        .collect())
}

fn collect_artifact_checksum_rows(
    root: &Path,
    dir: &Path,
    rows: &mut Vec<(String, String)>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_artifact_checksum_rows(root, &path, rows)?;
            continue;
        }
        let relative = path.strip_prefix(root)?;
        if relative == Path::new("checksums.sha256") || relative == Path::new("manifest.json") {
            continue;
        }
        let file = relative.to_string_lossy().replace('\\', "/");
        rows.push((file, file_sha256_hex(&path)?));
    }
    Ok(())
}

fn file_sha256_uri(path: &Path) -> Result<String> {
    Ok(format!("sha256:{}", file_sha256_hex(path)?))
}

fn file_sha256_hex(path: &Path) -> Result<String> {
    Ok(sha256_hex(&fs::read(path)?))
}

fn sha256_json<T: serde::Serialize>(value: &T) -> Result<String> {
    Ok(sha256_hex(serde_json::to_string_pretty(value)?.as_bytes()))
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}

fn rustc_version() -> String {
    ProcessCommand::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn write_checksums(root: &Path) -> Result<()> {
    let mut rows = Vec::new();
    collect_checksum_rows(root, root, &mut rows)?;
    rows.sort();
    fs::write(
        root.join("checksums.sha256"),
        format!("{}\n", rows.join("\n")),
    )?;
    Ok(())
}

fn collect_checksum_rows(root: &Path, dir: &Path, rows: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_checksum_rows(root, &path, rows)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .expect("checksum traversal remains under root");
        if relative == Path::new("checksums.sha256") {
            continue;
        }
        let file = relative.to_string_lossy().replace('\\', "/");
        let bytes = fs::read(&path)?;
        let digest = Sha256::digest(bytes);
        rows.push(format!("{digest:x}  {file}"));
    }
    Ok(())
}
