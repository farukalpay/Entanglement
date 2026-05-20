use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use ent_core::{BackendKind, CERTIFICATE_SCHEMA_VERSION};
use ent_elab::elaborate_source;
use ent_graphics::{bench_path, render_file, RenderMode, RenderOptions};
use ent_inspect::{inspect_path, render_markdown, InspectOptions};
use ent_kernel::verify;
use ent_native_audit::{
    audit_native_path, has_blocking_findings, render_markdown as render_native_markdown,
    NativeAuditOptions, NativeReadinessStatus,
};
use ent_runtime_audit::{
    audit_runtime_path, has_blocking_findings as has_runtime_blocking_findings,
    render_markdown as render_runtime_markdown, RuntimeAuditOptions, RuntimeReadinessStatus,
};
use ent_tensor::{
    generate_python_binding, run_tensor_benchmark, verify_artifact_manifest, verify_witness,
    TensorBenchOptions,
};
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
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    Plan {
        source: PathBuf,
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
    VerifyArtifact {
        source: PathBuf,
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    VerifyWitness {
        source: PathBuf,
        witness: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Bind {
        source: PathBuf,
        #[arg(long)]
        target: BindingTarget,
        #[arg(long)]
        framework: String,
        #[arg(long, short)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Inspect {
        path: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        markdown: bool,
        #[arg(long, short)]
        output: Option<PathBuf>,
        #[arg(long)]
        include_hidden: bool,
        #[arg(long)]
        max_file_bytes: Option<u64>,
        #[arg(long)]
        fail_on_diagnostics: bool,
    },
    NativeAudit {
        path: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        markdown: bool,
        #[arg(long, short)]
        output: Option<PathBuf>,
        #[arg(long)]
        include_hidden: bool,
        #[arg(long)]
        max_file_bytes: Option<u64>,
        #[arg(long)]
        exclude_tests: bool,
        #[arg(long)]
        fail_on_findings: bool,
    },
    RuntimeAudit {
        path: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        markdown: bool,
        #[arg(long, short)]
        output: Option<PathBuf>,
        #[arg(long)]
        include_hidden: bool,
        #[arg(long)]
        max_file_bytes: Option<u64>,
        #[arg(long)]
        fail_on_findings: bool,
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

#[derive(Clone, Debug, ValueEnum)]
enum BindingTarget {
    Python,
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
        Command::Apply {
            source,
            repo,
            dry_run,
            json,
        } => {
            let cert = load_and_elaborate(&source)?;
            verify(&cert)?;
            let report = ent_transform::apply_certificate_with_options(
                &cert,
                &repo,
                ent_transform::ApplyOptions { dry_run },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "APPLY world={} dry_run={} changed_files={} validators={}",
                    report.world,
                    report.dry_run,
                    report.changed_files.len(),
                    report.validators.len()
                );
            }
        }
        Command::Plan { source, json } => {
            let cert = load_and_elaborate(&source)?;
            let report = verify(&cert)?;
            let result = protocol_report(&cert, &report);
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "PLAN OK world={} objectives={} milestones={} tasks={} gates={} runtime_turns={} runtime_tools={}",
                    result["world"],
                    result["counts"]["objectives"],
                    result["counts"]["milestones"],
                    result["counts"]["tasks"],
                    result["counts"]["gates"],
                    result["counts"]["runtime_turns"],
                    result["counts"]["runtime_tools"]
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
        Command::VerifyArtifact {
            source,
            manifest,
            json,
        } => {
            let report = verify_artifact_manifest(&source, manifest.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ARTIFACT OK world={} artifact={} tensors={}",
                    report.world,
                    report.artifact,
                    report.tensors.len()
                );
            }
        }
        Command::VerifyWitness {
            source,
            witness,
            json,
        } => {
            let report = verify_witness(&source, &witness)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "WITNESS OK world={} witness={} trace_ops={}",
                    report.world,
                    report.witness,
                    report.trace_ops.len()
                );
            }
        }
        Command::Bind {
            source,
            target,
            framework,
            output,
            json,
        } => {
            let report = match target {
                BindingTarget::Python => generate_python_binding(&source, &output, &framework)?,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "BIND OK world={} target=python framework={} output={}",
                    report.world,
                    report.framework,
                    report.output.display()
                );
            }
        }
        Command::Inspect {
            path,
            json,
            markdown,
            output,
            include_hidden,
            max_file_bytes,
            fail_on_diagnostics,
        } => {
            if json && markdown {
                anyhow::bail!("choose either --json or --markdown, not both");
            }
            let options = InspectOptions {
                recursive: true,
                include_hidden,
                follow_symlinks: false,
                max_file_bytes: max_file_bytes.or(Some(4 * 1024 * 1024)),
            };
            let report = inspect_path(&path, options)?;
            let rendered = if json {
                format!("{}\n", serde_json::to_string_pretty(&report)?)
            } else if markdown {
                render_markdown(&report)
            } else {
                format!(
                    "INSPECT sources={} inspected={} verified={} mapped={} diagnostics={} declarations={} references={}\n",
                    report.summary.source_file_count,
                    report.summary.inspected_file_count,
                    report.summary.verified_file_count,
                    report.summary.mapped_file_count,
                    report.summary.diagnostic_count,
                    report.summary.declaration_count,
                    report.summary.reference_count
                )
            };
            if let Some(output) = output {
                write_text(&output, &rendered)?;
            } else {
                print!("{rendered}");
            }
            if fail_on_diagnostics && report.summary.error_count > 0 {
                anyhow::bail!(
                    "workspace inspection found {} blocking diagnostic(s)",
                    report.summary.error_count
                );
            }
        }
        Command::NativeAudit {
            path,
            json,
            markdown,
            output,
            include_hidden,
            max_file_bytes,
            exclude_tests,
            fail_on_findings,
        } => {
            if json && markdown {
                anyhow::bail!("choose either --json or --markdown, not both");
            }
            let report = audit_native_path(
                &path,
                NativeAuditOptions {
                    recursive: true,
                    include_hidden,
                    follow_symlinks: false,
                    max_file_bytes: max_file_bytes.or(Some(4 * 1024 * 1024)),
                    include_tests: !exclude_tests,
                },
            )?;
            let rendered = if json {
                format!("{}\n", serde_json::to_string_pretty(&report)?)
            } else if markdown {
                render_native_markdown(&report)
            } else {
                format!(
                    "NATIVE OK sources={} audited={} status={} public={} exported={} foreign={} findings={}\n",
                    report.summary.source_file_count,
                    report.summary.audited_file_count,
                    native_status_label(report.readiness.status),
                    report.summary.public_symbol_count,
                    report.summary.exported_symbol_count,
                    report.summary.foreign_symbol_count,
                    report.summary.finding_count
                )
            };
            if let Some(output) = output {
                write_text(&output, &rendered)?;
            } else {
                print!("{rendered}");
            }
            if fail_on_findings && has_blocking_findings(&report) {
                anyhow::bail!("native audit found blocking finding(s)");
            }
        }
        Command::RuntimeAudit {
            path,
            json,
            markdown,
            output,
            include_hidden,
            max_file_bytes,
            fail_on_findings,
        } => {
            if json && markdown {
                anyhow::bail!("choose either --json or --markdown, not both");
            }
            let report = audit_runtime_path(
                &path,
                RuntimeAuditOptions {
                    recursive: true,
                    include_hidden,
                    follow_symlinks: false,
                    max_file_bytes: max_file_bytes.or(Some(4 * 1024 * 1024)),
                },
            )?;
            let rendered = if json {
                format!("{}\n", serde_json::to_string_pretty(&report)?)
            } else if markdown {
                render_runtime_markdown(&report)
            } else {
                format!(
                    "RUNTIME OK sources={} audited={} status={} crates={} components={} flows={} findings={}\n",
                    report.summary.source_file_count,
                    report.summary.audited_file_count,
                    runtime_status_label(report.readiness.status),
                    report.summary.crate_count,
                    report.summary.component_count,
                    report.summary.flow_count,
                    report.summary.finding_count
                )
            };
            if let Some(output) = output {
                write_text(&output, &rendered)?;
            } else {
                print!("{rendered}");
            }
            if fail_on_findings && has_runtime_blocking_findings(&report) {
                anyhow::bail!("runtime audit found blocking finding(s)");
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

fn protocol_report(cert: &ent_core::Certificate, report: &ent_core::VerificationReport) -> Value {
    let mut tasks_by_state: BTreeMap<String, usize> = BTreeMap::new();
    let mut tasks_by_milestone: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut gates_by_task: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut claims_by_lane: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut handoffs_by_lane: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut syncs_by_lane: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut checkpoints_by_lane: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for task in &cert.tasks {
        *tasks_by_state.entry(task.state.clone()).or_default() += 1;
        tasks_by_milestone
            .entry(task.milestone.clone())
            .or_default()
            .push(task.name.as_str());
    }
    for gate in &cert.gates {
        gates_by_task
            .entry(gate.task.clone())
            .or_default()
            .push(gate.name.as_str());
    }
    for claim in &cert.claims {
        claims_by_lane
            .entry(claim.lane.clone())
            .or_default()
            .push(claim.name.as_str());
    }
    for handoff in &cert.handoffs {
        handoffs_by_lane
            .entry(handoff.from.clone())
            .or_default()
            .push(handoff.name.as_str());
        handoffs_by_lane
            .entry(handoff.to.clone())
            .or_default()
            .push(handoff.name.as_str());
    }
    for sync in &cert.syncs {
        syncs_by_lane
            .entry(sync.source.clone())
            .or_default()
            .push(sync.name.as_str());
        syncs_by_lane
            .entry(sync.target.clone())
            .or_default()
            .push(sync.name.as_str());
    }
    for checkpoint in &cert.checkpoints {
        checkpoints_by_lane
            .entry(checkpoint.lane.clone())
            .or_default()
            .push(checkpoint.name.as_str());
    }
    let dependency_edges = cert
        .tasks
        .iter()
        .flat_map(|task| {
            task.requires.iter().map(move |dependency| {
                json!({
                    "from": dependency,
                    "to": task.name,
                })
            })
        })
        .collect::<Vec<_>>();
    let coordination_edges = cert
        .claims
        .iter()
        .map(|claim| {
            json!({
                "kind": "claim",
                "from": claim.lane,
                "to": claim.scope,
                "name": claim.name,
            })
        })
        .chain(cert.handoffs.iter().map(|handoff| {
            json!({
                "kind": "handoff",
                "from": handoff.from,
                "to": handoff.to,
                "name": handoff.name,
                "item": handoff.item,
            })
        }))
        .chain(cert.syncs.iter().map(|sync| {
            json!({
                "kind": "sync",
                "from": sync.source,
                "to": sync.target,
                "name": sync.name,
            })
        }))
        .collect::<Vec<_>>();

    json!({
        "world": cert.world,
        "counts": {
            "objectives": cert.objectives.len(),
            "milestones": cert.milestones.len(),
            "tasks": cert.tasks.len(),
            "gates": cert.gates.len(),
            "decisions": cert.decisions.len(),
            "notes": cert.notes.len(),
            "lanes": cert.lanes.len(),
            "claims": cert.claims.len(),
            "handoffs": cert.handoffs.len(),
            "syncs": cert.syncs.len(),
            "checkpoints": cert.checkpoints.len(),
            "runtime_ledgers": cert.runtime_ledgers.len(),
            "runtime_policies": cert.runtime_policies.len(),
            "runtime_sessions": cert.runtime_sessions.len(),
            "runtime_tools": cert.runtime_tools.len(),
            "runtime_turns": cert.runtime_turns.len(),
            "runtime_hooks": cert.runtime_hooks.len(),
            "runtime_bridges": cert.runtime_bridges.len(),
        },
        "objectives": cert.objectives,
        "milestones": cert.milestones,
        "tasks": cert.tasks,
        "gates": cert.gates,
        "decisions": cert.decisions,
        "notes": cert.notes,
        "lanes": cert.lanes,
        "claims": cert.claims,
        "handoffs": cert.handoffs,
        "syncs": cert.syncs,
        "checkpoints": cert.checkpoints,
        "runtime_ledgers": cert.runtime_ledgers,
        "runtime_policies": cert.runtime_policies,
        "runtime_sessions": cert.runtime_sessions,
        "runtime_tools": cert.runtime_tools,
        "runtime_turns": cert.runtime_turns,
        "runtime_hooks": cert.runtime_hooks,
        "runtime_bridges": cert.runtime_bridges,
        "tasks_by_state": tasks_by_state,
        "tasks_by_milestone": tasks_by_milestone,
        "gates_by_task": gates_by_task,
        "claims_by_lane": claims_by_lane,
        "handoffs_by_lane": handoffs_by_lane,
        "syncs_by_lane": syncs_by_lane,
        "checkpoints_by_lane": checkpoints_by_lane,
        "dependency_edges": dependency_edges,
        "coordination_edges": coordination_edges,
        "checked_rows": report.checked_rows,
    })
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
            "verify_artifact": "entc verify-artifact path/to/model.ent --json",
            "bind_python": "entc bind path/to/model.ent --target python --framework pytorch_fx --output build/ent_contract.py",
            "verify_witness": "entc verify-witness path/to/model.ent artifacts/run.witness.json --json",
            "inspect": "entc inspect path/to/workspace --markdown --output build/workspace-map.md",
            "native_audit": "entc native-audit path/to/workspace --markdown --output build/native-audit.md",
            "runtime_audit": "entc runtime-audit path/to/workspace --markdown --output build/runtime-ledger.md",
            "plan": "entc plan path/to/work.ent --json",
            "coordination_plan": "entc plan examples/coordination-ledger.ent --json",
            "apply_dry_run": "entc apply path/to/work.ent --repo . --dry-run --json",
        },
        "editor": {
            "vscode_extension": format!("{workspace}/tooling/vscode/entanglement"),
            "language_id": "entanglement",
            "file_extensions": [".ent"],
        }
    })
}

fn native_status_label(status: NativeReadinessStatus) -> &'static str {
    match status {
        NativeReadinessStatus::Ready => "ready",
        NativeReadinessStatus::NeedsAttention => "needs-attention",
        NativeReadinessStatus::Blocked => "blocked",
        NativeReadinessStatus::Empty => "empty",
    }
}

fn runtime_status_label(status: RuntimeReadinessStatus) -> &'static str {
    match status {
        RuntimeReadinessStatus::Ready => "ready",
        RuntimeReadinessStatus::NeedsAttention => "needs-attention",
        RuntimeReadinessStatus::Blocked => "blocked",
        RuntimeReadinessStatus::Empty => "empty",
    }
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

fn write_text(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)?;
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
