mod code_map;

use anyhow::{bail, Context, Result};
use code_map::{
    analyze_code, import_kind_label, marker_kind_label, symbol_kind_label, CodeAnalysis,
    CodeImportKind, CodeMarkerKind, CodeSpan, CodeSymbolKind, SourceDialect,
};
use ent_core::CheckedRows;
use ent_elab::elaborate_ast;
use ent_kernel::{instability_from_error, verify};
use ent_parser::{parse_world_diagnostic, EffectAccess, SourceSpan, TransformTargetDecl, WorldAst};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectOptions {
    pub recursive: bool,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub max_file_bytes: Option<u64>,
}

impl Default for InspectOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            include_hidden: false,
            follow_symlinks: false,
            max_file_bytes: Some(4 * 1024 * 1024),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InspectReport {
    pub root: PathBuf,
    pub options: InspectOptions,
    pub summary: InspectSummary,
    pub readiness: ReadinessSignal,
    pub declaration_counts: DeclarationCounts,
    pub certificate_rows: CheckedRowSummary,
    pub proof_coverage: ProofCoverage,
    pub declarations: Vec<DeclarationSummary>,
    pub references: Vec<ReferenceSummary>,
    pub files: Vec<FileInspection>,
    pub diagnostics: Vec<InspectionDiagnostic>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectSummary {
    pub source_file_count: usize,
    pub inspected_file_count: usize,
    pub skipped_file_count: usize,
    pub mapped_file_count: usize,
    pub verified_file_count: usize,
    pub parse_failed_file_count: usize,
    pub elaboration_failed_file_count: usize,
    pub verification_failed_file_count: usize,
    pub read_failed_file_count: usize,
    pub byte_count: u64,
    pub line_count: usize,
    pub declaration_count: usize,
    pub reference_count: usize,
    pub certificate_row_count: usize,
    pub diagnostic_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileInspection {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub status: FileStatus,
    pub bytes: u64,
    pub lines: usize,
    pub sha256: Option<String>,
    pub world: Option<String>,
    pub declaration_counts: DeclarationCounts,
    pub certificate_rows: Option<CheckedRowSummary>,
    pub proof_coverage: ProofCoverage,
    pub declarations: Vec<DeclarationSummary>,
    pub references: Vec<ReferenceSummary>,
    pub diagnostics: Vec<InspectionDiagnostic>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileStatus {
    Mapped,
    Verified,
    ParseFailed,
    ElaborationFailed,
    VerificationFailed,
    ReadFailed,
    Skipped,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclarationCounts {
    pub modules: usize,
    pub imports: usize,
    pub functions: usize,
    pub dimensions: usize,
    pub states: usize,
    pub relations: usize,
    pub laws: usize,
    pub invariants: usize,
    pub effects: usize,
    pub externals: usize,
    pub workspaces: usize,
    pub parsers: usize,
    pub documents: usize,
    pub selections: usize,
    pub transforms: usize,
    pub validators: usize,
    pub objectives: usize,
    pub milestones: usize,
    pub tasks: usize,
    pub gates: usize,
    pub decisions: usize,
    pub notes: usize,
    pub graphics: usize,
    pub render_targets: usize,
    pub render_pipelines: usize,
    pub benchmarks: usize,
    pub tensors: usize,
    pub accelerators: usize,
    pub datasets: usize,
    pub models: usize,
    pub trainings: usize,
    pub canonicals: usize,
    pub artifacts: usize,
    pub lowerings: usize,
    pub executors: usize,
    pub witnesses: usize,
    pub machines: usize,
    pub memories: usize,
    pub instructions: usize,
    pub abis: usize,
    pub proof_artifacts: usize,
    pub evolves: usize,
    pub ad: usize,
    pub measures: usize,
    pub theorems: usize,
    pub proofs: usize,
    pub source_files: usize,
    pub source_imports: usize,
    pub source_symbols: usize,
    pub source_markers: usize,
    pub rust_sources: usize,
    pub c_sources: usize,
    pub cpp_sources: usize,
}

impl DeclarationCounts {
    pub fn total(&self) -> usize {
        self.modules
            + self.imports
            + self.functions
            + self.dimensions
            + self.states
            + self.relations
            + self.laws
            + self.invariants
            + self.effects
            + self.externals
            + self.workspaces
            + self.parsers
            + self.documents
            + self.selections
            + self.transforms
            + self.validators
            + self.objectives
            + self.milestones
            + self.tasks
            + self.gates
            + self.decisions
            + self.notes
            + self.graphics
            + self.render_targets
            + self.render_pipelines
            + self.benchmarks
            + self.tensors
            + self.accelerators
            + self.datasets
            + self.models
            + self.trainings
            + self.canonicals
            + self.artifacts
            + self.lowerings
            + self.executors
            + self.witnesses
            + self.machines
            + self.memories
            + self.instructions
            + self.abis
            + self.proof_artifacts
            + self.evolves
            + self.ad
            + self.measures
            + self.theorems
            + self.proofs
            + self.source_files
            + self.source_imports
            + self.source_symbols
            + self.source_markers
            + self.rust_sources
            + self.c_sources
            + self.cpp_sources
    }

    fn add_assign(&mut self, other: &Self) {
        self.modules += other.modules;
        self.imports += other.imports;
        self.functions += other.functions;
        self.dimensions += other.dimensions;
        self.states += other.states;
        self.relations += other.relations;
        self.laws += other.laws;
        self.invariants += other.invariants;
        self.effects += other.effects;
        self.externals += other.externals;
        self.workspaces += other.workspaces;
        self.parsers += other.parsers;
        self.documents += other.documents;
        self.selections += other.selections;
        self.transforms += other.transforms;
        self.validators += other.validators;
        self.objectives += other.objectives;
        self.milestones += other.milestones;
        self.tasks += other.tasks;
        self.gates += other.gates;
        self.decisions += other.decisions;
        self.notes += other.notes;
        self.graphics += other.graphics;
        self.render_targets += other.render_targets;
        self.render_pipelines += other.render_pipelines;
        self.benchmarks += other.benchmarks;
        self.tensors += other.tensors;
        self.accelerators += other.accelerators;
        self.datasets += other.datasets;
        self.models += other.models;
        self.trainings += other.trainings;
        self.canonicals += other.canonicals;
        self.artifacts += other.artifacts;
        self.lowerings += other.lowerings;
        self.executors += other.executors;
        self.witnesses += other.witnesses;
        self.machines += other.machines;
        self.memories += other.memories;
        self.instructions += other.instructions;
        self.abis += other.abis;
        self.proof_artifacts += other.proof_artifacts;
        self.evolves += other.evolves;
        self.ad += other.ad;
        self.measures += other.measures;
        self.theorems += other.theorems;
        self.proofs += other.proofs;
        self.source_files += other.source_files;
        self.source_imports += other.source_imports;
        self.source_symbols += other.source_symbols;
        self.source_markers += other.source_markers;
        self.rust_sources += other.rust_sources;
        self.c_sources += other.c_sources;
        self.cpp_sources += other.cpp_sources;
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckedRowSummary {
    pub equivalence: usize,
    pub inclusion: usize,
    pub union_composition: usize,
    pub modal_truth: usize,
    pub factors: usize,
    pub coordinate_separation: usize,
    pub invariants: usize,
    pub resources: usize,
    pub probabilities: usize,
    pub ad: usize,
    pub backends: usize,
    pub external_capabilities: usize,
    pub workspaces: usize,
    pub parsers: usize,
    pub selections: usize,
    pub transforms: usize,
    pub validators: usize,
    pub objectives: usize,
    pub milestones: usize,
    pub tasks: usize,
    pub gates: usize,
    pub decisions: usize,
    pub notes: usize,
    pub graphics: usize,
    pub render_targets: usize,
    pub render_pipelines: usize,
    pub benchmarks: usize,
    pub tensors: usize,
    pub accelerators: usize,
    pub datasets: usize,
    pub models: usize,
    pub trainings: usize,
    pub canonicals: usize,
    pub artifacts: usize,
    pub lowerings: usize,
    pub executors: usize,
    pub witnesses: usize,
    pub machines: usize,
    pub memory: usize,
    pub instructions: usize,
    pub abis: usize,
    pub proof_artifacts: usize,
    pub proofs: usize,
    pub total: usize,
}

impl CheckedRowSummary {
    fn from_checked_rows(rows: &CheckedRows) -> Self {
        let mut summary = Self {
            equivalence: rows.equivalence,
            inclusion: rows.inclusion,
            union_composition: rows.union_composition,
            modal_truth: rows.modal_truth,
            factors: rows.factors,
            coordinate_separation: rows.coordinate_separation,
            invariants: rows.invariants,
            resources: rows.resources,
            probabilities: rows.probabilities,
            ad: rows.ad,
            backends: rows.backends,
            external_capabilities: rows.external_capabilities,
            workspaces: rows.workspaces,
            parsers: rows.parsers,
            selections: rows.selections,
            transforms: rows.transforms,
            validators: rows.validators,
            objectives: rows.objectives,
            milestones: rows.milestones,
            tasks: rows.tasks,
            gates: rows.gates,
            decisions: rows.decisions,
            notes: rows.notes,
            graphics: rows.graphics,
            render_targets: rows.render_targets,
            render_pipelines: rows.render_pipelines,
            benchmarks: rows.benchmarks,
            tensors: rows.tensors,
            accelerators: rows.accelerators,
            datasets: rows.datasets,
            models: rows.models,
            trainings: rows.trainings,
            canonicals: rows.canonicals,
            artifacts: rows.artifacts,
            lowerings: rows.lowerings,
            executors: rows.executors,
            witnesses: rows.witnesses,
            machines: rows.machines,
            memory: rows.memory,
            instructions: rows.instructions,
            abis: rows.abis,
            proof_artifacts: rows.proof_artifacts,
            proofs: rows.proofs,
            total: 0,
        };
        summary.total = summary.compute_total();
        summary
    }

    fn add_assign(&mut self, other: &Self) {
        self.equivalence += other.equivalence;
        self.inclusion += other.inclusion;
        self.union_composition += other.union_composition;
        self.modal_truth += other.modal_truth;
        self.factors += other.factors;
        self.coordinate_separation += other.coordinate_separation;
        self.invariants += other.invariants;
        self.resources += other.resources;
        self.probabilities += other.probabilities;
        self.ad += other.ad;
        self.backends += other.backends;
        self.external_capabilities += other.external_capabilities;
        self.workspaces += other.workspaces;
        self.parsers += other.parsers;
        self.selections += other.selections;
        self.transforms += other.transforms;
        self.validators += other.validators;
        self.objectives += other.objectives;
        self.milestones += other.milestones;
        self.tasks += other.tasks;
        self.gates += other.gates;
        self.decisions += other.decisions;
        self.notes += other.notes;
        self.graphics += other.graphics;
        self.render_targets += other.render_targets;
        self.render_pipelines += other.render_pipelines;
        self.benchmarks += other.benchmarks;
        self.tensors += other.tensors;
        self.accelerators += other.accelerators;
        self.datasets += other.datasets;
        self.models += other.models;
        self.trainings += other.trainings;
        self.canonicals += other.canonicals;
        self.artifacts += other.artifacts;
        self.lowerings += other.lowerings;
        self.executors += other.executors;
        self.witnesses += other.witnesses;
        self.machines += other.machines;
        self.memory += other.memory;
        self.instructions += other.instructions;
        self.abis += other.abis;
        self.proof_artifacts += other.proof_artifacts;
        self.proofs += other.proofs;
        self.total = self.compute_total();
    }

    fn compute_total(&self) -> usize {
        self.equivalence
            + self.inclusion
            + self.union_composition
            + self.modal_truth
            + self.factors
            + self.coordinate_separation
            + self.invariants
            + self.resources
            + self.probabilities
            + self.ad
            + self.backends
            + self.external_capabilities
            + self.workspaces
            + self.parsers
            + self.selections
            + self.transforms
            + self.validators
            + self.objectives
            + self.milestones
            + self.tasks
            + self.gates
            + self.decisions
            + self.notes
            + self.graphics
            + self.render_targets
            + self.render_pipelines
            + self.benchmarks
            + self.tensors
            + self.accelerators
            + self.datasets
            + self.models
            + self.trainings
            + self.canonicals
            + self.artifacts
            + self.lowerings
            + self.executors
            + self.witnesses
            + self.machines
            + self.memory
            + self.instructions
            + self.abis
            + self.proof_artifacts
            + self.proofs
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProofCoverage {
    pub theorem_count: usize,
    pub proof_count: usize,
    pub proven_count: usize,
    pub missing_count: usize,
    pub extra_count: usize,
    pub coverage_percent: Option<f32>,
    pub missing_theorems: Vec<String>,
    pub extra_proofs: Vec<String>,
}

impl ProofCoverage {
    fn add_file(&mut self, file: &Path, other: &Self) {
        self.theorem_count += other.theorem_count;
        self.proof_count += other.proof_count;
        self.proven_count += other.proven_count;
        self.missing_count += other.missing_count;
        self.extra_count += other.extra_count;
        self.missing_theorems.extend(
            other
                .missing_theorems
                .iter()
                .map(|name| format!("{}:{name}", file.display())),
        );
        self.extra_proofs.extend(
            other
                .extra_proofs
                .iter()
                .map(|name| format!("{}:{name}", file.display())),
        );
        self.coverage_percent = coverage_percent(self.proven_count, self.theorem_count);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclarationSummary {
    pub file: PathBuf,
    pub kind: String,
    pub name: String,
    pub span: Option<ByteSpan>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceSummary {
    pub file: PathBuf,
    pub kind: String,
    pub value: String,
    pub owner: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectionDiagnostic {
    pub severity: DiagnosticSeverity,
    pub phase: InspectionPhase,
    pub path: Option<PathBuf>,
    pub message: String,
    pub span: Option<ByteSpan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InspectionPhase {
    Discover,
    Read,
    Parse,
    Elaborate,
    Verify,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessSignal {
    pub status: ReadinessStatus,
    pub score: u8,
    pub reasons: Vec<String>,
    pub risks: Vec<RiskSignal>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadinessStatus {
    Ready,
    NeedsAttention,
    Blocked,
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskSignal {
    pub level: RiskLevel,
    pub code: String,
    pub message: String,
    pub path: Option<PathBuf>,
    pub count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug)]
enum SourceCandidate {
    Inspect(PathBuf),
    Skip { path: PathBuf, message: String },
}

pub fn inspect_path(path: &Path, options: InspectOptions) -> Result<InspectReport> {
    let root_metadata = metadata_for(path, options.follow_symlinks)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    let root_is_file = root_metadata.is_file();
    let candidates = collect_sources(path, &root_metadata, &options)?;
    let mut files = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        let inspection = match candidate {
            SourceCandidate::Inspect(source_path) => {
                inspect_source_file(path, root_is_file, &source_path, &options)
            }
            SourceCandidate::Skip {
                path: source_path,
                message,
            } => skipped_file_inspection(path, root_is_file, source_path, message),
        };
        files.push(inspection);
    }

    Ok(assemble_report(path.to_path_buf(), options, files))
}

pub fn render_markdown(report: &InspectReport) -> String {
    let mut out = String::new();
    out.push_str("# Entanglement Inspection\n\n");
    out.push_str(&format!("- Root: `{}`\n", report.root.display()));
    out.push_str(&format!(
        "- Sources: {} inspected, {} skipped\n",
        report.summary.inspected_file_count, report.summary.skipped_file_count
    ));
    out.push_str(&format!(
        "- Mapped: {}, verified: {}\n",
        report.summary.mapped_file_count, report.summary.verified_file_count
    ));
    out.push_str(&format!(
        "- Declarations: {}\n",
        report.summary.declaration_count
    ));
    out.push_str(&format!(
        "- Checked rows: {}\n",
        report.summary.certificate_row_count
    ));
    out.push_str(&format!(
        "- Diagnostics: {} errors, {} warnings\n\n",
        report.summary.error_count, report.summary.warning_count
    ));

    out.push_str("## Readiness\n\n");
    out.push_str(&format!(
        "**{}** (score {}/100)\n\n",
        readiness_label(report.readiness.status),
        report.readiness.score
    ));
    for reason in &report.readiness.reasons {
        out.push_str(&format!("- {}\n", reason));
    }
    if !report.readiness.risks.is_empty() {
        out.push('\n');
        out.push_str("| Level | Code | Count | Message |\n");
        out.push_str("| --- | --- | ---: | --- |\n");
        for risk in &report.readiness.risks {
            out.push_str(&format!(
                "| {} | `{}` | {} | {} |\n",
                risk_level_label(risk.level),
                markdown_cell(&risk.code),
                risk.count,
                markdown_cell(&risk.message)
            ));
        }
    }

    out.push_str("\n## Files\n\n");
    if report.files.is_empty() {
        out.push_str("No supported sources found.\n");
    } else {
        out.push_str("| File | Status | World | Lines | Declarations | Rows | Proofs |\n");
        out.push_str("| --- | --- | --- | ---: | ---: | ---: | --- |\n");
        for file in &report.files {
            let rows = file.certificate_rows.as_ref().map_or(0, |rows| rows.total);
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} |\n",
                markdown_cell(&file.relative_path.display().to_string()),
                file_status_label(file.status),
                markdown_cell(file.world.as_deref().unwrap_or("-")),
                file.lines,
                file.declaration_counts.total(),
                rows,
                proof_label(&file.proof_coverage)
            ));
        }
    }

    out.push_str("\n## Proof Coverage\n\n");
    out.push_str(&format!(
        "{} of {} theorems have matching proof blocks",
        report.proof_coverage.proven_count, report.proof_coverage.theorem_count
    ));
    if let Some(percent) = report.proof_coverage.coverage_percent {
        out.push_str(&format!(" ({percent:.1}%)"));
    }
    out.push_str(".\n");
    if !report.proof_coverage.missing_theorems.is_empty() {
        out.push_str("\nMissing proof blocks:\n");
        for name in &report.proof_coverage.missing_theorems {
            out.push_str(&format!("- `{}`\n", markdown_cell(name)));
        }
    }
    if !report.proof_coverage.extra_proofs.is_empty() {
        out.push_str("\nProof blocks without matching theorem:\n");
        for name in &report.proof_coverage.extra_proofs {
            out.push_str(&format!("- `{}`\n", markdown_cell(name)));
        }
    }

    out.push_str("\n## Declaration Counts\n\n");
    for (name, count) in nonzero_declaration_counts(&report.declaration_counts) {
        out.push_str(&format!("- `{name}`: {count}\n"));
    }
    if report.declaration_counts.total() == 0 {
        out.push_str("No declarations were parsed.\n");
    }

    if !report.references.is_empty() {
        out.push_str("\n## References\n\n");
        out.push_str("| File | Kind | Owner | Value |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for reference in &report.references {
            out.push_str(&format!(
                "| `{}` | {} | {} | `{}` |\n",
                markdown_cell(&reference.file.display().to_string()),
                markdown_cell(&reference.kind),
                markdown_cell(reference.owner.as_deref().unwrap_or("-")),
                markdown_cell(&reference.value)
            ));
        }
    }

    if !report.diagnostics.is_empty() {
        out.push_str("\n## Diagnostics\n\n");
        out.push_str("| Severity | Phase | File | Message |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for diagnostic in &report.diagnostics {
            let file = diagnostic
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_owned());
            out.push_str(&format!(
                "| {} | {} | `{}` | {} |\n",
                severity_label(diagnostic.severity),
                phase_label(diagnostic.phase),
                markdown_cell(&file),
                markdown_cell(&diagnostic.message)
            ));
        }
    }

    out
}

pub fn render_compact_text(report: &InspectReport) -> String {
    format!(
        "INSPECT status={} score={} sources={} inspected={} verified={} mapped={} diagnostics={} errors={} warnings={} declarations={} rows={}",
        readiness_label(report.readiness.status),
        report.readiness.score,
        report.summary.source_file_count,
        report.summary.inspected_file_count,
        report.summary.verified_file_count,
        report.summary.mapped_file_count,
        report.summary.diagnostic_count,
        report.summary.error_count,
        report.summary.warning_count,
        report.summary.declaration_count,
        report.summary.certificate_row_count,
    )
}

fn assemble_report(
    root: PathBuf,
    options: InspectOptions,
    files: Vec<FileInspection>,
) -> InspectReport {
    let mut summary = InspectSummary {
        source_file_count: files.len(),
        ..InspectSummary::default()
    };
    let mut declaration_counts = DeclarationCounts::default();
    let mut certificate_rows = CheckedRowSummary::default();
    let mut proof_coverage = ProofCoverage::default();
    let mut declarations = Vec::new();
    let mut references = Vec::new();
    let mut diagnostics = Vec::new();

    for file in &files {
        match file.status {
            FileStatus::Skipped => summary.skipped_file_count += 1,
            FileStatus::Mapped => {
                summary.inspected_file_count += 1;
                summary.mapped_file_count += 1;
            }
            FileStatus::Verified => {
                summary.inspected_file_count += 1;
                summary.verified_file_count += 1;
            }
            FileStatus::ParseFailed => {
                summary.inspected_file_count += 1;
                summary.parse_failed_file_count += 1;
            }
            FileStatus::ElaborationFailed => {
                summary.inspected_file_count += 1;
                summary.elaboration_failed_file_count += 1;
            }
            FileStatus::VerificationFailed => {
                summary.inspected_file_count += 1;
                summary.verification_failed_file_count += 1;
            }
            FileStatus::ReadFailed => {
                summary.inspected_file_count += 1;
                summary.read_failed_file_count += 1;
            }
        }
        summary.byte_count += file.bytes;
        summary.line_count += file.lines;
        declaration_counts.add_assign(&file.declaration_counts);
        if let Some(rows) = &file.certificate_rows {
            certificate_rows.add_assign(rows);
        }
        proof_coverage.add_file(&file.relative_path, &file.proof_coverage);
        declarations.extend(file.declarations.iter().cloned());
        references.extend(file.references.iter().cloned());
        diagnostics.extend(file.diagnostics.iter().cloned());
    }

    declarations.sort_by(|left, right| {
        (
            &left.file,
            &left.kind,
            &left.name,
            left.span.as_ref().map(|span| span.start),
        )
            .cmp(&(
                &right.file,
                &right.kind,
                &right.name,
                right.span.as_ref().map(|span| span.start),
            ))
    });
    references.sort_by(|left, right| {
        (&left.file, &left.kind, &left.owner, &left.value).cmp(&(
            &right.file,
            &right.kind,
            &right.owner,
            &right.value,
        ))
    });
    diagnostics.sort_by(|left, right| {
        (
            &left.path,
            phase_order(left.phase),
            severity_order(left.severity),
            &left.message,
        )
            .cmp(&(
                &right.path,
                phase_order(right.phase),
                severity_order(right.severity),
                &right.message,
            ))
    });

    summary.declaration_count = declaration_counts.total();
    summary.reference_count = references.len();
    summary.certificate_row_count = certificate_rows.total;
    summary.diagnostic_count = diagnostics.len();
    summary.error_count = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .count();
    summary.warning_count = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
        .count();

    let readiness = build_readiness(&summary, &declaration_counts, &proof_coverage, &files);

    InspectReport {
        root,
        options,
        summary,
        readiness,
        declaration_counts,
        certificate_rows,
        proof_coverage,
        declarations,
        references,
        files,
        diagnostics,
    }
}

fn collect_sources(
    root: &Path,
    root_metadata: &fs::Metadata,
    options: &InspectOptions,
) -> Result<Vec<SourceCandidate>> {
    if root_metadata.is_file() {
        return Ok(if is_inspect_source(root) {
            vec![SourceCandidate::Inspect(root.to_path_buf())]
        } else {
            vec![SourceCandidate::Skip {
                path: root.to_path_buf(),
                message: "path is not a supported source".to_owned(),
            }]
        });
    }
    if !root_metadata.is_dir() {
        bail!("{} is neither a file nor a directory", root.display());
    }

    let mut candidates = Vec::new();
    let mut visited_dirs = BTreeSet::new();
    visit_dir(root, options, &mut visited_dirs, &mut candidates)?;
    candidates.sort_by(|left, right| candidate_path(left).cmp(candidate_path(right)));
    Ok(candidates)
}

fn visit_dir(
    dir: &Path,
    options: &InspectOptions,
    visited_dirs: &mut BTreeSet<PathBuf>,
    candidates: &mut Vec<SourceCandidate>,
) -> Result<()> {
    let visited_key = if options.follow_symlinks {
        fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
    } else {
        dir.to_path_buf()
    };
    if !visited_dirs.insert(visited_key) {
        return Ok(());
    }

    let entries = fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))?;
    let mut entries = entries.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if !options.include_hidden && is_hidden_entry(&path) {
            continue;
        }
        let metadata = match metadata_for(&path, options.follow_symlinks) {
            Ok(metadata) => metadata,
            Err(error) => {
                if is_inspect_source(&path) {
                    candidates.push(SourceCandidate::Skip {
                        path,
                        message: format!("failed to read metadata: {error}"),
                    });
                }
                continue;
            }
        };
        if metadata.file_type().is_symlink() && !options.follow_symlinks {
            if is_inspect_source(&path) {
                candidates.push(SourceCandidate::Skip {
                    path,
                    message: "symbolic links are disabled".to_owned(),
                });
            }
            continue;
        }
        if metadata.is_dir() {
            if is_ignored_directory(&path) {
                continue;
            }
            if options.recursive {
                visit_dir(&path, options, visited_dirs, candidates)?;
            }
        } else if metadata.is_file() && is_inspect_source(&path) {
            candidates.push(SourceCandidate::Inspect(path));
        }
    }

    Ok(())
}

fn inspect_source_file(
    root: &Path,
    root_is_file: bool,
    path: &Path,
    options: &InspectOptions,
) -> FileInspection {
    let relative_path = relative_path(root, root_is_file, path);
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            let diagnostic = diagnostic(
                DiagnosticSeverity::Error,
                InspectionPhase::Read,
                Some(relative_path.clone()),
                format!("failed to read metadata: {error}"),
                None,
            );
            return empty_file_inspection(
                path,
                relative_path,
                FileStatus::ReadFailed,
                0,
                vec![diagnostic],
            );
        }
    };
    let bytes = metadata.len();
    if let Some(max_file_bytes) = options.max_file_bytes {
        if bytes > max_file_bytes {
            let diagnostic = diagnostic(
                DiagnosticSeverity::Warning,
                InspectionPhase::Read,
                Some(relative_path.clone()),
                format!("file has {bytes} bytes, above configured limit {max_file_bytes}"),
                None,
            );
            return empty_file_inspection(
                path,
                relative_path,
                FileStatus::Skipped,
                bytes,
                vec![diagnostic],
            );
        }
    }

    let source_bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            let diagnostic = diagnostic(
                DiagnosticSeverity::Error,
                InspectionPhase::Read,
                Some(relative_path.clone()),
                format!("failed to read source: {error}"),
                None,
            );
            return empty_file_inspection(
                path,
                relative_path,
                FileStatus::ReadFailed,
                bytes,
                vec![diagnostic],
            );
        }
    };
    let sha256 = Some(format!("sha256:{:x}", Sha256::digest(&source_bytes)));
    let source = match std::str::from_utf8(&source_bytes) {
        Ok(source) => source,
        Err(error) => {
            let diagnostic = diagnostic(
                DiagnosticSeverity::Error,
                InspectionPhase::Read,
                Some(relative_path.clone()),
                format!("source is not valid UTF-8: {error}"),
                None,
            );
            return FileInspection {
                path: path.to_path_buf(),
                relative_path,
                status: FileStatus::ReadFailed,
                bytes,
                lines: 0,
                sha256,
                world: None,
                declaration_counts: DeclarationCounts::default(),
                certificate_rows: None,
                proof_coverage: ProofCoverage::default(),
                declarations: vec![],
                references: vec![],
                diagnostics: vec![diagnostic],
            };
        }
    };
    let lines = line_count(source);
    if let Some(dialect) = SourceDialect::classify(path) {
        return inspect_code_file(path, relative_path, bytes, lines, sha256, source, dialect);
    }

    let ast = match parse_world_diagnostic(source) {
        Ok(ast) => ast,
        Err(error) => {
            let diagnostic = diagnostic(
                DiagnosticSeverity::Error,
                InspectionPhase::Parse,
                Some(relative_path.clone()),
                error.message,
                Some(error.span.into()),
            );
            return FileInspection {
                path: path.to_path_buf(),
                relative_path,
                status: FileStatus::ParseFailed,
                bytes,
                lines,
                sha256,
                world: None,
                declaration_counts: DeclarationCounts::default(),
                certificate_rows: None,
                proof_coverage: ProofCoverage::default(),
                declarations: vec![],
                references: vec![],
                diagnostics: vec![diagnostic],
            };
        }
    };

    let declaration_counts = declaration_counts(&ast);
    let declarations = declaration_summaries(&relative_path, &ast);
    let references = reference_summaries(&relative_path, &ast);
    let proof_coverage = proof_coverage(&ast);
    let world = Some(ast.name.clone());
    let mut diagnostics = Vec::new();

    let certificate = match elaborate_ast(&ast) {
        Ok(certificate) => certificate,
        Err(error) => {
            diagnostics.push(diagnostic(
                DiagnosticSeverity::Error,
                InspectionPhase::Elaborate,
                Some(relative_path.clone()),
                error.to_string(),
                None,
            ));
            return FileInspection {
                path: path.to_path_buf(),
                relative_path,
                status: FileStatus::ElaborationFailed,
                bytes,
                lines,
                sha256,
                world,
                declaration_counts,
                certificate_rows: None,
                proof_coverage,
                declarations,
                references,
                diagnostics,
            };
        }
    };

    let report = match verify(&certificate) {
        Ok(report) => report,
        Err(error) => {
            let instability = instability_from_error(&error);
            diagnostics.push(diagnostic(
                DiagnosticSeverity::Error,
                InspectionPhase::Verify,
                Some(relative_path.clone()),
                format!(
                    "{}: {}",
                    instability_kind(&instability.kind),
                    instability.message
                ),
                None,
            ));
            return FileInspection {
                path: path.to_path_buf(),
                relative_path,
                status: FileStatus::VerificationFailed,
                bytes,
                lines,
                sha256,
                world,
                declaration_counts,
                certificate_rows: None,
                proof_coverage,
                declarations,
                references,
                diagnostics,
            };
        }
    };

    FileInspection {
        path: path.to_path_buf(),
        relative_path,
        status: FileStatus::Verified,
        bytes,
        lines,
        sha256,
        world,
        declaration_counts,
        certificate_rows: Some(CheckedRowSummary::from_checked_rows(&report.checked_rows)),
        proof_coverage,
        declarations,
        references,
        diagnostics,
    }
}

fn inspect_code_file(
    path: &Path,
    relative_path: PathBuf,
    bytes: u64,
    lines: usize,
    sha256: Option<String>,
    source: &str,
    dialect: SourceDialect,
) -> FileInspection {
    let analysis = match analyze_code(source, dialect) {
        Ok(analysis) => analysis,
        Err(error) => {
            let diagnostic = diagnostic(
                DiagnosticSeverity::Error,
                InspectionPhase::Parse,
                Some(relative_path.clone()),
                error.to_string(),
                None,
            );
            return FileInspection {
                path: path.to_path_buf(),
                relative_path,
                status: FileStatus::ParseFailed,
                bytes,
                lines,
                sha256,
                world: None,
                declaration_counts: DeclarationCounts::default(),
                certificate_rows: None,
                proof_coverage: ProofCoverage::default(),
                declarations: vec![],
                references: vec![],
                diagnostics: vec![diagnostic],
            };
        }
    };
    let mut diagnostics = Vec::new();
    if analysis.parse_error {
        diagnostics.push(diagnostic(
            DiagnosticSeverity::Error,
            InspectionPhase::Parse,
            Some(relative_path.clone()),
            format!("{} parser reported syntax errors", dialect.label()),
            None,
        ));
    }
    let status = if analysis.parse_error {
        FileStatus::ParseFailed
    } else {
        FileStatus::Mapped
    };
    FileInspection {
        path: path.to_path_buf(),
        relative_path: relative_path.clone(),
        status,
        bytes,
        lines,
        sha256,
        world: None,
        declaration_counts: code_declaration_counts(&analysis),
        certificate_rows: None,
        proof_coverage: ProofCoverage::default(),
        declarations: code_declaration_summaries(&relative_path, &analysis),
        references: code_reference_summaries(&relative_path, &analysis),
        diagnostics,
    }
}

fn empty_file_inspection(
    path: &Path,
    relative_path: PathBuf,
    status: FileStatus,
    bytes: u64,
    diagnostics: Vec<InspectionDiagnostic>,
) -> FileInspection {
    FileInspection {
        path: path.to_path_buf(),
        relative_path,
        status,
        bytes,
        lines: 0,
        sha256: None,
        world: None,
        declaration_counts: DeclarationCounts::default(),
        certificate_rows: None,
        proof_coverage: ProofCoverage::default(),
        declarations: vec![],
        references: vec![],
        diagnostics,
    }
}

fn skipped_file_inspection(
    root: &Path,
    root_is_file: bool,
    path: PathBuf,
    message: String,
) -> FileInspection {
    let relative_path = relative_path(root, root_is_file, &path);
    let diagnostic = diagnostic(
        DiagnosticSeverity::Warning,
        InspectionPhase::Discover,
        Some(relative_path.clone()),
        message,
        None,
    );
    empty_file_inspection(
        &path,
        relative_path,
        FileStatus::Skipped,
        0,
        vec![diagnostic],
    )
}

fn code_declaration_counts(analysis: &CodeAnalysis) -> DeclarationCounts {
    let mut counts = DeclarationCounts {
        source_files: 1,
        source_imports: analysis.imports.len(),
        source_symbols: analysis.symbols.len(),
        source_markers: analysis.markers.len(),
        ..DeclarationCounts::default()
    };
    match analysis.dialect {
        Some(SourceDialect::Rust) => counts.rust_sources = 1,
        Some(SourceDialect::C) => counts.c_sources = 1,
        Some(SourceDialect::Cpp) => counts.cpp_sources = 1,
        None => {}
    }
    counts
}

fn code_declaration_summaries(file: &Path, analysis: &CodeAnalysis) -> Vec<DeclarationSummary> {
    let mut declarations = Vec::new();
    let dialect = analysis.dialect.unwrap_or(SourceDialect::Rust);
    push_decl_code(
        &mut declarations,
        file,
        code_file_kind(dialect),
        dialect.label(),
        None,
    );
    for import in &analysis.imports {
        let kind = code_import_kind(dialect, import.kind);
        push_decl_code(
            &mut declarations,
            file,
            &kind,
            &import.target,
            Some(import.span),
        );
    }
    for symbol in &analysis.symbols {
        let kind = code_symbol_kind(dialect, symbol.kind);
        push_decl_code(
            &mut declarations,
            file,
            &kind,
            &symbol.name,
            Some(symbol.span),
        );
    }
    for marker in &analysis.markers {
        let kind = code_marker_kind(dialect, marker.kind);
        push_decl_code(
            &mut declarations,
            file,
            &kind,
            marker_kind_label(marker.kind),
            Some(marker.span),
        );
    }
    declarations
}

fn code_reference_summaries(file: &Path, analysis: &CodeAnalysis) -> Vec<ReferenceSummary> {
    let mut references = Vec::new();
    let dialect = analysis.dialect.unwrap_or(SourceDialect::Rust);
    for import in &analysis.imports {
        push_ref(
            &mut references,
            file,
            code_import_ref_kind(import.kind),
            &import.target,
            Some(dialect.label()),
        );
    }
    for symbol in &analysis.symbols {
        if !symbol.detail.is_empty() {
            push_ref(
                &mut references,
                file,
                "source-signature",
                &symbol.detail,
                Some(&symbol.name),
            );
        }
        if symbol.public {
            push_ref(
                &mut references,
                file,
                "source-public",
                symbol_kind_label(symbol.kind),
                Some(&symbol.name),
            );
        }
    }
    for call in &analysis.calls {
        push_ref(
            &mut references,
            file,
            "source-call",
            &call.target,
            call.caller.as_deref(),
        );
    }
    for marker in &analysis.markers {
        push_ref(
            &mut references,
            file,
            "source-marker",
            &marker.text,
            Some(marker_kind_label(marker.kind)),
        );
    }
    push_ref(
        &mut references,
        file,
        "source-metric",
        &format!("code-lines={}", analysis.metrics.code_lines),
        Some(dialect.label()),
    );
    push_ref(
        &mut references,
        file,
        "source-metric",
        &format!("comment-lines={}", analysis.metrics.comment_lines),
        Some(dialect.label()),
    );
    push_ref(
        &mut references,
        file,
        "source-metric",
        &format!("max-nesting={}", analysis.metrics.max_nesting),
        Some(dialect.label()),
    );
    if analysis.metrics.unsafe_blocks > 0 {
        push_ref(
            &mut references,
            file,
            "source-unsafe",
            &analysis.metrics.unsafe_blocks.to_string(),
            Some(dialect.label()),
        );
    }
    if analysis.metrics.extern_blocks > 0 {
        push_ref(
            &mut references,
            file,
            "source-extern",
            &analysis.metrics.extern_blocks.to_string(),
            Some(dialect.label()),
        );
    }
    references
}

fn declaration_counts(ast: &WorldAst) -> DeclarationCounts {
    DeclarationCounts {
        modules: ast.modules.len(),
        imports: ast.imports.len(),
        functions: ast.functions.len(),
        dimensions: ast.dimensions.len(),
        states: ast.states.len(),
        relations: ast.relations.len(),
        laws: ast.laws.len(),
        invariants: ast.invariants.len(),
        effects: ast.effects.len(),
        externals: ast.externals.len(),
        workspaces: ast.workspaces.len(),
        parsers: ast.parsers.len(),
        documents: ast.documents.len(),
        selections: ast.selections.len(),
        transforms: ast.transforms.len(),
        validators: ast.validators.len(),
        objectives: ast.objectives.len(),
        milestones: ast.milestones.len(),
        tasks: ast.tasks.len(),
        gates: ast.gates.len(),
        decisions: ast.decisions.len(),
        notes: ast.notes.len(),
        graphics: ast.graphics.len(),
        render_targets: ast.render_targets.len(),
        render_pipelines: ast.render_pipelines.len(),
        benchmarks: ast.benchmarks.len(),
        tensors: ast.tensors.len(),
        accelerators: ast.accelerators.len(),
        datasets: ast.datasets.len(),
        models: ast.models.len(),
        trainings: ast.trainings.len(),
        canonicals: ast.canonicals.len(),
        artifacts: ast.artifacts.len(),
        lowerings: ast.lowerings.len(),
        executors: ast.executors.len(),
        witnesses: ast.witnesses.len(),
        machines: ast.machines.len(),
        memories: ast.memories.len(),
        instructions: ast.instructions.len(),
        abis: ast.abis.len(),
        proof_artifacts: ast.proof_artifacts.len(),
        evolves: ast.evolves.len(),
        ad: ast.ad.len(),
        measures: ast.measures.len(),
        theorems: ast.theorems.len(),
        proofs: ast.proofs.len(),
        ..DeclarationCounts::default()
    }
}

fn declaration_summaries(file: &Path, ast: &WorldAst) -> Vec<DeclarationSummary> {
    let mut declarations = Vec::new();
    for decl in &ast.modules {
        push_decl(
            &mut declarations,
            file,
            "module",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.imports {
        push_decl(
            &mut declarations,
            file,
            "import",
            &decl.path,
            Some(decl.span),
        );
    }
    for decl in &ast.functions {
        push_decl(
            &mut declarations,
            file,
            "function",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.dimensions {
        push_decl(&mut declarations, file, "dimension", &decl.name, None);
    }
    for decl in &ast.states {
        push_decl(
            &mut declarations,
            file,
            "state",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.relations {
        push_decl(
            &mut declarations,
            file,
            "relation",
            &decl.name,
            Some(decl.span),
        );
    }
    for (idx, decl) in ast.laws.iter().enumerate() {
        push_decl(
            &mut declarations,
            file,
            "law",
            &format!("law-{}", idx + 1),
            Some(decl.span),
        );
    }
    for decl in &ast.invariants {
        push_decl(
            &mut declarations,
            file,
            "invariant",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.effects {
        push_decl(
            &mut declarations,
            file,
            "effect",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.externals {
        push_decl(
            &mut declarations,
            file,
            "external",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.workspaces {
        push_decl(
            &mut declarations,
            file,
            "workspace",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.parsers {
        push_decl(
            &mut declarations,
            file,
            "parser",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.documents {
        push_decl(
            &mut declarations,
            file,
            "document",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.selections {
        push_decl(
            &mut declarations,
            file,
            "selection",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.transforms {
        push_decl(
            &mut declarations,
            file,
            "transform",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.validators {
        push_decl(
            &mut declarations,
            file,
            "validator",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.objectives {
        push_decl(
            &mut declarations,
            file,
            "objective",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.milestones {
        push_decl(
            &mut declarations,
            file,
            "milestone",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.tasks {
        push_decl(&mut declarations, file, "task", &decl.name, Some(decl.span));
    }
    for decl in &ast.gates {
        push_decl(&mut declarations, file, "gate", &decl.name, Some(decl.span));
    }
    for decl in &ast.decisions {
        push_decl(
            &mut declarations,
            file,
            "decision",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.notes {
        push_decl(&mut declarations, file, "note", &decl.name, Some(decl.span));
    }
    for decl in &ast.graphics {
        push_decl(
            &mut declarations,
            file,
            "graphics",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.render_targets {
        push_decl(
            &mut declarations,
            file,
            "render-target",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.render_pipelines {
        push_decl(
            &mut declarations,
            file,
            "render-pipeline",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.benchmarks {
        push_decl(
            &mut declarations,
            file,
            "benchmark",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.tensors {
        push_decl(
            &mut declarations,
            file,
            "tensor",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.accelerators {
        push_decl(
            &mut declarations,
            file,
            "accelerator",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.datasets {
        push_decl(
            &mut declarations,
            file,
            "dataset",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.models {
        push_decl(
            &mut declarations,
            file,
            "model",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.trainings {
        push_decl(
            &mut declarations,
            file,
            "training",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.canonicals {
        push_decl(
            &mut declarations,
            file,
            "canonical",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.artifacts {
        push_decl(
            &mut declarations,
            file,
            "artifact",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.lowerings {
        push_decl(
            &mut declarations,
            file,
            "lowering",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.executors {
        push_decl(
            &mut declarations,
            file,
            "executor",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.witnesses {
        push_decl(
            &mut declarations,
            file,
            "witness",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.machines {
        push_decl(
            &mut declarations,
            file,
            "machine",
            &decl.id,
            Some(decl.span),
        );
    }
    for decl in &ast.memories {
        push_decl(
            &mut declarations,
            file,
            "memory",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.instructions {
        push_decl(
            &mut declarations,
            file,
            "instruction",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.abis {
        push_decl(&mut declarations, file, "abi", &decl.name, Some(decl.span));
    }
    for decl in &ast.proof_artifacts {
        push_decl(
            &mut declarations,
            file,
            "proof-artifact",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.evolves {
        push_decl(
            &mut declarations,
            file,
            "evolve",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.ad {
        push_decl(&mut declarations, file, "ad", &decl.primal, Some(decl.span));
    }
    for decl in &ast.measures {
        push_decl(
            &mut declarations,
            file,
            "measure",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.theorems {
        push_decl(
            &mut declarations,
            file,
            "theorem",
            &decl.name,
            Some(decl.span),
        );
    }
    for decl in &ast.proofs {
        push_decl(
            &mut declarations,
            file,
            "proof",
            &decl.theorem,
            Some(decl.span),
        );
    }
    declarations
}

fn reference_summaries(file: &Path, ast: &WorldAst) -> Vec<ReferenceSummary> {
    let mut references = Vec::new();
    for decl in &ast.imports {
        push_ref(&mut references, file, "import", &decl.path, None);
    }
    for decl in &ast.effects {
        push_ref(
            &mut references,
            file,
            access_kind("resource", decl.access.clone()),
            &decl.resource,
            Some(&decl.name),
        );
    }
    for decl in &ast.externals {
        push_ref(
            &mut references,
            file,
            "external-interface",
            &decl.interface,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            access_kind("resource", decl.access.clone()),
            &decl.resource,
            Some(&decl.name),
        );
    }
    for decl in &ast.workspaces {
        push_ref(
            &mut references,
            file,
            access_kind("workspace-boundary", decl.access.clone()),
            &decl.boundary,
            Some(&decl.name),
        );
    }
    for decl in &ast.parsers {
        push_ref(
            &mut references,
            file,
            "parser-adapter",
            &decl.adapter,
            Some(&decl.name),
        );
    }
    for decl in &ast.documents {
        push_ref(
            &mut references,
            file,
            "document-adapter",
            &decl.adapter,
            Some(&decl.name),
        );
    }
    for decl in &ast.transforms {
        match &decl.target {
            TransformTargetDecl::Selection(name) => {
                push_ref(&mut references, file, "selection", name, Some(&decl.name));
            }
            TransformTargetDecl::File(path) => {
                push_ref(&mut references, file, "file", path, Some(&decl.name));
            }
        }
        if let Some(destination) = &decl.destination {
            push_ref(
                &mut references,
                file,
                "transform-destination",
                destination,
                Some(&decl.name),
            );
        }
    }
    for decl in &ast.validators {
        push_ref(
            &mut references,
            file,
            "validator-command",
            &decl.argv.join(" "),
            Some(&decl.name),
        );
    }
    for decl in &ast.objectives {
        push_ref(
            &mut references,
            file,
            "objective-priority",
            &decl.priority,
            Some(&decl.name),
        );
    }
    for decl in &ast.milestones {
        push_ref(
            &mut references,
            file,
            "objective",
            &decl.objective,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "milestone-state",
            &decl.state,
            Some(&decl.name),
        );
    }
    for decl in &ast.tasks {
        push_ref(
            &mut references,
            file,
            "milestone",
            &decl.milestone,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "task-owner",
            &decl.owner,
            Some(&decl.name),
        );
        for required in &decl.requires {
            push_ref(
                &mut references,
                file,
                "task-requires",
                required,
                Some(&decl.name),
            );
        }
        for output in &decl.outputs {
            push_ref(
                &mut references,
                file,
                "task-output",
                output,
                Some(&decl.name),
            );
        }
    }
    for decl in &ast.gates {
        push_ref(&mut references, file, "task", &decl.task, Some(&decl.name));
        push_ref(
            &mut references,
            file,
            "gate-check",
            &decl.check,
            Some(&decl.name),
        );
    }
    for decl in &ast.decisions {
        push_ref(
            &mut references,
            file,
            "decision-scope",
            &decl.scope,
            Some(&decl.name),
        );
        for alternative in &decl.alternatives {
            push_ref(
                &mut references,
                file,
                "decision-alternative",
                alternative,
                Some(&decl.name),
            );
        }
    }
    for decl in &ast.notes {
        push_ref(
            &mut references,
            file,
            "note-scope",
            &decl.scope,
            Some(&decl.name),
        );
        for tag in &decl.tags {
            push_ref(&mut references, file, "note-tag", tag, Some(&decl.name));
        }
    }
    for decl in &ast.graphics {
        for import in &decl.imports {
            push_ref(
                &mut references,
                file,
                "graphics-import",
                import,
                Some(&decl.name),
            );
        }
    }
    for decl in &ast.render_pipelines {
        push_ref(
            &mut references,
            file,
            "graphics",
            &decl.graphics,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "render-target",
            &decl.target,
            Some(&decl.name),
        );
    }
    for decl in &ast.benchmarks {
        push_ref(
            &mut references,
            file,
            "graphics",
            &decl.graphics,
            Some(&decl.name),
        );
    }
    for decl in &ast.datasets {
        push_ref(
            &mut references,
            file,
            "dataset-source",
            &decl.source,
            Some(&decl.name),
        );
        for tensor in &decl.tensors {
            push_ref(&mut references, file, "tensor", tensor, Some(&decl.name));
        }
    }
    for decl in &ast.models {
        push_ref(
            &mut references,
            file,
            "model-entry",
            &decl.entry,
            Some(&decl.name),
        );
        for input in &decl.inputs {
            push_ref(&mut references, file, "tensor", input, Some(&decl.name));
        }
        for parameter in &decl.parameters {
            push_ref(&mut references, file, "tensor", parameter, Some(&decl.name));
        }
        for output in &decl.outputs {
            push_ref(&mut references, file, "tensor", output, Some(&decl.name));
        }
    }
    for decl in &ast.trainings {
        push_ref(
            &mut references,
            file,
            "model",
            &decl.model,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "dataset",
            &decl.dataset,
            Some(&decl.name),
        );
        if let Some(artifact) = &decl.artifact {
            push_ref(
                &mut references,
                file,
                "artifact",
                artifact,
                Some(&decl.name),
            );
        }
        push_ref(
            &mut references,
            file,
            "accelerator",
            &decl.accelerator,
            Some(&decl.name),
        );
    }
    for decl in &ast.artifacts {
        push_ref(
            &mut references,
            file,
            "manifest",
            &decl.manifest,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "canonical",
            &decl.canonical,
            Some(&decl.name),
        );
        for tensor in &decl.tensors {
            push_ref(&mut references, file, "tensor", tensor, Some(&decl.name));
        }
    }
    for decl in &ast.lowerings {
        push_ref(
            &mut references,
            file,
            "model",
            &decl.model,
            Some(&decl.name),
        );
    }
    for decl in &ast.executors {
        push_ref(
            &mut references,
            file,
            "module",
            &decl.module,
            Some(&decl.name),
        );
        for artifact in &decl.read_artifacts {
            push_ref(
                &mut references,
                file,
                "read-artifact",
                artifact,
                Some(&decl.name),
            );
        }
        for path in &decl.write_paths {
            push_ref(&mut references, file, "write-path", path, Some(&decl.name));
        }
    }
    for decl in &ast.witnesses {
        push_ref(
            &mut references,
            file,
            "training",
            &decl.training,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "artifact",
            &decl.artifact,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "lowering",
            &decl.lowering,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "executor",
            &decl.executor,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "manifest",
            &decl.manifest,
            Some(&decl.name),
        );
    }
    for decl in &ast.machines {
        push_ref(
            &mut references,
            file,
            "semantic-source",
            &decl.semantic_source,
            Some(&decl.id),
        );
    }
    for decl in &ast.memories {
        push_ref(
            &mut references,
            file,
            "machine",
            &decl.machine,
            Some(&decl.name),
        );
    }
    for decl in &ast.instructions {
        push_ref(
            &mut references,
            file,
            "machine",
            &decl.machine,
            Some(&decl.name),
        );
        push_ref(
            &mut references,
            file,
            "proof-artifact",
            &decl.proof_artifact,
            Some(&decl.name),
        );
    }
    for decl in &ast.abis {
        push_ref(
            &mut references,
            file,
            "machine",
            &decl.machine,
            Some(&decl.name),
        );
    }
    for decl in &ast.proof_artifacts {
        push_ref(
            &mut references,
            file,
            "proof-module",
            &decl.module,
            Some(&decl.name),
        );
        for obligation in &decl.obligations {
            push_ref(
                &mut references,
                file,
                "proof-obligation",
                obligation,
                Some(&decl.name),
            );
        }
    }
    for decl in &ast.proofs {
        push_ref(
            &mut references,
            file,
            "theorem",
            &decl.theorem,
            Some(&decl.theorem),
        );
    }
    references
}

fn proof_coverage(ast: &WorldAst) -> ProofCoverage {
    let theorem_names = ast
        .theorems
        .iter()
        .map(|decl| decl.name.clone())
        .collect::<BTreeSet<_>>();
    let proof_names = ast
        .proofs
        .iter()
        .map(|decl| decl.theorem.clone())
        .collect::<BTreeSet<_>>();
    let missing_theorems = theorem_names
        .difference(&proof_names)
        .cloned()
        .collect::<Vec<_>>();
    let extra_proofs = proof_names
        .difference(&theorem_names)
        .cloned()
        .collect::<Vec<_>>();
    let proven_count = theorem_names.intersection(&proof_names).count();
    ProofCoverage {
        theorem_count: ast.theorems.len(),
        proof_count: ast.proofs.len(),
        proven_count,
        missing_count: missing_theorems.len(),
        extra_count: extra_proofs.len(),
        coverage_percent: coverage_percent(proven_count, ast.theorems.len()),
        missing_theorems,
        extra_proofs,
    }
}

fn build_readiness(
    summary: &InspectSummary,
    declaration_counts: &DeclarationCounts,
    proof_coverage: &ProofCoverage,
    files: &[FileInspection],
) -> ReadinessSignal {
    let mut risks = Vec::new();
    if summary.source_file_count == 0 {
        return ReadinessSignal {
            status: ReadinessStatus::Empty,
            score: 0,
            reasons: vec!["no supported sources were found".to_owned()],
            risks,
        };
    }
    if summary.error_count > 0 {
        risks.push(RiskSignal {
            level: RiskLevel::High,
            code: "blocking-diagnostics".to_owned(),
            message: "one or more sources did not complete inspection".to_owned(),
            path: None,
            count: summary.error_count,
        });
    }
    if summary.skipped_file_count > 0 {
        risks.push(RiskSignal {
            level: RiskLevel::Medium,
            code: "skipped-sources".to_owned(),
            message: "some sources were skipped by discovery or size settings".to_owned(),
            path: None,
            count: summary.skipped_file_count,
        });
    }
    if proof_coverage.missing_count > 0 {
        risks.push(RiskSignal {
            level: RiskLevel::High,
            code: "missing-proofs".to_owned(),
            message: "some theorem declarations lack matching proof blocks".to_owned(),
            path: None,
            count: proof_coverage.missing_count,
        });
    }
    let write_count = count_write_like_declarations(files);
    if write_count > 0 {
        risks.push(RiskSignal {
            level: RiskLevel::Medium,
            code: "write-boundaries".to_owned(),
            message: "write-capable resource, workspace, transform, or executor rows are present"
                .to_owned(),
            path: None,
            count: write_count,
        });
    }
    if declaration_counts.externals > 0 {
        risks.push(RiskSignal {
            level: RiskLevel::Medium,
            code: "external-boundaries".to_owned(),
            message: "external boundary declarations are present".to_owned(),
            path: None,
            count: declaration_counts.externals,
        });
    }
    if declaration_counts.validators > 0 {
        risks.push(RiskSignal {
            level: RiskLevel::Low,
            code: "validator-commands".to_owned(),
            message: "validator command rows are present".to_owned(),
            path: None,
            count: declaration_counts.validators,
        });
    }
    if declaration_counts.source_markers > 0 {
        risks.push(RiskSignal {
            level: RiskLevel::Low,
            code: "source-markers".to_owned(),
            message: "source marker comments are present".to_owned(),
            path: None,
            count: declaration_counts.source_markers,
        });
    }

    let mut score = 100i32;
    score -= (summary.error_count as i32 * 25).min(80);
    score -= (summary.warning_count as i32 * 5).min(30);
    score -= (proof_coverage.missing_count as i32 * 10).min(40);
    score -= (summary.skipped_file_count as i32 * 3).min(15);
    score -= risks
        .iter()
        .filter(|risk| risk.level == RiskLevel::Medium)
        .count() as i32
        * 4;
    score -= risks
        .iter()
        .filter(|risk| risk.level == RiskLevel::Low)
        .count() as i32
        * 2;
    let score = score.clamp(0, 100) as u8;

    let status = if summary.error_count > 0 {
        ReadinessStatus::Blocked
    } else if risks
        .iter()
        .any(|risk| matches!(risk.level, RiskLevel::High | RiskLevel::Medium))
        || summary.warning_count > 0
    {
        ReadinessStatus::NeedsAttention
    } else {
        ReadinessStatus::Ready
    };

    let mut reasons = Vec::new();
    if summary.verified_file_count + summary.mapped_file_count == summary.source_file_count {
        reasons.push("all discovered sources were mapped or verified".to_owned());
    } else {
        reasons.push(format!(
            "{} of {} discovered sources mapped or verified",
            summary.verified_file_count + summary.mapped_file_count,
            summary.source_file_count
        ));
    }
    if proof_coverage.theorem_count == 0 {
        reasons.push("no theorem declarations were found".to_owned());
    } else if proof_coverage.missing_count == 0 {
        reasons.push("every theorem declaration has a matching proof block".to_owned());
    } else {
        reasons.push(format!(
            "{} theorem declarations are missing proof blocks",
            proof_coverage.missing_count
        ));
    }

    ReadinessSignal {
        status,
        score,
        reasons,
        risks,
    }
}

fn count_write_like_declarations(files: &[FileInspection]) -> usize {
    files
        .iter()
        .flat_map(|file| file.references.iter())
        .filter(|reference| {
            matches!(
                reference.kind.as_str(),
                "resource-write"
                    | "workspace-boundary-write"
                    | "transform-destination"
                    | "write-path"
            )
        })
        .count()
}

fn access_kind(prefix: &'static str, access: EffectAccess) -> &'static str {
    match (prefix, access) {
        ("resource", EffectAccess::Read) => "resource-read",
        ("resource", EffectAccess::Write) => "resource-write",
        ("workspace-boundary", EffectAccess::Read) => "workspace-boundary-read",
        ("workspace-boundary", EffectAccess::Write) => "workspace-boundary-write",
        _ => prefix,
    }
}

fn code_file_kind(dialect: SourceDialect) -> &'static str {
    match dialect {
        SourceDialect::Rust => "rust-source",
        SourceDialect::C => "c-source",
        SourceDialect::Cpp => "cpp-source",
    }
}

fn code_import_kind(dialect: SourceDialect, kind: CodeImportKind) -> String {
    format!(
        "{}-{}",
        dialect.label(),
        import_kind_label(kind).replace('_', "-")
    )
}

fn code_import_ref_kind(kind: CodeImportKind) -> &'static str {
    match kind {
        CodeImportKind::Include => "source-include",
        CodeImportKind::Use => "source-use",
        CodeImportKind::Module => "source-module",
        CodeImportKind::ExternCrate => "source-extern-crate",
        CodeImportKind::Namespace => "source-namespace",
    }
}

fn code_symbol_kind(dialect: SourceDialect, kind: CodeSymbolKind) -> String {
    format!("{}-{}", dialect.label(), symbol_kind_label(kind))
}

fn code_marker_kind(dialect: SourceDialect, kind: CodeMarkerKind) -> String {
    format!("{}-{}", dialect.label(), marker_kind_label(kind))
}

fn push_decl(
    declarations: &mut Vec<DeclarationSummary>,
    file: &Path,
    kind: &str,
    name: &str,
    span: Option<SourceSpan>,
) {
    declarations.push(DeclarationSummary {
        file: file.to_path_buf(),
        kind: kind.to_owned(),
        name: name.to_owned(),
        span: span.map(Into::into),
    });
}

fn push_decl_code(
    declarations: &mut Vec<DeclarationSummary>,
    file: &Path,
    kind: &str,
    name: &str,
    span: Option<CodeSpan>,
) {
    declarations.push(DeclarationSummary {
        file: file.to_path_buf(),
        kind: kind.to_owned(),
        name: name.to_owned(),
        span: span.map(Into::into),
    });
}

fn push_ref(
    references: &mut Vec<ReferenceSummary>,
    file: &Path,
    kind: &str,
    value: &str,
    owner: Option<&str>,
) {
    if value.trim().is_empty() {
        return;
    }
    references.push(ReferenceSummary {
        file: file.to_path_buf(),
        kind: kind.to_owned(),
        value: value.to_owned(),
        owner: owner.map(str::to_owned),
    });
}

fn diagnostic(
    severity: DiagnosticSeverity,
    phase: InspectionPhase,
    path: Option<PathBuf>,
    message: String,
    span: Option<ByteSpan>,
) -> InspectionDiagnostic {
    InspectionDiagnostic {
        severity,
        phase,
        path,
        message,
        span,
    }
}

fn metadata_for(path: &Path, follow_symlinks: bool) -> std::io::Result<fs::Metadata> {
    if follow_symlinks {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    }
}

fn candidate_path(candidate: &SourceCandidate) -> &Path {
    match candidate {
        SourceCandidate::Inspect(path) => path,
        SourceCandidate::Skip { path, .. } => path,
    }
}

fn relative_path(root: &Path, root_is_file: bool, path: &Path) -> PathBuf {
    if root_is_file {
        return path
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf());
    }
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| path.to_path_buf())
}

fn is_ent_source(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "ent")
}

fn is_inspect_source(path: &Path) -> bool {
    is_ent_source(path) || SourceDialect::classify(path).is_some()
}

fn is_hidden_entry(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

fn is_ignored_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "target" | "build" | "node_modules" | ".build" | ".swiftpm"
            )
        })
}

fn line_count(source: &str) -> usize {
    if source.is_empty() {
        0
    } else {
        source.lines().count()
    }
}

fn coverage_percent(proven_count: usize, theorem_count: usize) -> Option<f32> {
    if theorem_count == 0 {
        None
    } else {
        Some((proven_count as f32 / theorem_count as f32) * 100.0)
    }
}

fn nonzero_declaration_counts(counts: &DeclarationCounts) -> BTreeMap<&'static str, usize> {
    let mut values = BTreeMap::new();
    macro_rules! insert_count {
        ($field:ident) => {
            if counts.$field > 0 {
                values.insert(stringify!($field), counts.$field);
            }
        };
    }
    insert_count!(modules);
    insert_count!(imports);
    insert_count!(functions);
    insert_count!(dimensions);
    insert_count!(states);
    insert_count!(relations);
    insert_count!(laws);
    insert_count!(invariants);
    insert_count!(effects);
    insert_count!(externals);
    insert_count!(workspaces);
    insert_count!(parsers);
    insert_count!(documents);
    insert_count!(selections);
    insert_count!(transforms);
    insert_count!(validators);
    insert_count!(objectives);
    insert_count!(milestones);
    insert_count!(tasks);
    insert_count!(gates);
    insert_count!(decisions);
    insert_count!(notes);
    insert_count!(graphics);
    insert_count!(render_targets);
    insert_count!(render_pipelines);
    insert_count!(benchmarks);
    insert_count!(tensors);
    insert_count!(accelerators);
    insert_count!(datasets);
    insert_count!(models);
    insert_count!(trainings);
    insert_count!(canonicals);
    insert_count!(artifacts);
    insert_count!(lowerings);
    insert_count!(executors);
    insert_count!(witnesses);
    insert_count!(machines);
    insert_count!(memories);
    insert_count!(instructions);
    insert_count!(abis);
    insert_count!(proof_artifacts);
    insert_count!(evolves);
    insert_count!(ad);
    insert_count!(measures);
    insert_count!(theorems);
    insert_count!(proofs);
    insert_count!(source_files);
    insert_count!(source_imports);
    insert_count!(source_symbols);
    insert_count!(source_markers);
    insert_count!(rust_sources);
    insert_count!(c_sources);
    insert_count!(cpp_sources);
    values
}

fn markdown_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', " ")
}

fn proof_label(coverage: &ProofCoverage) -> String {
    if coverage.theorem_count == 0 {
        "-".to_owned()
    } else if let Some(percent) = coverage.coverage_percent {
        format!(
            "{}/{} ({percent:.0}%)",
            coverage.proven_count, coverage.theorem_count
        )
    } else {
        format!("{}/{}", coverage.proven_count, coverage.theorem_count)
    }
}

fn file_status_label(status: FileStatus) -> &'static str {
    match status {
        FileStatus::Mapped => "mapped",
        FileStatus::Verified => "verified",
        FileStatus::ParseFailed => "parse failed",
        FileStatus::ElaborationFailed => "elaboration failed",
        FileStatus::VerificationFailed => "verification failed",
        FileStatus::ReadFailed => "read failed",
        FileStatus::Skipped => "skipped",
    }
}

fn readiness_label(status: ReadinessStatus) -> &'static str {
    match status {
        ReadinessStatus::Ready => "ready",
        ReadinessStatus::NeedsAttention => "needs attention",
        ReadinessStatus::Blocked => "blocked",
        ReadinessStatus::Empty => "empty",
    }
}

fn risk_level_label(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
    }
}

fn severity_label(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

fn phase_label(phase: InspectionPhase) -> &'static str {
    match phase {
        InspectionPhase::Discover => "discover",
        InspectionPhase::Read => "read",
        InspectionPhase::Parse => "parse",
        InspectionPhase::Elaborate => "elaborate",
        InspectionPhase::Verify => "verify",
    }
}

fn phase_order(phase: InspectionPhase) -> u8 {
    match phase {
        InspectionPhase::Discover => 0,
        InspectionPhase::Read => 1,
        InspectionPhase::Parse => 2,
        InspectionPhase::Elaborate => 3,
        InspectionPhase::Verify => 4,
    }
}

fn severity_order(severity: DiagnosticSeverity) -> u8 {
    match severity {
        DiagnosticSeverity::Error => 0,
        DiagnosticSeverity::Warning => 1,
        DiagnosticSeverity::Info => 2,
    }
}

fn instability_kind(kind: &ent_core::InstabilityKind) -> &'static str {
    match kind {
        ent_core::InstabilityKind::UnsupportedVersion => "unsupported-version",
        ent_core::InstabilityKind::EvidenceMissing => "evidence-missing",
        ent_core::InstabilityKind::BadRelation => "bad-relation",
        ent_core::InstabilityKind::MissingMidpoint => "missing-midpoint",
        ent_core::InstabilityKind::ModalTruthMismatch => "modal-truth-mismatch",
        ent_core::InstabilityKind::DiamondWitnessInvalid => "diamond-witness-invalid",
        ent_core::InstabilityKind::FactorClosureFailure => "factor-closure-failure",
        ent_core::InstabilityKind::CoordinateSeparationFailure => "coordinate-separation-failure",
        ent_core::InstabilityKind::InvariantDrift => "invariant-drift",
        ent_core::InstabilityKind::ResourceConflict => "resource-conflict",
        ent_core::InstabilityKind::ProbabilityDrift => "probability-drift",
        ent_core::InstabilityKind::AdContractViolation => "ad-contract-violation",
        ent_core::InstabilityKind::BackendInadmissible => "backend-inadmissible",
        ent_core::InstabilityKind::ExternalInadmissible => "external-inadmissible",
        ent_core::InstabilityKind::WorkspaceInadmissible => "workspace-inadmissible",
        ent_core::InstabilityKind::ParserInadmissible => "parser-inadmissible",
        ent_core::InstabilityKind::SelectionInadmissible => "selection-inadmissible",
        ent_core::InstabilityKind::TransformInadmissible => "transform-inadmissible",
        ent_core::InstabilityKind::ValidatorInadmissible => "validator-inadmissible",
        ent_core::InstabilityKind::ObjectiveInadmissible => "objective-inadmissible",
        ent_core::InstabilityKind::MilestoneInadmissible => "milestone-inadmissible",
        ent_core::InstabilityKind::TaskInadmissible => "task-inadmissible",
        ent_core::InstabilityKind::GateInadmissible => "gate-inadmissible",
        ent_core::InstabilityKind::DecisionInadmissible => "decision-inadmissible",
        ent_core::InstabilityKind::NoteInadmissible => "note-inadmissible",
        ent_core::InstabilityKind::GraphicsInadmissible => "graphics-inadmissible",
        ent_core::InstabilityKind::RenderTargetInadmissible => "render-target-inadmissible",
        ent_core::InstabilityKind::RenderPipelineInadmissible => "render-pipeline-inadmissible",
        ent_core::InstabilityKind::BenchmarkInadmissible => "benchmark-inadmissible",
        ent_core::InstabilityKind::TensorInadmissible => "tensor-inadmissible",
        ent_core::InstabilityKind::AcceleratorInadmissible => "accelerator-inadmissible",
        ent_core::InstabilityKind::DatasetInadmissible => "dataset-inadmissible",
        ent_core::InstabilityKind::ModelInadmissible => "model-inadmissible",
        ent_core::InstabilityKind::TrainingInadmissible => "training-inadmissible",
        ent_core::InstabilityKind::CanonicalInadmissible => "canonical-inadmissible",
        ent_core::InstabilityKind::ArtifactInadmissible => "artifact-inadmissible",
        ent_core::InstabilityKind::LoweringInadmissible => "lowering-inadmissible",
        ent_core::InstabilityKind::ExecutorInadmissible => "executor-inadmissible",
        ent_core::InstabilityKind::WitnessInadmissible => "witness-inadmissible",
        ent_core::InstabilityKind::MachineInadmissible => "machine-inadmissible",
        ent_core::InstabilityKind::MemoryInadmissible => "memory-inadmissible",
        ent_core::InstabilityKind::InstructionInadmissible => "instruction-inadmissible",
        ent_core::InstabilityKind::AbiInadmissible => "abi-inadmissible",
        ent_core::InstabilityKind::ProofArtifactInadmissible => "proof-artifact-inadmissible",
        ent_core::InstabilityKind::ProofGap => "proof-gap",
        ent_core::InstabilityKind::RootFormulaMissing => "root-formula-missing",
        ent_core::InstabilityKind::UnknownReference => "unknown-reference",
    }
}

impl From<SourceSpan> for ByteSpan {
    fn from(span: SourceSpan) -> Self {
        Self {
            start: span.start,
            end: span.end,
        }
    }
}

impl From<CodeSpan> for ByteSpan {
    fn from(span: CodeSpan) -> Self {
        Self {
            start: span.start,
            end: span.end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const VERIFIED_SOURCE: &str = r#"
world VerifiedStore(role Client, space Workspace) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<Client>] preserves truth changes heap[c]
  invariant auth_preserved(heap) before 1.0 after 1.0 tolerance 0.0 evidence auth_trace
  effect put uses heap write evidence heap_put_single_writer
  theorem causal_step : dev_frame(step)
  theorem linear_heap : resource_linear(heap)
  theorem auth_ok : invariant_preserved(auth_preserved)
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
  proof auth_ok {
    let row = row invariant auth_preserved
    let fact = rule invariant_preserved_from_invariant(row)
    qed fact
  }
}
"#;

    #[test]
    fn inspects_single_verified_source() {
        let dir = tempdir().expect("tempdir");
        let source_path = dir.path().join("verified.ent");
        fs::write(&source_path, VERIFIED_SOURCE).expect("write source");

        let report = inspect_path(&source_path, InspectOptions::default()).expect("inspect");

        assert_eq!(report.summary.source_file_count, 1);
        assert_eq!(report.summary.verified_file_count, 1);
        assert_eq!(report.summary.error_count, 0);
        assert_eq!(report.files[0].world.as_deref(), Some("VerifiedStore"));
        assert_eq!(report.proof_coverage.proven_count, 3);
        assert!(report.certificate_rows.total > 0);
        assert_eq!(report.readiness.status, ReadinessStatus::NeedsAttention);
        assert!(report
            .references
            .iter()
            .any(|reference| reference.kind == "resource-write" && reference.value == "heap"));
    }

    #[test]
    fn walks_sources_in_deterministic_order_and_reports_parse_errors() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("z.ent"), "world Bad(role X) {\n  nope\n}\n")
            .expect("write bad source");
        fs::write(dir.path().join("a.ent"), VERIFIED_SOURCE).expect("write good source");
        fs::write(dir.path().join("ignore.txt"), "world Noop(role X) {}").expect("write ignored");
        fs::create_dir_all(dir.path().join("target")).expect("target dir");
        fs::write(
            dir.path().join("target/generated.rs"),
            "pub fn generated() {}",
        )
        .expect("write generated source");

        let report = inspect_path(dir.path(), InspectOptions::default()).expect("inspect");

        let paths = report
            .files
            .iter()
            .map(|file| file.relative_path.clone())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec![PathBuf::from("a.ent"), PathBuf::from("z.ent")]);
        assert_eq!(report.summary.source_file_count, 2);
        assert_eq!(report.summary.verified_file_count, 1);
        assert_eq!(report.summary.parse_failed_file_count, 1);
        assert_eq!(report.readiness.status, ReadinessStatus::Blocked);
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.phase == InspectionPhase::Parse));
    }

    #[test]
    fn renders_markdown_without_runtime_context() {
        let dir = tempdir().expect("tempdir");
        let source_path = dir.path().join("verified.ent");
        fs::write(&source_path, VERIFIED_SOURCE).expect("write source");
        let report = inspect_path(&source_path, InspectOptions::default()).expect("inspect");

        let markdown = render_markdown(&report);

        assert!(markdown.contains("Entanglement Inspection"));
        assert!(markdown.contains("verified.ent"));
        assert!(markdown.contains("Checked rows"));
        assert!(!markdown.contains("AI"));
    }

    #[test]
    fn maps_rust_and_cpp_sources_next_to_ent_sources() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("verified.ent"), VERIFIED_SOURCE).expect("write source");
        fs::write(
            dir.path().join("src/lib.rs"),
            r#"
use std::fmt;

pub struct Store {
    value: usize,
}

pub fn run_store() {
    helper();
}

fn helper() {}
"#,
        )
        .expect("write rust");
        fs::write(
            dir.path().join("engine.cpp"),
            r#"
#include "engine.hpp"

namespace demo {
class Engine {
public:
    void tick();
};

void Engine::tick() {
    update();
}

void update() {}
}
"#,
        )
        .expect("write cpp");

        let report = inspect_path(dir.path(), InspectOptions::default()).expect("inspect");

        assert_eq!(report.summary.source_file_count, 3);
        assert_eq!(report.summary.verified_file_count, 1);
        assert_eq!(report.summary.mapped_file_count, 2);
        assert!(report
            .declarations
            .iter()
            .any(|decl| decl.kind == "rust-function" && decl.name == "run_store"));
        assert!(report
            .declarations
            .iter()
            .any(|decl| decl.kind == "cpp-function" || decl.kind == "cpp-method"));
        assert!(
            report
                .references
                .iter()
                .any(|reference| reference.kind == "source-call"
                    && reference.value.contains("helper"))
        );
        assert!(
            report
                .references
                .iter()
                .any(|reference| reference.kind == "source-include"
                    && reference.value == "engine.hpp")
        );
    }

    #[test]
    fn report_is_serde_serializable() {
        let dir = tempdir().expect("tempdir");
        let source_path = dir.path().join("verified.ent");
        fs::write(&source_path, VERIFIED_SOURCE).expect("write source");
        let report = inspect_path(&source_path, InspectOptions::default()).expect("inspect");

        let json = serde_json::to_string(&report).expect("serialize report");
        let decoded: InspectReport = serde_json::from_str(&json).expect("deserialize report");

        assert_eq!(decoded.summary.verified_file_count, 1);
    }
}
