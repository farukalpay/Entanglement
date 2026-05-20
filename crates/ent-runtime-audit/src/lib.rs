use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const RUNTIME_SCHEMA_VERSION: u32 = 1;
pub const RUNTIME_OWNER: &str = "entanglement";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAuditOptions {
    pub recursive: bool,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub max_file_bytes: Option<u64>,
}

impl Default for RuntimeAuditOptions {
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
pub struct RuntimeAuditReport {
    pub schema_version: u32,
    pub root: PathBuf,
    pub options: RuntimeAuditOptions,
    pub summary: RuntimeSummary,
    pub readiness: RuntimeReadiness,
    pub topology: RuntimeTopology,
    pub crates: Vec<RuntimeCrate>,
    pub components: Vec<RuntimeComponent>,
    pub flows: Vec<RuntimeFlowEdge>,
    pub files: Vec<RuntimeFile>,
    pub findings: Vec<RuntimeFinding>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSummary {
    pub source_file_count: usize,
    pub audited_file_count: usize,
    pub skipped_file_count: usize,
    pub read_failed_file_count: usize,
    pub crate_count: usize,
    pub component_count: usize,
    pub flow_count: usize,
    pub byte_count: u64,
    pub line_count: usize,
    pub signal_count: usize,
    pub finding_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeReadiness {
    pub status: RuntimeReadinessStatus,
    pub score: u8,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeReadinessStatus {
    Ready,
    NeedsAttention,
    Blocked,
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTopology {
    pub owner: String,
    pub components_by_kind: BTreeMap<String, Vec<String>>,
    pub ownership: Vec<RuntimeOwnership>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeOwnership {
    pub owner: String,
    pub component: String,
    pub policy: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeComponentKind {
    RuntimeCore,
    SessionRuntime,
    TurnScheduler,
    TaskLane,
    EventLedger,
    Storage,
    ToolSurface,
    ExecPolicy,
    SandboxBoundary,
    HookRuntime,
    SkillRegistry,
    PluginRegistry,
    McpBridge,
    ModelProvider,
    AppServer,
    ApiProtocol,
    RealtimeBridge,
    Connector,
    FileWatcher,
    PatchEngine,
    ReviewGate,
    ConfigSurface,
    CloudTask,
    Identity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCrate {
    pub name: String,
    pub manifest: PathBuf,
    pub root: PathBuf,
    pub roles: Vec<RuntimeComponentKind>,
    pub dependencies: Vec<String>,
    pub public_modules: Vec<String>,
    pub score: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeComponent {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub kind: RuntimeComponentKind,
    pub files: Vec<PathBuf>,
    pub crates: Vec<String>,
    pub signals: Vec<String>,
    pub evidence: Vec<RuntimeEvidence>,
    pub confidence: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvidence {
    pub path: PathBuf,
    pub signal: String,
    pub strength: RuntimeEvidenceStrength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeEvidenceStrength {
    Weak,
    Medium,
    Strong,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFlowEdge {
    pub from: String,
    pub to: String,
    pub kind: RuntimeFlowKind,
    pub evidence: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeFlowKind {
    Schedules,
    Persists,
    Guards,
    Exposes,
    Loads,
    Bridges,
    Invokes,
    Observes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFile {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub status: RuntimeFileStatus,
    pub bytes: u64,
    pub lines: usize,
    pub sha256: Option<String>,
    pub crate_name: Option<String>,
    pub roles: Vec<RuntimeComponentKind>,
    pub signals: Vec<RuntimeSignal>,
    pub findings: Vec<RuntimeFinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeFileStatus {
    Audited,
    Skipped,
    ReadFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSignal {
    pub kind: RuntimeComponentKind,
    pub phrase: String,
    pub weight: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFinding {
    pub severity: RuntimeFindingSeverity,
    pub code: String,
    pub message: String,
    pub path: Option<PathBuf>,
    pub component: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeFindingSeverity {
    Info,
    Warning,
    Error,
}

pub fn audit_runtime_path(root: &Path, options: RuntimeAuditOptions) -> Result<RuntimeAuditReport> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))?;
    RuntimeSurveyor { root, options }.audit()
}

pub fn has_blocking_findings(report: &RuntimeAuditReport) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.severity == RuntimeFindingSeverity::Error)
}

pub fn render_markdown(report: &RuntimeAuditReport) -> String {
    let mut out = String::new();
    out.push_str("# Entanglement Runtime Ledger\n\n");
    out.push_str(&format!("- Root: `{}`\n", report.root.display()));
    out.push_str(&format!(
        "- Owner: `{}`\n- Status: {} (score {}/100)\n",
        markdown_cell(&report.topology.owner),
        readiness_label(report.readiness.status),
        report.readiness.score
    ));
    out.push_str(&format!(
        "- Sources: {} audited, {} skipped, {} read failed\n",
        report.summary.audited_file_count,
        report.summary.skipped_file_count,
        report.summary.read_failed_file_count
    ));
    out.push_str(&format!(
        "- Crates: {} | Components: {} | Flows: {} | Findings: {}\n\n",
        report.summary.crate_count,
        report.summary.component_count,
        report.summary.flow_count,
        report.summary.finding_count
    ));

    out.push_str("## Readiness\n\n");
    if report.readiness.reasons.is_empty() {
        out.push_str("- No readiness notes.\n");
    } else {
        for reason in &report.readiness.reasons {
            out.push_str(&format!("- {}\n", markdown_cell(reason)));
        }
    }

    out.push_str("\n## Components\n\n");
    if report.components.is_empty() {
        out.push_str("No runtime architecture components were discovered.\n");
    } else {
        out.push_str("| Component | Kind | Confidence | Crates | Signals |\n");
        out.push_str("| --- | --- | ---: | --- | --- |\n");
        for component in &report.components {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                markdown_cell(&component.name),
                component_kind_label(component.kind),
                component.confidence,
                markdown_cell(&component.crates.join(", ")),
                markdown_cell(
                    &component
                        .signals
                        .iter()
                        .take(6)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            ));
        }
    }

    out.push_str("\n## Flows\n\n");
    if report.flows.is_empty() {
        out.push_str("No runtime flows were inferred.\n");
    } else {
        out.push_str("| From | Flow | To | Evidence |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for edge in &report.flows {
            out.push_str(&format!(
                "| `{}` | {} | `{}` | {} |\n",
                markdown_cell(&edge.from),
                flow_kind_label(edge.kind),
                markdown_cell(&edge.to),
                markdown_cell(&edge.evidence)
            ));
        }
    }

    out.push_str("\n## Crates\n\n");
    if report.crates.is_empty() {
        out.push_str("No Rust package manifests were discovered.\n");
    } else {
        out.push_str("| Crate | Score | Roles | Public Modules | Dependencies |\n");
        out.push_str("| --- | ---: | --- | --- | --- |\n");
        for krate in &report.crates {
            let roles = krate
                .roles
                .iter()
                .map(|role| component_kind_label(*role))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                markdown_cell(&krate.name),
                krate.score,
                markdown_cell(&roles),
                markdown_cell(&krate.public_modules.join(", ")),
                markdown_cell(
                    &krate
                        .dependencies
                        .iter()
                        .take(10)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            ));
        }
    }

    out.push_str("\n## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("No findings were reported.\n");
    } else {
        out.push_str("| Severity | Code | Location | Message |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for finding in &report.findings {
            let location = finding
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_owned());
            out.push_str(&format!(
                "| {} | `{}` | `{}` | {} |\n",
                finding_severity_label(finding.severity),
                markdown_cell(&finding.code),
                markdown_cell(&location),
                markdown_cell(&finding.message)
            ));
        }
    }

    out
}

struct RuntimeSurveyor {
    root: PathBuf,
    options: RuntimeAuditOptions,
}

impl RuntimeSurveyor {
    fn audit(&self) -> Result<RuntimeAuditReport> {
        let source_paths = discover_sources(&self.root, &self.options)?;
        let manifest_paths = discover_manifests(&self.root, &self.options)?;
        let manifests = manifest_paths
            .iter()
            .filter_map(|manifest| read_manifest(manifest, &self.root).transpose())
            .collect::<Result<Vec<_>>>()?;
        let mut files = Vec::with_capacity(source_paths.len());
        for source_path in source_paths {
            files.push(self.audit_file(source_path, &manifests));
        }

        let crates = crates_from_manifests(&manifests, &files);
        let components = components_from_files(&files);
        let flows = infer_flows(&components);
        let mut findings = collect_findings(&files, &crates, &components, &flows);
        findings.sort_by(|lhs, rhs| {
            lhs.severity
                .cmp(&rhs.severity)
                .then_with(|| lhs.code.cmp(&rhs.code))
                .then_with(|| lhs.message.cmp(&rhs.message))
        });
        let summary = summarize(&files, &crates, &components, &flows, &findings);
        let readiness = readiness_from_summary(&summary, &components, &findings);
        let topology = topology_from_components(&components);

        Ok(RuntimeAuditReport {
            schema_version: RUNTIME_SCHEMA_VERSION,
            root: self.root.clone(),
            options: self.options.clone(),
            summary,
            readiness,
            topology,
            crates,
            components,
            flows,
            files,
            findings,
        })
    }

    fn audit_file(&self, path: PathBuf, manifests: &[CargoManifest]) -> RuntimeFile {
        let relative_path = relative_path(&self.root, &path);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return RuntimeFile {
                    path,
                    relative_path: relative_path.clone(),
                    status: RuntimeFileStatus::ReadFailed,
                    bytes: 0,
                    lines: 0,
                    sha256: None,
                    crate_name: None,
                    roles: vec![],
                    signals: vec![],
                    findings: vec![finding(
                        RuntimeFindingSeverity::Error,
                        "read-failed",
                        format!("failed to read metadata: {error}"),
                        Some(relative_path),
                        None,
                    )],
                };
            }
        };

        if self
            .options
            .max_file_bytes
            .is_some_and(|max| metadata.len() > max)
        {
            return RuntimeFile {
                path,
                relative_path,
                status: RuntimeFileStatus::Skipped,
                bytes: metadata.len(),
                lines: 0,
                sha256: None,
                crate_name: None,
                roles: vec![],
                signals: vec![],
                findings: vec![finding(
                    RuntimeFindingSeverity::Info,
                    "file-skipped",
                    "file exceeds configured byte limit",
                    None,
                    None,
                )],
            };
        }

        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return RuntimeFile {
                    path,
                    relative_path: relative_path.clone(),
                    status: RuntimeFileStatus::ReadFailed,
                    bytes: metadata.len(),
                    lines: 0,
                    sha256: None,
                    crate_name: None,
                    roles: vec![],
                    signals: vec![],
                    findings: vec![finding(
                        RuntimeFindingSeverity::Error,
                        "read-failed",
                        format!("failed to read source: {error}"),
                        Some(relative_path),
                        None,
                    )],
                };
            }
        };
        let sha256 = Some(sha256_uri(&bytes));
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(error) => {
                return RuntimeFile {
                    path,
                    relative_path: relative_path.clone(),
                    status: RuntimeFileStatus::Skipped,
                    bytes: bytes.len() as u64,
                    lines: 0,
                    sha256,
                    crate_name: None,
                    roles: vec![],
                    signals: vec![],
                    findings: vec![finding(
                        RuntimeFindingSeverity::Error,
                        "not-utf8",
                        format!("source is not valid UTF-8: {error}"),
                        Some(relative_path),
                        None,
                    )],
                };
            }
        };
        let signals = runtime_signals(&relative_path, text);
        let roles = roles_from_signals(&signals);
        let crate_name = crate_for_path(&path, manifests).map(str::to_owned);
        let findings = file_findings(&relative_path, text, &signals);

        RuntimeFile {
            path,
            relative_path,
            status: RuntimeFileStatus::Audited,
            bytes: bytes.len() as u64,
            lines: text.lines().count(),
            sha256,
            crate_name,
            roles,
            signals,
            findings,
        }
    }
}

#[derive(Clone, Debug)]
struct CargoManifest {
    name: String,
    manifest: PathBuf,
    root: PathBuf,
    dependencies: Vec<String>,
    public_modules: Vec<String>,
}

#[derive(Default)]
struct ComponentAccum {
    files: BTreeSet<PathBuf>,
    crates: BTreeSet<String>,
    signals: BTreeSet<String>,
    evidence: Vec<RuntimeEvidence>,
    weight: u32,
}

fn discover_sources(root: &Path, options: &RuntimeAuditOptions) -> Result<Vec<PathBuf>> {
    let mut sources = Vec::new();
    if root.is_file() {
        if is_architecture_source(root) {
            sources.push(root.to_path_buf());
        }
        return Ok(sources);
    }
    discover_sources_inner(root, options, &mut sources)?;
    sources.sort();
    sources.dedup();
    Ok(sources)
}

fn discover_sources_inner(
    dir: &Path,
    options: &RuntimeAuditOptions,
    sources: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to enumerate {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_type = if options.follow_symlinks {
            entry.metadata()?.file_type()
        } else {
            entry.file_type()?
        };
        if file_type.is_dir() {
            if options.recursive && should_enter_dir(&path, options.include_hidden) {
                discover_sources_inner(&path, options, sources)?;
            }
        } else if file_type.is_file() && is_architecture_source(&path) {
            sources.push(path);
        }
    }
    Ok(())
}

fn discover_manifests(root: &Path, options: &RuntimeAuditOptions) -> Result<Vec<PathBuf>> {
    let mut manifests = Vec::new();
    if root.is_file() {
        if root.file_name().is_some_and(|name| name == "Cargo.toml") {
            manifests.push(root.to_path_buf());
        }
        return Ok(manifests);
    }
    discover_manifests_inner(root, options, &mut manifests)?;
    manifests.sort();
    manifests.dedup();
    Ok(manifests)
}

fn discover_manifests_inner(
    dir: &Path,
    options: &RuntimeAuditOptions,
    manifests: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to enumerate {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_type = if options.follow_symlinks {
            entry.metadata()?.file_type()
        } else {
            entry.file_type()?
        };
        if file_type.is_dir() {
            if options.recursive && should_enter_dir(&path, options.include_hidden) {
                discover_manifests_inner(&path, options, manifests)?;
            }
        } else if file_type.is_file() && path.file_name().is_some_and(|name| name == "Cargo.toml") {
            manifests.push(path);
        }
    }
    Ok(())
}

fn should_enter_dir(path: &Path, include_hidden: bool) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    if matches!(
        name,
        "target" | "node_modules" | ".git" | ".hg" | ".svn" | ".jj" | "dist" | "build"
    ) {
        return false;
    }
    include_hidden || !name.starts_with('.')
}

fn is_architecture_source(path: &Path) -> bool {
    if path.file_name().is_some_and(|name| name == "Cargo.toml") {
        return true;
    }
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return false;
    };
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "rs" | "toml" | "md" | "ts" | "tsx" | "js" | "jsx" | "py"
    )
}

fn read_manifest(path: &Path, root: &Path) -> Result<Option<CargoManifest>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let Some(name) = package_name(&text) else {
        return Ok(None);
    };
    let manifest = relative_path(root, path);
    let crate_root = path.parent().unwrap_or(path).to_path_buf();
    let public_modules = public_modules(&crate_root.join("src/lib.rs")).unwrap_or_default();
    Ok(Some(CargoManifest {
        name,
        manifest,
        root: crate_root,
        dependencies: dependency_names(&text),
        public_modules,
    }))
}

fn package_name(text: &str) -> Option<String> {
    let mut in_package = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[package]" {
            in_package = true;
            continue;
        }
        if in_package && trimmed.starts_with('[') {
            return None;
        }
        if in_package && trimmed.starts_with("name") {
            return quoted_value(trimmed);
        }
    }
    None
}

fn dependency_names(text: &str) -> Vec<String> {
    let mut dependencies = BTreeSet::new();
    let mut in_deps = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if matches!(
            trimmed,
            "[dependencies]" | "[dev-dependencies]" | "[build-dependencies]"
        ) {
            in_deps = true;
            continue;
        }
        if in_deps && trimmed.starts_with('[') {
            in_deps = false;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            dependencies.insert(name.trim().trim_matches('"').to_owned());
        }
    }
    dependencies.into_iter().collect()
}

fn public_modules(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let modules = text
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let rest = trimmed
                .strip_prefix("pub mod ")
                .or_else(|| trimmed.strip_prefix("pub(crate) mod "))?;
            let name = rest
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .next()
                .unwrap_or_default();
            if name.is_empty() {
                None
            } else {
                Some(name.to_owned())
            }
        })
        .collect::<BTreeSet<_>>();
    Ok(modules.into_iter().collect())
}

fn quoted_value(trimmed: &str) -> Option<String> {
    let (_, value) = trimmed.split_once('=')?;
    let value = value.trim();
    if !value.starts_with('"') {
        return None;
    }
    let value = value.trim_matches('"');
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn crate_for_path<'a>(path: &Path, manifests: &'a [CargoManifest]) -> Option<&'a str> {
    manifests
        .iter()
        .filter(|manifest| path.starts_with(&manifest.root))
        .max_by_key(|manifest| manifest.root.components().count())
        .map(|manifest| manifest.name.as_str())
}

fn crates_from_manifests(manifests: &[CargoManifest], files: &[RuntimeFile]) -> Vec<RuntimeCrate> {
    let mut crates = manifests
        .iter()
        .map(|manifest| {
            let roles = files
                .iter()
                .filter(|file| file.crate_name.as_deref() == Some(manifest.name.as_str()))
                .flat_map(|file| file.roles.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let score = crate_score(
                &roles,
                manifest.dependencies.len(),
                manifest.public_modules.len(),
            );
            RuntimeCrate {
                name: manifest.name.clone(),
                manifest: manifest.manifest.clone(),
                root: manifest
                    .root
                    .file_name()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(".")),
                roles,
                dependencies: manifest.dependencies.clone(),
                public_modules: manifest.public_modules.clone(),
                score,
            }
        })
        .collect::<Vec<_>>();
    crates.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    crates
}

fn crate_score(roles: &[RuntimeComponentKind], dependency_count: usize, module_count: usize) -> u8 {
    let role_score = (roles.len() as u8).saturating_mul(12).min(72);
    let dependency_score = if dependency_count == 0 {
        4
    } else {
        (dependency_count as u8).saturating_mul(2).min(14)
    };
    let module_score = (module_count as u8).saturating_mul(2).min(14);
    role_score
        .saturating_add(dependency_score)
        .saturating_add(module_score)
}

fn components_from_files(files: &[RuntimeFile]) -> Vec<RuntimeComponent> {
    let mut accums: BTreeMap<RuntimeComponentKind, ComponentAccum> = BTreeMap::new();
    for file in files
        .iter()
        .filter(|file| file.status == RuntimeFileStatus::Audited)
    {
        for signal in &file.signals {
            let accum = accums.entry(signal.kind).or_default();
            accum.files.insert(file.relative_path.clone());
            if let Some(crate_name) = &file.crate_name {
                accum.crates.insert(crate_name.clone());
            }
            accum.signals.insert(signal.phrase.clone());
            accum.weight += u32::from(signal.weight);
            accum.evidence.push(RuntimeEvidence {
                path: file.relative_path.clone(),
                signal: signal.phrase.clone(),
                strength: evidence_strength(signal.weight),
            });
        }
    }

    let mut components = accums
        .into_iter()
        .map(|(kind, mut accum)| {
            accum.evidence.sort_by(|lhs, rhs| {
                rhs.strength
                    .cmp(&lhs.strength)
                    .then_with(|| lhs.path.cmp(&rhs.path))
                    .then_with(|| lhs.signal.cmp(&rhs.signal))
            });
            accum.evidence.truncate(16);
            RuntimeComponent {
                id: component_id(kind),
                owner: RUNTIME_OWNER.to_owned(),
                name: component_name(kind).to_owned(),
                kind,
                files: accum.files.into_iter().collect(),
                crates: accum.crates.into_iter().collect(),
                signals: accum.signals.into_iter().collect(),
                confidence: confidence_from_weight(accum.weight),
                evidence: accum.evidence,
            }
        })
        .collect::<Vec<_>>();
    components.sort_by(|lhs, rhs| lhs.kind.cmp(&rhs.kind));
    components
}

fn infer_flows(components: &[RuntimeComponent]) -> Vec<RuntimeFlowEdge> {
    let ids = components
        .iter()
        .map(|component| (component.kind, component.id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut flows = Vec::new();
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::SessionRuntime,
        RuntimeFlowKind::Schedules,
        RuntimeComponentKind::TurnScheduler,
        "session runtime owns turn admission",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::TurnScheduler,
        RuntimeFlowKind::Invokes,
        RuntimeComponentKind::ToolSurface,
        "turn execution invokes declared tools",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::ToolSurface,
        RuntimeFlowKind::Guards,
        RuntimeComponentKind::ExecPolicy,
        "tool calls are checked by execution policy",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::ExecPolicy,
        RuntimeFlowKind::Guards,
        RuntimeComponentKind::SandboxBoundary,
        "policy decisions select sandbox boundaries",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::SessionRuntime,
        RuntimeFlowKind::Persists,
        RuntimeComponentKind::EventLedger,
        "sessions append turn and item events",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::EventLedger,
        RuntimeFlowKind::Persists,
        RuntimeComponentKind::Storage,
        "ledger rows settle into durable stores",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::HookRuntime,
        RuntimeFlowKind::Observes,
        RuntimeComponentKind::ToolSurface,
        "hooks observe pre and post tool events",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::SkillRegistry,
        RuntimeFlowKind::Loads,
        RuntimeComponentKind::ToolSurface,
        "skills enrich the callable tool surface",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::PluginRegistry,
        RuntimeFlowKind::Loads,
        RuntimeComponentKind::ToolSurface,
        "plugins contribute tools and connectors",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::McpBridge,
        RuntimeFlowKind::Bridges,
        RuntimeComponentKind::ToolSurface,
        "MCP bridges remote tools into Runtime calls",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::ModelProvider,
        RuntimeFlowKind::Invokes,
        RuntimeComponentKind::TurnScheduler,
        "model streams drive turn progression",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::AppServer,
        RuntimeFlowKind::Exposes,
        RuntimeComponentKind::ApiProtocol,
        "app server exposes protocol methods",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::ApiProtocol,
        RuntimeFlowKind::Exposes,
        RuntimeComponentKind::SessionRuntime,
        "protocol methods address sessions",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::RealtimeBridge,
        RuntimeFlowKind::Bridges,
        RuntimeComponentKind::TurnScheduler,
        "realtime channels feed live turn deltas",
    );
    add_flow(
        &ids,
        &mut flows,
        RuntimeComponentKind::PatchEngine,
        RuntimeFlowKind::Invokes,
        RuntimeComponentKind::ReviewGate,
        "patch previews are reviewable gate inputs",
    );
    flows.sort_by(|lhs, rhs| {
        lhs.from
            .cmp(&rhs.from)
            .then_with(|| lhs.to.cmp(&rhs.to))
            .then_with(|| lhs.kind.cmp(&rhs.kind))
    });
    flows
}

fn add_flow(
    ids: &BTreeMap<RuntimeComponentKind, String>,
    flows: &mut Vec<RuntimeFlowEdge>,
    from: RuntimeComponentKind,
    kind: RuntimeFlowKind,
    to: RuntimeComponentKind,
    evidence: &str,
) {
    let (Some(from), Some(to)) = (ids.get(&from), ids.get(&to)) else {
        return;
    };
    flows.push(RuntimeFlowEdge {
        from: from.clone(),
        to: to.clone(),
        kind,
        evidence: evidence.to_owned(),
    });
}

fn collect_findings(
    files: &[RuntimeFile],
    crates: &[RuntimeCrate],
    components: &[RuntimeComponent],
    flows: &[RuntimeFlowEdge],
) -> Vec<RuntimeFinding> {
    let mut findings = files
        .iter()
        .flat_map(|file| file.findings.iter().cloned())
        .collect::<Vec<_>>();
    let kinds = components
        .iter()
        .map(|component| component.kind)
        .collect::<BTreeSet<_>>();

    if kinds.is_empty() {
        findings.push(finding(
            RuntimeFindingSeverity::Warning,
            "runtime-surface-empty",
            "no runtime architecture signals were discovered",
            None,
            None,
        ));
        return findings;
    }
    if kinds.contains(&RuntimeComponentKind::ToolSurface)
        && !kinds.contains(&RuntimeComponentKind::ExecPolicy)
    {
        findings.push(finding(
            RuntimeFindingSeverity::Warning,
            "tool-surface-without-policy",
            "tool surface exists without a matching execution policy component",
            None,
            Some(component_id(RuntimeComponentKind::ToolSurface)),
        ));
    }
    if kinds.contains(&RuntimeComponentKind::SessionRuntime)
        && !kinds.contains(&RuntimeComponentKind::EventLedger)
    {
        findings.push(finding(
            RuntimeFindingSeverity::Warning,
            "session-without-ledger",
            "session runtime exists without a visible event ledger",
            None,
            Some(component_id(RuntimeComponentKind::SessionRuntime)),
        ));
    }
    if kinds.contains(&RuntimeComponentKind::ExecPolicy)
        && !kinds.contains(&RuntimeComponentKind::SandboxBoundary)
    {
        findings.push(finding(
            RuntimeFindingSeverity::Info,
            "policy-without-sandbox",
            "execution policy was found, but no sandbox boundary was detected",
            None,
            Some(component_id(RuntimeComponentKind::ExecPolicy)),
        ));
    }
    if flows.is_empty() && kinds.len() > 1 {
        findings.push(finding(
            RuntimeFindingSeverity::Info,
            "components-unlinked",
            "components were discovered, but no known Runtime flow could be inferred",
            None,
            None,
        ));
    }
    for krate in crates {
        if krate.name.contains("core") && krate.roles.len() > 6 {
            findings.push(finding(
                RuntimeFindingSeverity::Warning,
                "core-crate-overloaded",
                format!(
                    "crate `{}` owns {} Runtime roles; consider splitting runtime surfaces",
                    krate.name,
                    krate.roles.len()
                ),
                Some(krate.manifest.clone()),
                None,
            ));
        }
    }
    findings
}

fn file_findings(
    relative_path: &Path,
    text: &str,
    signals: &[RuntimeSignal],
) -> Vec<RuntimeFinding> {
    let mut findings = Vec::new();
    let has_tool = signals
        .iter()
        .any(|signal| signal.kind == RuntimeComponentKind::ToolSurface);
    let has_policy = signals
        .iter()
        .any(|signal| signal.kind == RuntimeComponentKind::ExecPolicy);
    if has_tool && text.contains("unsafe") && !has_policy {
        findings.push(finding(
            RuntimeFindingSeverity::Info,
            "unsafe-tool-surface",
            "tool-facing source contains unsafe code; policy evidence should stay close",
            Some(relative_path.to_path_buf()),
            Some(component_id(RuntimeComponentKind::ToolSurface)),
        ));
    }
    findings
}

fn summarize(
    files: &[RuntimeFile],
    crates: &[RuntimeCrate],
    components: &[RuntimeComponent],
    flows: &[RuntimeFlowEdge],
    findings: &[RuntimeFinding],
) -> RuntimeSummary {
    let mut summary = RuntimeSummary {
        source_file_count: files.len(),
        crate_count: crates.len(),
        component_count: components.len(),
        flow_count: flows.len(),
        signal_count: files.iter().map(|file| file.signals.len()).sum(),
        finding_count: findings.len(),
        ..RuntimeSummary::default()
    };
    for file in files {
        match file.status {
            RuntimeFileStatus::Audited => summary.audited_file_count += 1,
            RuntimeFileStatus::Skipped => summary.skipped_file_count += 1,
            RuntimeFileStatus::ReadFailed => summary.read_failed_file_count += 1,
        }
        summary.byte_count += file.bytes;
        summary.line_count += file.lines;
    }
    for finding in findings {
        match finding.severity {
            RuntimeFindingSeverity::Info => summary.info_count += 1,
            RuntimeFindingSeverity::Warning => summary.warning_count += 1,
            RuntimeFindingSeverity::Error => summary.error_count += 1,
        }
    }
    summary
}

fn readiness_from_summary(
    summary: &RuntimeSummary,
    components: &[RuntimeComponent],
    findings: &[RuntimeFinding],
) -> RuntimeReadiness {
    if summary.source_file_count == 0 || components.is_empty() {
        return RuntimeReadiness {
            status: RuntimeReadinessStatus::Empty,
            score: 0,
            reasons: vec!["no runtime architecture surface was discovered".to_owned()],
        };
    }

    let kinds = components
        .iter()
        .map(|component| component.kind)
        .collect::<BTreeSet<_>>();
    let mut score = 72i32;
    let mut reasons = Vec::new();
    for required in [
        RuntimeComponentKind::SessionRuntime,
        RuntimeComponentKind::ToolSurface,
        RuntimeComponentKind::ExecPolicy,
        RuntimeComponentKind::EventLedger,
    ] {
        if kinds.contains(&required) {
            score += 5;
        } else {
            score -= 8;
            reasons.push(format!(
                "missing expected {} component",
                component_kind_label(required)
            ));
        }
    }
    if kinds.contains(&RuntimeComponentKind::SandboxBoundary) {
        score += 4;
    }
    if kinds.contains(&RuntimeComponentKind::HookRuntime) {
        score += 3;
    }
    if kinds.contains(&RuntimeComponentKind::SkillRegistry)
        || kinds.contains(&RuntimeComponentKind::PluginRegistry)
    {
        score += 3;
    }
    score -= (summary.error_count as i32) * 25;
    score -= (summary.warning_count as i32) * 8;
    score -= (summary.info_count as i32) * 2;
    score = score.clamp(0, 100);

    for finding in findings {
        if finding.severity != RuntimeFindingSeverity::Info {
            reasons.push(format!("{}: {}", finding.code, finding.message));
        }
    }
    if reasons.is_empty() {
        reasons.push(
            "runtime architecture components have session, tool, policy, and ledger coverage"
                .to_owned(),
        );
    }

    let status = if summary.error_count > 0 {
        RuntimeReadinessStatus::Blocked
    } else if summary.warning_count > 0 || score < 80 {
        RuntimeReadinessStatus::NeedsAttention
    } else {
        RuntimeReadinessStatus::Ready
    };
    RuntimeReadiness {
        status,
        score: score as u8,
        reasons,
    }
}

fn topology_from_components(components: &[RuntimeComponent]) -> RuntimeTopology {
    let mut components_by_kind: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut ownership = Vec::new();
    for component in components {
        components_by_kind
            .entry(component_kind_label(component.kind).to_owned())
            .or_default()
            .push(component.id.clone());
        ownership.push(RuntimeOwnership {
            owner: RUNTIME_OWNER.to_owned(),
            component: component.id.clone(),
            policy: "certificate-native runtime ownership".to_owned(),
        });
    }
    RuntimeTopology {
        owner: RUNTIME_OWNER.to_owned(),
        components_by_kind,
        ownership,
    }
}

fn runtime_signals(relative_path: &Path, text: &str) -> Vec<RuntimeSignal> {
    let path_text = relative_path.display().to_string().to_ascii_lowercase();
    let content = text.to_ascii_lowercase();
    let mut signals = Vec::new();
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::RuntimeCore,
        &["/core/", "core/src/lib.rs", "runtime"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::SessionRuntime,
        &["session", "thread", "conversation"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::TurnScheduler,
        &["turn", "task", "lifecycle", "scheduler"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::TaskLane,
        &["tasks", "cloud-task", "goal", "lane"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::EventLedger,
        &["rollout", "event", "history", "recorder", "trace"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::Storage,
        &["store", "state-db", "cache", "sqlite", "db"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::ToolSurface,
        &["tool", "function_call", "tool_call", "tool_executor"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::ExecPolicy,
        &[
            "execpolicy",
            "exec_policy",
            "approval",
            "permission",
            "policy",
        ],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::SandboxBoundary,
        &["sandbox", "landlock", "bwrap", "seatbelt", "conpty"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::HookRuntime,
        &["hook", "dispatcher", "pre_tool_use", "post_tool_use"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::SkillRegistry,
        &["skill", "skills"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::PluginRegistry,
        &["plugin", "plugins"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::McpBridge,
        &["mcp", "rmcp"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::ModelProvider,
        &["model-provider", "models-manager", "responses", "client"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::AppServer,
        &["app-server", "daemon", "transport"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::ApiProtocol,
        &["protocol", "api", "openapi"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::RealtimeBridge,
        &["realtime", "websocket", "webrtc"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::Connector,
        &["connector", "connectors"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::FileWatcher,
        &["file-watcher", "watcher"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::PatchEngine,
        &["apply-patch", "patch", "diff"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::ReviewGate,
        &["review", "gate", "guard"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::ConfigSurface,
        &["config", "settings", "options"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::CloudTask,
        &["cloud-task", "remote"],
    );
    push_path_signal(
        &mut signals,
        &path_text,
        RuntimeComponentKind::Identity,
        &["identity", "install", "login", "auth", "attestation"],
    );

    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::SessionRuntime,
        &[
            "threadmanager",
            "newthread",
            "sessionmeta",
            "startthreadoptions",
        ],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::TurnScheduler,
        &["turncontext", "userturn", "turnmetadata", "compact"],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::EventLedger,
        &["rolloutrecorder", "append_thread_name", "eventpersistence"],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::ToolSurface,
        &["toolspec", "toolcall", "toolexecutor", "functiontool"],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::ExecPolicy,
        &[
            "approvalpolicy",
            "execpolicy",
            "permissionrequest",
            "sandboxpolicy",
        ],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::HookRuntime,
        &[
            "session_start",
            "pre_tool_use",
            "post_tool_use",
            "hookruntime",
        ],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::PluginRegistry,
        &["pluginid", "pluginregistry", "plugin_namespace"],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::SkillRegistry,
        &["skillmetadata", "skillinjections", "skillsmanager"],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::McpBridge,
        &["mcpmanager", "mcp_tool", "mcp_connection"],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::ModelProvider,
        &[
            "modelclient",
            "responsesrequest",
            "responseevent",
            "modelprovider",
        ],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::AppServer,
        &["app/list", "thread/read", "jsonrpc", "daemon"],
    );
    push_content_signal(
        &mut signals,
        &content,
        RuntimeComponentKind::PatchEngine,
        &["apply_patch", "patchartifact", "changed_files"],
    );
    dedupe_signals(&mut signals);
    signals
}

fn push_path_signal(
    signals: &mut Vec<RuntimeSignal>,
    haystack: &str,
    kind: RuntimeComponentKind,
    needles: &[&str],
) {
    for needle in needles {
        if haystack.contains(needle) {
            signals.push(RuntimeSignal {
                kind,
                phrase: format!("path:{needle}"),
                weight: 8,
            });
        }
    }
}

fn push_content_signal(
    signals: &mut Vec<RuntimeSignal>,
    haystack: &str,
    kind: RuntimeComponentKind,
    needles: &[&str],
) {
    for needle in needles {
        if haystack.contains(needle) {
            signals.push(RuntimeSignal {
                kind,
                phrase: format!("symbol:{needle}"),
                weight: 14,
            });
        }
    }
}

fn dedupe_signals(signals: &mut Vec<RuntimeSignal>) {
    let mut seen = BTreeSet::new();
    signals.retain(|signal| seen.insert((signal.kind, signal.phrase.clone())));
    signals.sort_by(|lhs, rhs| {
        lhs.kind
            .cmp(&rhs.kind)
            .then_with(|| rhs.weight.cmp(&lhs.weight))
            .then_with(|| lhs.phrase.cmp(&rhs.phrase))
    });
}

fn roles_from_signals(signals: &[RuntimeSignal]) -> Vec<RuntimeComponentKind> {
    signals
        .iter()
        .map(|signal| signal.kind)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn evidence_strength(weight: u8) -> RuntimeEvidenceStrength {
    match weight {
        0..=7 => RuntimeEvidenceStrength::Weak,
        8..=13 => RuntimeEvidenceStrength::Medium,
        _ => RuntimeEvidenceStrength::Strong,
    }
}

fn confidence_from_weight(weight: u32) -> u8 {
    (30 + weight.min(70)) as u8
}

fn finding(
    severity: RuntimeFindingSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    path: Option<PathBuf>,
    component: Option<String>,
) -> RuntimeFinding {
    RuntimeFinding {
        severity,
        code: code.into(),
        message: message.into(),
        path,
        component,
    }
}

fn relative_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn sha256_uri(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn component_id(kind: RuntimeComponentKind) -> String {
    format!("runtime:{}", component_kind_label(kind))
}

fn component_name(kind: RuntimeComponentKind) -> &'static str {
    match kind {
        RuntimeComponentKind::RuntimeCore => "Entanglement Runtime Core",
        RuntimeComponentKind::SessionRuntime => "Session Runtime",
        RuntimeComponentKind::TurnScheduler => "Turn Scheduler",
        RuntimeComponentKind::TaskLane => "Task Lane",
        RuntimeComponentKind::EventLedger => "Event Ledger",
        RuntimeComponentKind::Storage => "Storage Plane",
        RuntimeComponentKind::ToolSurface => "Tool Surface",
        RuntimeComponentKind::ExecPolicy => "Execution Policy",
        RuntimeComponentKind::SandboxBoundary => "Sandbox Boundary",
        RuntimeComponentKind::HookRuntime => "Hook Runtime",
        RuntimeComponentKind::SkillRegistry => "Skill Registry",
        RuntimeComponentKind::PluginRegistry => "Plugin Registry",
        RuntimeComponentKind::McpBridge => "MCP Bridge",
        RuntimeComponentKind::ModelProvider => "Model Provider",
        RuntimeComponentKind::AppServer => "App Server",
        RuntimeComponentKind::ApiProtocol => "API Protocol",
        RuntimeComponentKind::RealtimeBridge => "Realtime Bridge",
        RuntimeComponentKind::Connector => "Connector Plane",
        RuntimeComponentKind::FileWatcher => "File Watcher",
        RuntimeComponentKind::PatchEngine => "Patch Engine",
        RuntimeComponentKind::ReviewGate => "Review Gate",
        RuntimeComponentKind::ConfigSurface => "Config Surface",
        RuntimeComponentKind::CloudTask => "Cloud Task Plane",
        RuntimeComponentKind::Identity => "Identity Plane",
    }
}

pub fn component_kind_label(kind: RuntimeComponentKind) -> &'static str {
    match kind {
        RuntimeComponentKind::RuntimeCore => "runtime-core",
        RuntimeComponentKind::SessionRuntime => "session-runtime",
        RuntimeComponentKind::TurnScheduler => "turn-scheduler",
        RuntimeComponentKind::TaskLane => "task-lane",
        RuntimeComponentKind::EventLedger => "event-ledger",
        RuntimeComponentKind::Storage => "storage",
        RuntimeComponentKind::ToolSurface => "tool-surface",
        RuntimeComponentKind::ExecPolicy => "exec-policy",
        RuntimeComponentKind::SandboxBoundary => "sandbox-boundary",
        RuntimeComponentKind::HookRuntime => "hook-runtime",
        RuntimeComponentKind::SkillRegistry => "skill-registry",
        RuntimeComponentKind::PluginRegistry => "plugin-registry",
        RuntimeComponentKind::McpBridge => "mcp-bridge",
        RuntimeComponentKind::ModelProvider => "model-provider",
        RuntimeComponentKind::AppServer => "app-server",
        RuntimeComponentKind::ApiProtocol => "api-protocol",
        RuntimeComponentKind::RealtimeBridge => "realtime-bridge",
        RuntimeComponentKind::Connector => "connector",
        RuntimeComponentKind::FileWatcher => "file-watcher",
        RuntimeComponentKind::PatchEngine => "patch-engine",
        RuntimeComponentKind::ReviewGate => "review-gate",
        RuntimeComponentKind::ConfigSurface => "config-surface",
        RuntimeComponentKind::CloudTask => "cloud-task",
        RuntimeComponentKind::Identity => "identity",
    }
}

fn flow_kind_label(kind: RuntimeFlowKind) -> &'static str {
    match kind {
        RuntimeFlowKind::Schedules => "schedules",
        RuntimeFlowKind::Persists => "persists",
        RuntimeFlowKind::Guards => "guards",
        RuntimeFlowKind::Exposes => "exposes",
        RuntimeFlowKind::Loads => "loads",
        RuntimeFlowKind::Bridges => "bridges",
        RuntimeFlowKind::Invokes => "invokes",
        RuntimeFlowKind::Observes => "observes",
    }
}

fn readiness_label(status: RuntimeReadinessStatus) -> &'static str {
    match status {
        RuntimeReadinessStatus::Ready => "ready",
        RuntimeReadinessStatus::NeedsAttention => "needs-attention",
        RuntimeReadinessStatus::Blocked => "blocked",
        RuntimeReadinessStatus::Empty => "empty",
    }
}

fn finding_severity_label(severity: RuntimeFindingSeverity) -> &'static str {
    match severity {
        RuntimeFindingSeverity::Info => "info",
        RuntimeFindingSeverity::Warning => "warning",
        RuntimeFindingSeverity::Error => "error",
    }
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}
