use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use tree_sitter::{Language, Node, Parser};

pub const NATIVE_AUDIT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAuditOptions {
    pub recursive: bool,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub max_file_bytes: Option<u64>,
    pub include_tests: bool,
}

impl Default for NativeAuditOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            include_hidden: false,
            follow_symlinks: false,
            max_file_bytes: Some(4 * 1024 * 1024),
            include_tests: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeAuditReport {
    pub schema_version: u32,
    pub root: PathBuf,
    pub options: NativeAuditOptions,
    pub summary: NativeSummary,
    pub readiness: NativeReadiness,
    pub build: BuildProfile,
    pub modules: Vec<NativeModule>,
    pub surface: Vec<SurfaceEntry>,
    pub include_edges: Vec<IncludeEdge>,
    pub call_edges: Vec<CallEdge>,
    pub files: Vec<FileAudit>,
    pub findings: Vec<NativeFinding>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSummary {
    pub source_file_count: usize,
    pub audited_file_count: usize,
    pub skipped_file_count: usize,
    pub read_failed_file_count: usize,
    pub parse_warning_count: usize,
    pub rust_file_count: usize,
    pub c_file_count: usize,
    pub cpp_file_count: usize,
    pub header_file_count: usize,
    pub implementation_file_count: usize,
    pub test_file_count: usize,
    pub build_manifest_count: usize,
    pub byte_count: u64,
    pub line_count: usize,
    pub code_line_count: usize,
    pub comment_line_count: usize,
    pub blank_line_count: usize,
    pub symbol_count: usize,
    pub public_symbol_count: usize,
    pub exported_symbol_count: usize,
    pub foreign_symbol_count: usize,
    pub include_edge_count: usize,
    pub call_edge_count: usize,
    pub unsafe_count: usize,
    pub macro_count: usize,
    pub marker_count: usize,
    pub finding_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeReadiness {
    pub status: NativeReadinessStatus,
    pub score: u8,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeReadinessStatus {
    Ready,
    NeedsAttention,
    Blocked,
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildProfile {
    pub manifests: Vec<BuildManifest>,
    pub inferred_commands: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildManifest {
    pub path: PathBuf,
    pub kind: BuildManifestKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildManifestKind {
    Cargo,
    CMake,
    Make,
    Meson,
    Bazel,
    CompileCommands,
    BuildScript,
    Package,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeModule {
    pub name: String,
    pub root: PathBuf,
    pub dialects: Vec<SourceDialect>,
    pub files: usize,
    pub public_symbols: usize,
    pub exported_symbols: usize,
    pub foreign_symbols: usize,
    pub findings: usize,
    pub score: u8,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileAudit {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub status: FileStatus,
    pub dialect: SourceDialect,
    pub role: SourceRole,
    pub bytes: u64,
    pub lines: usize,
    pub sha256: Option<String>,
    pub metrics: FileMetrics,
    pub imports: Vec<NativeImport>,
    pub symbols: Vec<NativeSymbol>,
    pub calls: Vec<NativeCall>,
    pub markers: Vec<SourceMarker>,
    pub findings: Vec<NativeFinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileStatus {
    Audited,
    Skipped,
    ReadFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceDialect {
    Rust,
    C,
    Cpp,
}

impl SourceDialect {
    pub fn classify(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_string_lossy().to_ascii_lowercase();
        match extension.as_str() {
            "rs" => Some(Self::Rust),
            "c" => Some(Self::C),
            "h" => Some(Self::C),
            "hh" | "hpp" | "hxx" | "cc" | "cpp" | "cxx" => Some(Self::Cpp),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::C => "c",
            Self::Cpp => "cpp",
        }
    }

    fn language(self) -> Language {
        match self {
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
            Self::C => tree_sitter_c::LANGUAGE.into(),
            Self::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceRole {
    Header,
    Implementation,
    Test,
    BuildScript,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetrics {
    pub code_lines: usize,
    pub comment_lines: usize,
    pub blank_lines: usize,
    pub max_nesting: usize,
    pub unsafe_blocks: usize,
    pub extern_blocks: usize,
    pub public_items: usize,
    pub exported_items: usize,
    pub foreign_items: usize,
    pub macro_items: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeImport {
    pub kind: ImportKind,
    pub target: String,
    pub span: ByteSpan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportKind {
    IncludeLocal,
    IncludeSystem,
    Use,
    Module,
    ExternCrate,
    Namespace,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSymbol {
    pub name: String,
    pub kind: SymbolKind,
    pub visibility: SymbolVisibility,
    pub linkage: SymbolLinkage,
    pub abi: AbiKind,
    pub span: ByteSpan,
    pub signature: String,
    pub flags: Vec<SymbolFlag>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolKind {
    Function,
    Method,
    Type,
    Trait,
    Impl,
    Module,
    Namespace,
    Macro,
    Constant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolVisibility {
    Public,
    Private,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolLinkage {
    Internal,
    External,
    Exported,
    Imported,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbiKind {
    Rust,
    C,
    Cpp,
    System,
    Unknown,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolFlag {
    Exported,
    Foreign,
    Unsafe,
    Test,
    Generic,
    Template,
    Macro,
    MutableStatic,
    RawPointer,
    Throws,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCall {
    pub caller: Option<String>,
    pub target: String,
    pub span: ByteSpan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMarker {
    pub kind: MarkerKind,
    pub text: String,
    pub span: ByteSpan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkerKind {
    Todo,
    Fixme,
    Safety,
    Note,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceEntry {
    pub id: String,
    pub file: PathBuf,
    pub symbol: String,
    pub kind: SymbolKind,
    pub visibility: SymbolVisibility,
    pub linkage: SymbolLinkage,
    pub abi: AbiKind,
    pub signature: String,
    pub stability: u8,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncludeEdge {
    pub from: PathBuf,
    pub target: String,
    pub kind: ImportKind,
    pub resolved: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallEdge {
    pub file: PathBuf,
    pub caller: Option<String>,
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeFinding {
    pub severity: FindingSeverity,
    pub code: String,
    pub message: String,
    pub path: Option<PathBuf>,
    pub symbol: Option<String>,
    pub span: Option<ByteSpan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

pub fn audit_native_path(root: &Path, options: NativeAuditOptions) -> Result<NativeAuditReport> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))?;
    let engine = AuditEngine { root, options };
    engine.audit()
}

pub fn render_markdown(report: &NativeAuditReport) -> String {
    let mut out = String::new();
    out.push_str("# Entanglement Native Audit\n\n");
    out.push_str(&format!("- Root: `{}`\n", report.root.display()));
    out.push_str(&format!(
        "- Status: {} (score {}/100)\n",
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
        "- Languages: rust {}, c {}, cpp {}\n",
        report.summary.rust_file_count, report.summary.c_file_count, report.summary.cpp_file_count
    ));
    out.push_str(&format!(
        "- Surface: {} public, {} exported, {} foreign\n\n",
        report.summary.public_symbol_count,
        report.summary.exported_symbol_count,
        report.summary.foreign_symbol_count
    ));

    out.push_str("## Readiness\n\n");
    if report.readiness.reasons.is_empty() {
        out.push_str("- No readiness notes.\n");
    } else {
        for reason in &report.readiness.reasons {
            out.push_str(&format!("- {}\n", markdown_cell(reason)));
        }
    }

    out.push_str("\n## Build Profile\n\n");
    if report.build.manifests.is_empty() {
        out.push_str("No build manifests were discovered.\n");
    } else {
        out.push_str("| Kind | Path |\n| --- | --- |\n");
        for manifest in &report.build.manifests {
            out.push_str(&format!(
                "| {} | `{}` |\n",
                build_manifest_label(manifest.kind),
                markdown_cell(&manifest.path.display().to_string())
            ));
        }
    }
    if !report.build.inferred_commands.is_empty() {
        out.push_str("\nSuggested commands:\n");
        for command in &report.build.inferred_commands {
            out.push_str(&format!("- `{}`\n", markdown_cell(command)));
        }
    }

    out.push_str("\n## Modules\n\n");
    if report.modules.is_empty() {
        out.push_str("No native modules were discovered.\n");
    } else {
        out.push_str(
            "| Module | Files | Dialects | Public | Exported | Foreign | Findings | Score |\n",
        );
        out.push_str("| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |\n");
        for module in &report.modules {
            let dialects = module
                .dialects
                .iter()
                .map(|dialect| dialect.label())
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} | {} |\n",
                markdown_cell(&module.name),
                module.files,
                markdown_cell(&dialects),
                module.public_symbols,
                module.exported_symbols,
                module.foreign_symbols,
                module.findings,
                module.score
            ));
        }
    }

    out.push_str("\n## Public Surface\n\n");
    if report.surface.is_empty() {
        out.push_str("No public native surface was discovered.\n");
    } else {
        out.push_str("| Symbol | Kind | Linkage | ABI | Stability | File |\n");
        out.push_str("| --- | --- | --- | --- | ---: | --- |\n");
        for entry in report.surface.iter().take(80) {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | `{}` |\n",
                markdown_cell(&entry.symbol),
                symbol_kind_label(entry.kind),
                linkage_label(entry.linkage),
                abi_label(entry.abi),
                entry.stability,
                markdown_cell(&entry.file.display().to_string())
            ));
        }
        if report.surface.len() > 80 {
            out.push_str(&format!(
                "\n{} more surface entries were omitted from markdown output.\n",
                report.surface.len() - 80
            ));
        }
    }

    out.push_str("\n## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("No findings were reported.\n");
    } else {
        out.push_str("| Severity | Code | Location | Message |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for finding in report.findings.iter().take(120) {
            let location = finding
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_owned());
            out.push_str(&format!(
                "| {} | `{}` | `{}` | {} |\n",
                severity_label(finding.severity),
                markdown_cell(&finding.code),
                markdown_cell(&location),
                markdown_cell(&finding.message)
            ));
        }
        if report.findings.len() > 120 {
            out.push_str(&format!(
                "\n{} more findings were omitted from markdown output.\n",
                report.findings.len() - 120
            ));
        }
    }

    out
}

pub fn has_blocking_findings(report: &NativeAuditReport) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.severity == FindingSeverity::Error)
}

struct AuditEngine {
    root: PathBuf,
    options: NativeAuditOptions,
}

impl AuditEngine {
    fn audit(&self) -> Result<NativeAuditReport> {
        let sources = discover_sources(&self.root, &self.options)?;
        let build = discover_build_profile(&self.root, &self.options)?;
        let mut files = Vec::with_capacity(sources.len());
        for source in sources {
            let dialect = SourceDialect::classify(&source).expect("source discovery filters files");
            if !self.options.include_tests && source_role(&source, dialect) == SourceRole::Test {
                files.push(skipped_file(
                    &self.root,
                    source,
                    dialect,
                    "test file excluded by options",
                ));
                continue;
            }
            files.push(self.audit_file(source, dialect));
        }

        let include_edges = collect_include_edges(&self.root, &files);
        let call_edges = collect_call_edges(&files);
        let surface = collect_surface(&files);
        let findings = collect_findings(&files);
        let modules = collect_modules(&files);
        let summary = summarize(
            &files,
            &findings,
            &surface,
            &include_edges,
            &call_edges,
            &build,
        );
        let readiness = readiness_from_summary(&summary, &findings);

        Ok(NativeAuditReport {
            schema_version: NATIVE_AUDIT_SCHEMA_VERSION,
            root: self.root.clone(),
            options: self.options.clone(),
            summary,
            readiness,
            build,
            modules,
            surface,
            include_edges,
            call_edges,
            files,
            findings,
        })
    }

    fn audit_file(&self, path: PathBuf, dialect: SourceDialect) -> FileAudit {
        let relative_path = relative_path(&self.root, &path);
        let role = source_role(&path, dialect);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return FileAudit {
                    path,
                    relative_path: relative_path.clone(),
                    status: FileStatus::ReadFailed,
                    dialect,
                    role,
                    bytes: 0,
                    lines: 0,
                    sha256: None,
                    metrics: FileMetrics::default(),
                    imports: vec![],
                    symbols: vec![],
                    calls: vec![],
                    markers: vec![],
                    findings: vec![finding(
                        FindingSeverity::Error,
                        "read-failed",
                        format!("failed to read metadata: {error}"),
                        Some(relative_path),
                        None,
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
            return skipped_file(
                &self.root,
                path,
                dialect,
                "file exceeds configured byte limit",
            );
        }

        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return FileAudit {
                    path,
                    relative_path: relative_path.clone(),
                    status: FileStatus::ReadFailed,
                    dialect,
                    role,
                    bytes: metadata.len(),
                    lines: 0,
                    sha256: None,
                    metrics: FileMetrics::default(),
                    imports: vec![],
                    symbols: vec![],
                    calls: vec![],
                    markers: vec![],
                    findings: vec![finding(
                        FindingSeverity::Error,
                        "read-failed",
                        format!("failed to read source: {error}"),
                        Some(relative_path),
                        None,
                        None,
                    )],
                };
            }
        };

        let sha256 = Some(sha256_uri(&bytes));
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(error) => {
                return FileAudit {
                    path,
                    relative_path: relative_path.clone(),
                    status: FileStatus::Skipped,
                    dialect,
                    role,
                    bytes: bytes.len() as u64,
                    lines: 0,
                    sha256,
                    metrics: FileMetrics::default(),
                    imports: vec![],
                    symbols: vec![],
                    calls: vec![],
                    markers: vec![],
                    findings: vec![finding(
                        FindingSeverity::Error,
                        "not-utf8",
                        format!("source is not valid UTF-8: {error}"),
                        Some(relative_path),
                        None,
                        None,
                    )],
                };
            }
        };

        let mut metrics = line_metrics(text);
        let mut imports = line_imports(text, dialect);
        let mut symbols = line_symbols(text, dialect, role);
        let mut calls = Vec::new();
        let markers = source_markers(text);
        let mut findings = file_findings(text, dialect, role, &relative_path, &markers);

        match tree_analysis(text, dialect) {
            Ok(tree) => {
                metrics.max_nesting = metrics.max_nesting.max(tree.metrics.max_nesting);
                metrics.unsafe_blocks += tree.metrics.unsafe_blocks;
                metrics.extern_blocks += tree.metrics.extern_blocks;
                imports.extend(tree.imports);
                symbols.extend(tree.symbols);
                calls.extend(tree.calls);
                if tree.parse_error {
                    findings.push(finding(
                        FindingSeverity::Warning,
                        "syntax-warning",
                        "syntax parser reported at least one recovery node",
                        Some(relative_path.clone()),
                        None,
                        None,
                    ));
                }
            }
            Err(message) => findings.push(finding(
                FindingSeverity::Warning,
                "syntax-unavailable",
                message,
                Some(relative_path.clone()),
                None,
                None,
            )),
        }

        dedupe_imports(&mut imports);
        dedupe_symbols(&mut symbols);
        dedupe_calls(&mut calls);
        enrich_symbol_metrics(&mut metrics, &symbols);
        enrich_findings_from_symbols(&mut findings, &relative_path, &symbols);

        FileAudit {
            path,
            relative_path,
            status: FileStatus::Audited,
            dialect,
            role,
            bytes: bytes.len() as u64,
            lines: text.lines().count(),
            sha256,
            metrics,
            imports,
            symbols,
            calls,
            markers,
            findings,
        }
    }
}

#[derive(Default)]
struct TreeAnalysis {
    parse_error: bool,
    metrics: FileMetrics,
    imports: Vec<NativeImport>,
    symbols: Vec<NativeSymbol>,
    calls: Vec<NativeCall>,
}

struct TreeWalk<'a> {
    source: &'a str,
    dialect: SourceDialect,
    current_symbols: Vec<String>,
    metrics: FileMetrics,
    imports: Vec<NativeImport>,
    symbols: Vec<NativeSymbol>,
    calls: Vec<NativeCall>,
    nesting: usize,
}

fn tree_analysis(
    source: &str,
    dialect: SourceDialect,
) -> std::result::Result<TreeAnalysis, String> {
    let mut parser = Parser::new();
    let language = dialect.language();
    parser.set_language(&language).map_err(|error| {
        format!(
            "failed to initialize {} syntax parser: {error}",
            dialect.label()
        )
    })?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| format!("{} syntax parser produced no tree", dialect.label()))?;
    let parse_error = tree.root_node().has_error();
    let mut walk = TreeWalk {
        source,
        dialect,
        current_symbols: vec![],
        metrics: FileMetrics::default(),
        imports: vec![],
        symbols: vec![],
        calls: vec![],
        nesting: 0,
    };
    walk_tree(tree.root_node(), &mut walk);
    Ok(TreeAnalysis {
        parse_error,
        metrics: walk.metrics,
        imports: walk.imports,
        symbols: walk.symbols,
        calls: walk.calls,
    })
}

fn walk_tree(node: Node<'_>, walk: &mut TreeWalk<'_>) {
    if node.is_named() {
        if let Some(import) = tree_import(walk.dialect, node, walk.source) {
            walk.imports.push(import);
        }
        if let Some(call) = tree_call(walk.dialect, node, walk.source, &walk.current_symbols) {
            walk.calls.push(call);
        }
        if is_unsafe_node(node) {
            walk.metrics.unsafe_blocks += 1;
        }
        if is_extern_node(node) {
            walk.metrics.extern_blocks += 1;
        }
    }

    let symbol = tree_symbol(walk.dialect, node, walk.source);
    let symbol_name = symbol.as_ref().and_then(|symbol| {
        if matches!(symbol.kind, SymbolKind::Function | SymbolKind::Method) {
            Some(symbol.name.clone())
        } else {
            None
        }
    });
    if let Some(symbol) = symbol {
        walk.symbols.push(symbol);
    }
    if let Some(name) = &symbol_name {
        walk.current_symbols.push(name.clone());
    }

    let increment = nesting_increment(node.kind());
    walk.nesting += increment;
    walk.metrics.max_nesting = walk.metrics.max_nesting.max(walk.nesting);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_tree(child, walk);
    }
    walk.nesting = walk.nesting.saturating_sub(increment);

    if symbol_name.is_some() {
        walk.current_symbols.pop();
    }
}

fn tree_symbol(dialect: SourceDialect, node: Node<'_>, source: &str) -> Option<NativeSymbol> {
    let kind = match (dialect, node.kind()) {
        (SourceDialect::Rust, "function_item") => SymbolKind::Function,
        (SourceDialect::Rust, "struct_item" | "enum_item" | "union_item" | "type_item") => {
            SymbolKind::Type
        }
        (SourceDialect::Rust, "trait_item") => SymbolKind::Trait,
        (SourceDialect::Rust, "impl_item") => SymbolKind::Impl,
        (SourceDialect::Rust, "mod_item") => SymbolKind::Module,
        (SourceDialect::Rust, "macro_definition") => SymbolKind::Macro,
        (SourceDialect::Rust, "const_item" | "static_item") => SymbolKind::Constant,
        (SourceDialect::C | SourceDialect::Cpp, "function_definition") => {
            if c_like_method_name(node, source).is_some() {
                SymbolKind::Method
            } else {
                SymbolKind::Function
            }
        }
        (SourceDialect::C | SourceDialect::Cpp, "struct_specifier" | "enum_specifier") => {
            SymbolKind::Type
        }
        (SourceDialect::C, "union_specifier") => SymbolKind::Type,
        (SourceDialect::Cpp, "class_specifier" | "union_specifier" | "type_definition") => {
            SymbolKind::Type
        }
        (SourceDialect::Cpp, "namespace_definition") => SymbolKind::Namespace,
        (SourceDialect::C | SourceDialect::Cpp, "preproc_function_def" | "preproc_def") => {
            SymbolKind::Macro
        }
        _ => return None,
    };

    let signature = signature_for_node(node, source);
    let name = symbol_name(dialect, kind, node, source, &signature)?;
    Some(symbol_from_parts(
        dialect,
        kind,
        name,
        signature,
        ByteSpan::from_node(node),
    ))
}

fn tree_import(dialect: SourceDialect, node: Node<'_>, source: &str) -> Option<NativeImport> {
    let text = node_text(node, source)?;
    match (dialect, node.kind()) {
        (SourceDialect::Rust, "use_declaration") => Some(NativeImport {
            kind: ImportKind::Use,
            target: trim_rust_use(text),
            span: ByteSpan::from_node(node),
        }),
        (SourceDialect::Rust, "extern_crate_declaration") => Some(NativeImport {
            kind: ImportKind::ExternCrate,
            target: trim_extern_crate(text),
            span: ByteSpan::from_node(node),
        }),
        (SourceDialect::Rust, "mod_item") if text.trim_end().ends_with(';') => Some(NativeImport {
            kind: ImportKind::Module,
            target: node
                .child_by_field_name("name")
                .and_then(|node| normalized_node_text(node, source))
                .unwrap_or_else(|| trim_rust_mod(text)),
            span: ByteSpan::from_node(node),
        }),
        (SourceDialect::C | SourceDialect::Cpp, "preproc_include") => {
            include_from_line(text, node.start_byte())
        }
        (SourceDialect::Cpp, "using_declaration" | "namespace_alias_definition") => {
            Some(NativeImport {
                kind: ImportKind::Namespace,
                target: compact_whitespace(text.trim_end_matches(';')),
                span: ByteSpan::from_node(node),
            })
        }
        _ => None,
    }
}

fn tree_call(
    dialect: SourceDialect,
    node: Node<'_>,
    source: &str,
    current_symbols: &[String],
) -> Option<NativeCall> {
    let target = match (dialect, node.kind()) {
        (_, "call_expression") => node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
            .and_then(|node| normalized_node_text(node, source)),
        (SourceDialect::Rust, "macro_invocation") => rust_macro_call_name(node, source),
        _ => None,
    }?;
    let target = target.trim();
    if target.is_empty() || target.len() > 180 {
        return None;
    }
    Some(NativeCall {
        caller: current_symbols.last().cloned(),
        target: target.to_owned(),
        span: ByteSpan::from_node(node),
    })
}

fn discover_sources(root: &Path, options: &NativeAuditOptions) -> Result<Vec<PathBuf>> {
    let mut sources = Vec::new();
    if root.is_file() {
        if SourceDialect::classify(root).is_some() {
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
    options: &NativeAuditOptions,
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
        if should_skip_path(&path, file_type.is_dir(), options) {
            continue;
        }
        if file_type.is_symlink() && !options.follow_symlinks {
            continue;
        }
        if file_type.is_dir() {
            if options.recursive {
                discover_sources_inner(&path, options, sources)?;
            }
        } else if file_type.is_file() && SourceDialect::classify(&path).is_some() {
            sources.push(path);
        }
    }
    Ok(())
}

fn discover_build_profile(root: &Path, options: &NativeAuditOptions) -> Result<BuildProfile> {
    let mut manifests = Vec::new();
    if root.is_file() {
        return Ok(BuildProfile {
            manifests,
            inferred_commands: vec![],
            notes: vec!["audit root is a file; build profile discovery is limited".to_owned()],
        });
    }
    discover_build_profile_inner(root, options, &mut manifests)?;
    manifests.sort_by(|left, right| {
        left.kind.cmp(&right.kind).then(
            left.path
                .display()
                .to_string()
                .cmp(&right.path.display().to_string()),
        )
    });
    manifests.dedup_by(|left, right| left.kind == right.kind && left.path == right.path);
    let inferred_commands = infer_build_commands(&manifests);
    let mut notes = Vec::new();
    if manifests.is_empty() {
        notes.push("no recognized build manifest was found".to_owned());
    }
    if manifests
        .iter()
        .any(|manifest| manifest.kind == BuildManifestKind::CompileCommands)
    {
        notes.push("compile command database can be used to cross-check native flags".to_owned());
    }
    Ok(BuildProfile {
        manifests,
        inferred_commands,
        notes,
    })
}

fn discover_build_profile_inner(
    dir: &Path,
    options: &NativeAuditOptions,
    manifests: &mut Vec<BuildManifest>,
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
        if should_skip_path(&path, file_type.is_dir(), options) {
            continue;
        }
        if file_type.is_symlink() && !options.follow_symlinks {
            continue;
        }
        if file_type.is_dir() {
            if options.recursive {
                discover_build_profile_inner(&path, options, manifests)?;
            }
        } else if file_type.is_file() {
            if let Some(kind) = classify_build_manifest(&path) {
                manifests.push(BuildManifest {
                    path: path.to_path_buf(),
                    kind,
                });
            }
        }
    }
    Ok(())
}

fn should_skip_path(path: &Path, is_dir: bool, options: &NativeAuditOptions) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    if !options.include_hidden && name.starts_with('.') {
        return true;
    }
    if is_dir {
        matches!(
            name.as_ref(),
            "target"
                | "node_modules"
                | ".git"
                | ".hg"
                | ".svn"
                | ".build"
                | "build"
                | "dist"
                | "DerivedData"
        )
    } else {
        false
    }
}

fn classify_build_manifest(path: &Path) -> Option<BuildManifestKind> {
    let name = path.file_name()?.to_string_lossy();
    match name.as_ref() {
        "Cargo.toml" => Some(BuildManifestKind::Cargo),
        "CMakeLists.txt" => Some(BuildManifestKind::CMake),
        "Makefile" | "makefile" => Some(BuildManifestKind::Make),
        "meson.build" => Some(BuildManifestKind::Meson),
        "BUILD" | "BUILD.bazel" | "WORKSPACE" | "WORKSPACE.bazel" => Some(BuildManifestKind::Bazel),
        "compile_commands.json" => Some(BuildManifestKind::CompileCommands),
        "build.rs" => Some(BuildManifestKind::BuildScript),
        "Package.swift" => Some(BuildManifestKind::Package),
        _ => None,
    }
}

fn infer_build_commands(manifests: &[BuildManifest]) -> Vec<String> {
    let kinds = manifests
        .iter()
        .map(|manifest| manifest.kind)
        .collect::<BTreeSet<_>>();
    let mut commands = Vec::new();
    if kinds.contains(&BuildManifestKind::Cargo) {
        commands.push("cargo check --workspace".to_owned());
        commands.push("cargo test --workspace".to_owned());
    }
    if kinds.contains(&BuildManifestKind::CMake) {
        commands.push("cmake -S . -B build".to_owned());
        commands.push("cmake --build build".to_owned());
    }
    if kinds.contains(&BuildManifestKind::Make) {
        commands.push("make".to_owned());
    }
    if kinds.contains(&BuildManifestKind::Meson) {
        commands.push("meson setup build".to_owned());
        commands.push("meson compile -C build".to_owned());
    }
    if kinds.contains(&BuildManifestKind::Bazel) {
        commands.push("bazel test //...".to_owned());
    }
    commands
}

fn source_role(path: &Path, dialect: SourceDialect) -> SourceRole {
    let extension = path
        .extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let lower_path = path.display().to_string().to_ascii_lowercase();
    if lower_path.ends_with("build.rs") {
        return SourceRole::BuildScript;
    }
    if lower_path.contains("/test")
        || lower_path.contains("\\test")
        || lower_path.contains("/tests/")
        || lower_path.contains("\\tests\\")
        || lower_path.ends_with("_test.rs")
        || lower_path.ends_with("_test.cpp")
        || lower_path.ends_with("_test.c")
        || lower_path.ends_with(".test.cpp")
    {
        return SourceRole::Test;
    }
    match (dialect, extension.as_str()) {
        (SourceDialect::C | SourceDialect::Cpp, "h" | "hh" | "hpp" | "hxx") => SourceRole::Header,
        _ => SourceRole::Implementation,
    }
}

fn skipped_file(root: &Path, path: PathBuf, dialect: SourceDialect, reason: &str) -> FileAudit {
    let relative_path = relative_path(root, &path);
    FileAudit {
        role: source_role(&path, dialect),
        path,
        relative_path: relative_path.clone(),
        status: FileStatus::Skipped,
        dialect,
        bytes: 0,
        lines: 0,
        sha256: None,
        metrics: FileMetrics::default(),
        imports: vec![],
        symbols: vec![],
        calls: vec![],
        markers: vec![],
        findings: vec![finding(
            FindingSeverity::Info,
            "file-skipped",
            reason.to_owned(),
            Some(relative_path),
            None,
            None,
        )],
    }
}

fn line_metrics(source: &str) -> FileMetrics {
    let mut metrics = FileMetrics::default();
    let mut in_block = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            metrics.blank_lines += 1;
            continue;
        }
        if in_block {
            metrics.comment_lines += 1;
            if trimmed.contains("*/") {
                in_block = false;
            }
            continue;
        }
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            metrics.comment_lines += 1;
            continue;
        }
        if trimmed.starts_with("/*") {
            metrics.comment_lines += 1;
            if !trimmed.contains("*/") {
                in_block = true;
            }
            continue;
        }
        metrics.code_lines += 1;
    }
    metrics
}

fn line_imports(source: &str, dialect: SourceDialect) -> Vec<NativeImport> {
    let mut imports = Vec::new();
    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        let logical = line.trim_end_matches(['\n', '\r']);
        let trimmed = logical.trim();
        match dialect {
            SourceDialect::Rust => {
                if trimmed.starts_with("use ") {
                    imports.push(NativeImport {
                        kind: ImportKind::Use,
                        target: trimmed
                            .trim_start_matches("use")
                            .trim()
                            .trim_end_matches(';')
                            .trim()
                            .to_owned(),
                        span: ByteSpan {
                            start: offset,
                            end: offset + logical.len(),
                        },
                    });
                } else if trimmed.starts_with("mod ") && trimmed.ends_with(';') {
                    imports.push(NativeImport {
                        kind: ImportKind::Module,
                        target: trimmed
                            .trim_start_matches("mod")
                            .trim()
                            .trim_end_matches(';')
                            .trim()
                            .to_owned(),
                        span: ByteSpan {
                            start: offset,
                            end: offset + logical.len(),
                        },
                    });
                } else if trimmed.starts_with("extern crate ") {
                    imports.push(NativeImport {
                        kind: ImportKind::ExternCrate,
                        target: trimmed
                            .trim_start_matches("extern crate")
                            .trim()
                            .trim_end_matches(';')
                            .trim()
                            .to_owned(),
                        span: ByteSpan {
                            start: offset,
                            end: offset + logical.len(),
                        },
                    });
                }
            }
            SourceDialect::C | SourceDialect::Cpp => {
                if trimmed.starts_with("#include") {
                    if let Some(import) = include_from_line(trimmed, offset) {
                        imports.push(import);
                    }
                } else if dialect == SourceDialect::Cpp
                    && (trimmed.starts_with("using ") || trimmed.starts_with("namespace "))
                {
                    imports.push(NativeImport {
                        kind: ImportKind::Namespace,
                        target: compact_whitespace(trimmed.trim_end_matches(';')),
                        span: ByteSpan {
                            start: offset,
                            end: offset + logical.len(),
                        },
                    });
                }
            }
        }
        offset += line.len();
    }
    imports
}

fn line_symbols(source: &str, dialect: SourceDialect, role: SourceRole) -> Vec<NativeSymbol> {
    let mut symbols = Vec::new();
    let mut offset = 0usize;
    let mut pending_attributes = Vec::new();
    for line in source.split_inclusive('\n') {
        let logical = line.trim_end_matches(['\n', '\r']);
        let trimmed = logical.trim();
        if trimmed.starts_with("#[") {
            pending_attributes.push(trimmed.to_owned());
            offset += line.len();
            continue;
        }
        match dialect {
            SourceDialect::Rust => {
                if let Some(symbol) = rust_line_symbol(
                    trimmed,
                    &pending_attributes,
                    ByteSpan {
                        start: offset,
                        end: offset + logical.len(),
                    },
                ) {
                    symbols.push(symbol);
                }
            }
            SourceDialect::C | SourceDialect::Cpp => {
                if let Some(symbol) = c_like_line_symbol(
                    trimmed,
                    dialect,
                    role,
                    ByteSpan {
                        start: offset,
                        end: offset + logical.len(),
                    },
                ) {
                    symbols.push(symbol);
                }
            }
        }
        if !trimmed.is_empty() && !trimmed.starts_with("#[") {
            pending_attributes.clear();
        }
        offset += line.len();
    }
    symbols
}

fn rust_line_symbol(line: &str, attributes: &[String], span: ByteSpan) -> Option<NativeSymbol> {
    let compact = compact_whitespace(line);
    let kind = if compact.contains(" fn ")
        || compact.starts_with("fn ")
        || compact.starts_with("pub fn ")
        || compact.contains(" extern ") && compact.contains(" fn ")
    {
        SymbolKind::Function
    } else if compact.starts_with("pub struct ")
        || compact.starts_with("struct ")
        || compact.starts_with("pub enum ")
        || compact.starts_with("enum ")
        || compact.starts_with("pub type ")
        || compact.starts_with("type ")
    {
        SymbolKind::Type
    } else if compact.starts_with("pub trait ") || compact.starts_with("trait ") {
        SymbolKind::Trait
    } else if compact.starts_with("pub const ")
        || compact.starts_with("const ")
        || compact.starts_with("pub static ")
        || compact.starts_with("static ")
    {
        SymbolKind::Constant
    } else {
        return None;
    };
    let name = match kind {
        SymbolKind::Function => name_after_keyword(&compact, "fn"),
        SymbolKind::Type => name_after_any_keyword(&compact, &["struct", "enum", "type"]),
        SymbolKind::Trait => name_after_keyword(&compact, "trait"),
        SymbolKind::Constant => name_after_any_keyword(&compact, &["const", "static"]),
        _ => None,
    }?;
    let mut signature = compact;
    if !attributes.is_empty() {
        signature = format!("{} {signature}", attributes.join(" "));
    }
    Some(symbol_from_parts(
        SourceDialect::Rust,
        kind,
        name,
        signature,
        span,
    ))
}

fn c_like_line_symbol(
    line: &str,
    dialect: SourceDialect,
    role: SourceRole,
    span: ByteSpan,
) -> Option<NativeSymbol> {
    if line.is_empty()
        || line.starts_with("//")
        || line.starts_with('#') && !line.starts_with("#define")
    {
        return None;
    }
    if line.starts_with("#define") {
        let name = line
            .trim_start_matches("#define")
            .trim()
            .split(|ch: char| ch == '(' || ch.is_whitespace())
            .next()
            .filter(|name| !name.is_empty())?
            .to_owned();
        return Some(symbol_from_parts(
            dialect,
            SymbolKind::Macro,
            name,
            compact_whitespace(line),
            span,
        ));
    }
    let compact = compact_whitespace(line);
    if role == SourceRole::Header
        && looks_like_function_prototype(&compact)
        && !looks_like_control_flow(&compact)
    {
        let name = c_like_function_name(&compact)?;
        return Some(symbol_from_parts(
            dialect,
            SymbolKind::Function,
            name,
            compact,
            span,
        ));
    }
    None
}

fn symbol_from_parts(
    dialect: SourceDialect,
    kind: SymbolKind,
    name: String,
    signature: String,
    span: ByteSpan,
) -> NativeSymbol {
    let visibility = visibility_for_signature(dialect, kind, &signature);
    let abi = abi_for_signature(dialect, &signature);
    let linkage = linkage_for_signature(dialect, kind, visibility, abi, &signature);
    let mut flags = Vec::new();
    if linkage == SymbolLinkage::Exported {
        flags.push(SymbolFlag::Exported);
    }
    if matches!(linkage, SymbolLinkage::Imported) || abi != AbiKind::None && abi != AbiKind::Rust {
        flags.push(SymbolFlag::Foreign);
    }
    if signature.contains("unsafe ") || signature.contains(" unsafe") {
        flags.push(SymbolFlag::Unsafe);
    }
    if signature.contains("<") && signature.contains(">") {
        match dialect {
            SourceDialect::Rust => flags.push(SymbolFlag::Generic),
            SourceDialect::Cpp => flags.push(SymbolFlag::Template),
            SourceDialect::C => {}
        }
    }
    if kind == SymbolKind::Macro {
        flags.push(SymbolFlag::Macro);
    }
    if signature.contains("static mut") || signature.contains(" mutable ") {
        flags.push(SymbolFlag::MutableStatic);
    }
    if signature.contains('*') && matches!(kind, SymbolKind::Function | SymbolKind::Method) {
        flags.push(SymbolFlag::RawPointer);
    }
    if signature.contains(" throw(") || signature.contains(" noexcept(false)") {
        flags.push(SymbolFlag::Throws);
    }
    flags.sort();
    flags.dedup();
    NativeSymbol {
        name,
        kind,
        visibility,
        linkage,
        abi,
        span,
        signature: truncate(signature, 320),
        flags,
    }
}

fn visibility_for_signature(
    dialect: SourceDialect,
    kind: SymbolKind,
    signature: &str,
) -> SymbolVisibility {
    if kind == SymbolKind::Macro {
        return SymbolVisibility::Public;
    }
    match dialect {
        SourceDialect::Rust => {
            if signature.contains("pub ") || signature.contains("pub(") {
                SymbolVisibility::Public
            } else {
                SymbolVisibility::Private
            }
        }
        SourceDialect::C => {
            if signature.starts_with("static ") {
                SymbolVisibility::Private
            } else {
                SymbolVisibility::Public
            }
        }
        SourceDialect::Cpp => {
            if signature.starts_with("static ") || signature.contains(" private:") {
                SymbolVisibility::Private
            } else {
                SymbolVisibility::Public
            }
        }
    }
}

fn abi_for_signature(dialect: SourceDialect, signature: &str) -> AbiKind {
    match dialect {
        SourceDialect::Rust => {
            if signature.contains("extern \"C\"") {
                AbiKind::C
            } else if signature.contains("extern \"system\"") {
                AbiKind::System
            } else if signature.contains("extern ") {
                AbiKind::Unknown
            } else {
                AbiKind::Rust
            }
        }
        SourceDialect::C => AbiKind::C,
        SourceDialect::Cpp => {
            if signature.contains("extern \"C\"") {
                AbiKind::C
            } else {
                AbiKind::Cpp
            }
        }
    }
}

fn linkage_for_signature(
    dialect: SourceDialect,
    kind: SymbolKind,
    visibility: SymbolVisibility,
    abi: AbiKind,
    signature: &str,
) -> SymbolLinkage {
    if kind == SymbolKind::Macro {
        return SymbolLinkage::External;
    }
    if signature.contains("no_mangle")
        || signature.contains("export_name")
        || signature.contains("__declspec(dllexport)")
        || signature.contains("__attribute__((visibility(\"default\")))")
    {
        return SymbolLinkage::Exported;
    }
    if signature.contains("extern \"C\" {")
        || signature.ends_with(");") && signature.starts_with("extern ")
    {
        return SymbolLinkage::Imported;
    }
    match dialect {
        SourceDialect::Rust => {
            if abi != AbiKind::Rust && visibility == SymbolVisibility::Public {
                SymbolLinkage::External
            } else if visibility == SymbolVisibility::Public {
                SymbolLinkage::External
            } else {
                SymbolLinkage::Internal
            }
        }
        SourceDialect::C | SourceDialect::Cpp => {
            if visibility == SymbolVisibility::Private {
                SymbolLinkage::Internal
            } else {
                SymbolLinkage::External
            }
        }
    }
}

fn file_findings(
    source: &str,
    dialect: SourceDialect,
    role: SourceRole,
    path: &Path,
    markers: &[SourceMarker],
) -> Vec<NativeFinding> {
    let mut findings = Vec::new();
    if matches!(role, SourceRole::Header) && !has_header_guard(source) {
        findings.push(finding(
            FindingSeverity::Warning,
            "header-guard-missing",
            "header does not declare #pragma once or a conventional include guard",
            Some(path.to_path_buf()),
            None,
            None,
        ));
    }
    if matches!(dialect, SourceDialect::C | SourceDialect::Cpp) {
        for token in ["strcpy(", "strcat(", "sprintf(", "gets("] {
            if source.contains(token) {
                findings.push(finding(
                    FindingSeverity::Warning,
                    "unchecked-buffer-call",
                    format!("source uses {token} in native code"),
                    Some(path.to_path_buf()),
                    None,
                    None,
                ));
            }
        }
        for token in ["reinterpret_cast<", "const_cast<"] {
            if source.contains(token) {
                findings.push(finding(
                    FindingSeverity::Warning,
                    "narrow-cast",
                    format!("source uses {token}"),
                    Some(path.to_path_buf()),
                    None,
                    None,
                ));
            }
        }
        if source.contains("malloc(") || source.contains("free(") || source.contains(" new ") {
            findings.push(finding(
                FindingSeverity::Info,
                "manual-lifetime",
                "source contains manual lifetime management calls",
                Some(path.to_path_buf()),
                None,
                None,
            ));
        }
    }
    if dialect == SourceDialect::Rust && source.contains(".unwrap()") {
        findings.push(finding(
            FindingSeverity::Info,
            "panic-shortcut",
            "source contains unwrap calls",
            Some(path.to_path_buf()),
            None,
            None,
        ));
    }
    for marker in markers {
        findings.push(finding(
            match marker.kind {
                MarkerKind::Fixme => FindingSeverity::Warning,
                _ => FindingSeverity::Info,
            },
            marker_kind_code(marker.kind),
            marker.text.clone(),
            Some(path.to_path_buf()),
            None,
            Some(marker.span),
        ));
    }
    findings
}

fn enrich_findings_from_symbols(
    findings: &mut Vec<NativeFinding>,
    path: &Path,
    symbols: &[NativeSymbol],
) {
    for symbol in symbols {
        if symbol.flags.contains(&SymbolFlag::Unsafe) {
            findings.push(finding(
                FindingSeverity::Warning,
                "unsafe-surface",
                format!("{} is marked unsafe", symbol.name),
                Some(path.to_path_buf()),
                Some(symbol.name.clone()),
                Some(symbol.span),
            ));
        }
        if symbol.flags.contains(&SymbolFlag::RawPointer)
            && symbol.visibility == SymbolVisibility::Public
        {
            findings.push(finding(
                FindingSeverity::Warning,
                "raw-pointer-surface",
                format!("{} exposes raw pointer parameters or returns", symbol.name),
                Some(path.to_path_buf()),
                Some(symbol.name.clone()),
                Some(symbol.span),
            ));
        }
        if symbol.flags.contains(&SymbolFlag::MutableStatic) {
            findings.push(finding(
                FindingSeverity::Warning,
                "mutable-static",
                format!("{} uses mutable static storage", symbol.name),
                Some(path.to_path_buf()),
                Some(symbol.name.clone()),
                Some(symbol.span),
            ));
        }
        if symbol.linkage == SymbolLinkage::Exported && symbol.abi == AbiKind::Rust {
            findings.push(finding(
                FindingSeverity::Warning,
                "rust-abi-export",
                format!(
                    "{} is exported without an explicit foreign ABI",
                    symbol.name
                ),
                Some(path.to_path_buf()),
                Some(symbol.name.clone()),
                Some(symbol.span),
            ));
        }
    }
}

fn collect_surface(files: &[FileAudit]) -> Vec<SurfaceEntry> {
    let mut entries = Vec::new();
    for file in files {
        if file.status != FileStatus::Audited {
            continue;
        }
        for symbol in &file.symbols {
            if symbol.visibility != SymbolVisibility::Public
                && symbol.linkage != SymbolLinkage::Exported
                && symbol.linkage != SymbolLinkage::Imported
                && !symbol.flags.contains(&SymbolFlag::Foreign)
            {
                continue;
            }
            let (stability, reasons) = surface_stability(file, symbol);
            entries.push(SurfaceEntry {
                id: surface_id(&file.relative_path, symbol),
                file: file.relative_path.clone(),
                symbol: symbol.name.clone(),
                kind: symbol.kind,
                visibility: symbol.visibility,
                linkage: symbol.linkage,
                abi: symbol.abi,
                signature: symbol.signature.clone(),
                stability,
                reasons,
            });
        }
    }
    entries.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.symbol.cmp(&right.symbol))
            .then(left.kind.cmp(&right.kind))
    });
    entries.dedup_by(|left, right| {
        left.file == right.file && left.symbol == right.symbol && left.kind == right.kind
    });
    entries
}

fn surface_stability(file: &FileAudit, symbol: &NativeSymbol) -> (u8, Vec<String>) {
    let mut score: i32 = 100;
    let mut reasons = Vec::new();
    if file.role == SourceRole::Header {
        reasons.push("declared in a header".to_owned());
    }
    if symbol.linkage == SymbolLinkage::Exported {
        reasons.push("explicit export marker".to_owned());
    }
    if symbol.flags.contains(&SymbolFlag::RawPointer) {
        score -= 15;
        reasons.push("raw pointer surface".to_owned());
    }
    if symbol.flags.contains(&SymbolFlag::Unsafe) {
        score -= 15;
        reasons.push("unsafe marker".to_owned());
    }
    if symbol.flags.contains(&SymbolFlag::MutableStatic) {
        score -= 20;
        reasons.push("mutable static storage".to_owned());
    }
    if symbol.flags.contains(&SymbolFlag::Template) || symbol.flags.contains(&SymbolFlag::Generic) {
        score -= 5;
        reasons.push("generic shape".to_owned());
    }
    if symbol.abi == AbiKind::Unknown {
        score -= 10;
        reasons.push("unknown ABI".to_owned());
    }
    (score.clamp(0, 100) as u8, reasons)
}

fn collect_include_edges(root: &Path, files: &[FileAudit]) -> Vec<IncludeEdge> {
    let mut edges = Vec::new();
    for file in files {
        if file.status != FileStatus::Audited {
            continue;
        }
        for import in &file.imports {
            if matches!(
                import.kind,
                ImportKind::IncludeLocal
                    | ImportKind::IncludeSystem
                    | ImportKind::Use
                    | ImportKind::Module
                    | ImportKind::ExternCrate
                    | ImportKind::Namespace
            ) {
                edges.push(IncludeEdge {
                    from: file.relative_path.clone(),
                    target: import.target.clone(),
                    kind: import.kind,
                    resolved: resolve_import(root, file, import),
                });
            }
        }
    }
    edges.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then(left.target.cmp(&right.target))
            .then(left.kind.cmp(&right.kind))
    });
    edges.dedup_by(|left, right| {
        left.from == right.from && left.target == right.target && left.kind == right.kind
    });
    edges
}

fn collect_call_edges(files: &[FileAudit]) -> Vec<CallEdge> {
    let mut edges = Vec::new();
    for file in files {
        if file.status != FileStatus::Audited {
            continue;
        }
        for call in &file.calls {
            edges.push(CallEdge {
                file: file.relative_path.clone(),
                caller: call.caller.clone(),
                target: call.target.clone(),
            });
        }
    }
    edges.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.caller.cmp(&right.caller))
            .then(left.target.cmp(&right.target))
    });
    edges.dedup();
    edges
}

fn collect_findings(files: &[FileAudit]) -> Vec<NativeFinding> {
    let mut findings = files
        .iter()
        .flat_map(|file| file.findings.iter().cloned())
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        severity_rank(left.severity)
            .cmp(&severity_rank(right.severity))
            .then(left.path.cmp(&right.path))
            .then(left.code.cmp(&right.code))
            .then(left.message.cmp(&right.message))
    });
    findings
}

fn collect_modules(files: &[FileAudit]) -> Vec<NativeModule> {
    #[derive(Default)]
    struct Acc {
        root: PathBuf,
        dialects: BTreeSet<SourceDialect>,
        files: usize,
        public_symbols: usize,
        exported_symbols: usize,
        foreign_symbols: usize,
        findings: usize,
    }
    let mut modules: BTreeMap<String, Acc> = BTreeMap::new();
    for file in files {
        if file.status != FileStatus::Audited {
            continue;
        }
        let name = module_name(&file.relative_path);
        let acc = modules.entry(name).or_insert_with(Acc::default);
        if acc.root.as_os_str().is_empty() {
            acc.root = module_root(&file.relative_path);
        }
        acc.dialects.insert(file.dialect);
        acc.files += 1;
        acc.public_symbols += file
            .symbols
            .iter()
            .filter(|symbol| symbol.visibility == SymbolVisibility::Public)
            .count();
        acc.exported_symbols += file
            .symbols
            .iter()
            .filter(|symbol| symbol.linkage == SymbolLinkage::Exported)
            .count();
        acc.foreign_symbols += file
            .symbols
            .iter()
            .filter(|symbol| symbol.flags.contains(&SymbolFlag::Foreign))
            .count();
        acc.findings += file
            .findings
            .iter()
            .filter(|finding| finding.severity != FindingSeverity::Info)
            .count();
    }
    modules
        .into_iter()
        .map(|(name, acc)| {
            let score = (100i32 - (acc.findings as i32 * 8).min(80)).clamp(0, 100) as u8;
            NativeModule {
                name,
                root: acc.root,
                dialects: acc.dialects.into_iter().collect(),
                files: acc.files,
                public_symbols: acc.public_symbols,
                exported_symbols: acc.exported_symbols,
                foreign_symbols: acc.foreign_symbols,
                findings: acc.findings,
                score,
            }
        })
        .collect()
}

fn summarize(
    files: &[FileAudit],
    findings: &[NativeFinding],
    surface: &[SurfaceEntry],
    include_edges: &[IncludeEdge],
    call_edges: &[CallEdge],
    build: &BuildProfile,
) -> NativeSummary {
    let mut summary = NativeSummary {
        source_file_count: files.len(),
        build_manifest_count: build.manifests.len(),
        include_edge_count: include_edges.len(),
        call_edge_count: call_edges.len(),
        public_symbol_count: surface
            .iter()
            .filter(|entry| entry.visibility == SymbolVisibility::Public)
            .count(),
        exported_symbol_count: surface
            .iter()
            .filter(|entry| entry.linkage == SymbolLinkage::Exported)
            .count(),
        foreign_symbol_count: surface
            .iter()
            .filter(|entry| entry.abi != AbiKind::Rust && entry.abi != AbiKind::None)
            .count(),
        finding_count: findings.len(),
        error_count: findings
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Error)
            .count(),
        warning_count: findings
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Warning)
            .count(),
        info_count: findings
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Info)
            .count(),
        ..NativeSummary::default()
    };

    for file in files {
        match file.status {
            FileStatus::Audited => summary.audited_file_count += 1,
            FileStatus::Skipped => summary.skipped_file_count += 1,
            FileStatus::ReadFailed => summary.read_failed_file_count += 1,
        }
        match file.dialect {
            SourceDialect::Rust => summary.rust_file_count += 1,
            SourceDialect::C => summary.c_file_count += 1,
            SourceDialect::Cpp => summary.cpp_file_count += 1,
        }
        match file.role {
            SourceRole::Header => summary.header_file_count += 1,
            SourceRole::Implementation | SourceRole::BuildScript => {
                summary.implementation_file_count += 1
            }
            SourceRole::Test => summary.test_file_count += 1,
        }
        summary.byte_count += file.bytes;
        summary.line_count += file.lines;
        summary.code_line_count += file.metrics.code_lines;
        summary.comment_line_count += file.metrics.comment_lines;
        summary.blank_line_count += file.metrics.blank_lines;
        summary.symbol_count += file.symbols.len();
        summary.unsafe_count += file.metrics.unsafe_blocks;
        summary.macro_count += file.metrics.macro_items;
        summary.marker_count += file.markers.len();
        if file
            .findings
            .iter()
            .any(|finding| finding.code == "syntax-warning")
        {
            summary.parse_warning_count += 1;
        }
    }
    summary
}

fn readiness_from_summary(summary: &NativeSummary, findings: &[NativeFinding]) -> NativeReadiness {
    if summary.source_file_count == 0 {
        return NativeReadiness {
            status: NativeReadinessStatus::Empty,
            score: 0,
            reasons: vec!["no Rust, C, or C++ files were discovered".to_owned()],
        };
    }
    let mut score = 100i32;
    score -= (summary.error_count as i32 * 25).min(80);
    score -= (summary.warning_count as i32 * 7).min(70);
    score -= (summary.parse_warning_count as i32 * 10).min(40);
    score -= (summary.read_failed_file_count as i32 * 20).min(60);
    if summary.build_manifest_count == 0 {
        score -= 8;
    }
    let score = score.clamp(0, 100) as u8;
    let status = if summary.error_count > 0 || summary.read_failed_file_count > 0 {
        NativeReadinessStatus::Blocked
    } else if summary.warning_count > 0 || summary.parse_warning_count > 0 {
        NativeReadinessStatus::NeedsAttention
    } else {
        NativeReadinessStatus::Ready
    };
    let mut reasons = Vec::new();
    if summary.build_manifest_count == 0 {
        reasons.push("no recognized build manifest was found".to_owned());
    }
    if summary.exported_symbol_count > 0 {
        reasons.push(format!(
            "{} exported native symbol(s) are part of the surface",
            summary.exported_symbol_count
        ));
    }
    if summary.foreign_symbol_count > 0 {
        reasons.push(format!(
            "{} foreign boundary symbol(s) were discovered",
            summary.foreign_symbol_count
        ));
    }
    if summary.warning_count > 0 {
        reasons.push(format!(
            "{} warning finding(s) require review",
            summary.warning_count
        ));
    }
    if summary.error_count > 0 {
        reasons.push(format!(
            "{} error finding(s) block readiness",
            summary.error_count
        ));
    }
    if reasons.is_empty() {
        reasons.push("native surface is mapped without blocking findings".to_owned());
    }
    if findings
        .iter()
        .any(|finding| finding.code == "raw-pointer-surface")
    {
        reasons.push("raw pointer surfaces should have documented ownership rules".to_owned());
    }
    NativeReadiness {
        status,
        score,
        reasons,
    }
}

fn resolve_import(root: &Path, file: &FileAudit, import: &NativeImport) -> Option<PathBuf> {
    match import.kind {
        ImportKind::IncludeLocal => {
            let base = root.join(&file.relative_path).parent()?.to_path_buf();
            let candidates = [
                base.join(&import.target),
                root.join(&import.target),
                root.join("include").join(&import.target),
                root.join("src").join(&import.target),
            ];
            candidates
                .into_iter()
                .find(|candidate| candidate.exists())
                .map(|path| relative_path(root, &path))
        }
        ImportKind::Module if file.dialect == SourceDialect::Rust => {
            let base = root.join(&file.relative_path).parent()?.to_path_buf();
            let candidates = [
                base.join(format!("{}.rs", import.target)),
                base.join(&import.target).join("mod.rs"),
                root.join("src").join(format!("{}.rs", import.target)),
                root.join("src").join(&import.target).join("mod.rs"),
            ];
            candidates
                .into_iter()
                .find(|candidate| candidate.exists())
                .map(|path| relative_path(root, &path))
        }
        _ => None,
    }
}

fn source_markers(source: &str) -> Vec<SourceMarker> {
    let mut markers = Vec::new();
    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        let line_end = offset + line.len();
        let logical = line.trim_end_matches(['\n', '\r']);
        let trimmed = logical.trim_start();
        let is_comment = trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with("///")
            || trimmed.starts_with("//!");
        if is_comment {
            let lower = trimmed.to_ascii_lowercase();
            let kind = if lower.contains("fixme") {
                Some(MarkerKind::Fixme)
            } else if lower.contains("todo") {
                Some(MarkerKind::Todo)
            } else if lower.contains("safety") {
                Some(MarkerKind::Safety)
            } else if lower.contains("note") {
                Some(MarkerKind::Note)
            } else {
                None
            };
            if let Some(kind) = kind {
                markers.push(SourceMarker {
                    kind,
                    text: truncate(compact_whitespace(trimmed), 180),
                    span: ByteSpan {
                        start: offset,
                        end: line_end,
                    },
                });
            }
        }
        offset = line_end;
    }
    markers
}

fn has_header_guard(source: &str) -> bool {
    if source.contains("#pragma once") {
        return true;
    }
    let mut has_ifndef = false;
    let mut has_define = false;
    for line in source.lines().take(60) {
        let trimmed = line.trim();
        if trimmed.starts_with("#ifndef ") {
            has_ifndef = true;
        }
        if trimmed.starts_with("#define ") {
            has_define = true;
        }
        if has_ifndef && has_define {
            return true;
        }
    }
    false
}

fn include_from_line(line: &str, start: usize) -> Option<NativeImport> {
    let text = line.trim().trim_start_matches("#include").trim();
    if let Some(target) = text
        .strip_prefix('"')
        .and_then(|tail| tail.split('"').next())
        .filter(|target| !target.is_empty())
    {
        return Some(NativeImport {
            kind: ImportKind::IncludeLocal,
            target: target.trim().to_owned(),
            span: ByteSpan {
                start,
                end: start + line.len(),
            },
        });
    }
    if let Some(target) = text
        .strip_prefix('<')
        .and_then(|tail| tail.split('>').next())
        .filter(|target| !target.is_empty())
    {
        return Some(NativeImport {
            kind: ImportKind::IncludeSystem,
            target: target.trim().to_owned(),
            span: ByteSpan {
                start,
                end: start + line.len(),
            },
        });
    }
    None
}

fn looks_like_function_prototype(line: &str) -> bool {
    line.ends_with(';')
        && line.contains('(')
        && line.contains(')')
        && !line.contains("typedef")
        && !line.contains(" using ")
        && !line.starts_with("using ")
        && !line.contains(" operator ")
}

fn looks_like_control_flow(line: &str) -> bool {
    let trimmed = line.trim_start();
    ["if ", "for ", "while ", "switch ", "return "]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
}

fn c_like_function_name(signature: &str) -> Option<String> {
    let before_paren = signature.split('(').next()?.trim();
    let before_paren = before_paren.trim_end_matches('*').trim();
    before_paren
        .split(|ch: char| ch.is_whitespace() || ch == '*' || ch == '&')
        .filter(|part| !part.is_empty())
        .last()
        .map(|name| name.trim_matches(':').to_owned())
        .filter(|name| !name.is_empty())
}

fn c_like_method_name(node: Node<'_>, source: &str) -> Option<String> {
    node.child_by_field_name("declarator")
        .and_then(|node| normalized_node_text(node, source))
        .filter(|declarator| declarator.contains("::"))
}

fn symbol_name(
    dialect: SourceDialect,
    kind: SymbolKind,
    node: Node<'_>,
    source: &str,
    signature: &str,
) -> Option<String> {
    if kind == SymbolKind::Impl {
        return node
            .child_by_field_name("type")
            .and_then(|node| normalized_node_text(node, source))
            .or_else(|| deep_identifier(node, source));
    }
    if matches!(kind, SymbolKind::Function | SymbolKind::Method)
        && matches!(dialect, SourceDialect::C | SourceDialect::Cpp)
    {
        return node
            .child_by_field_name("declarator")
            .and_then(|node| deep_identifier(node, source))
            .or_else(|| c_like_function_name(signature))
            .or_else(|| deep_identifier(node, source));
    }
    if matches!(
        kind,
        SymbolKind::Macro | SymbolKind::Constant | SymbolKind::Module
    ) {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|node| normalized_node_text(node, source))
        {
            return Some(name);
        }
    }
    node.child_by_field_name("name")
        .and_then(|node| normalized_node_text(node, source))
        .or_else(|| deep_identifier(node, source))
}

fn signature_for_node(node: Node<'_>, source: &str) -> String {
    let start = node.start_byte();
    let mut end = node.end_byte();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if matches!(
            child.kind(),
            "block" | "compound_statement" | "field_declaration_list"
        ) {
            end = child.start_byte();
            break;
        }
    }
    if start >= end || end > source.len() {
        return String::new();
    }
    truncate(
        compact_whitespace(&source[start..end])
            .trim_end_matches('{')
            .trim_end_matches(';')
            .trim(),
        320,
    )
}

fn rust_macro_call_name(node: Node<'_>, source: &str) -> Option<String> {
    node.child_by_field_name("macro")
        .and_then(|node| normalized_node_text(node, source))
        .or_else(|| deep_identifier(node, source))
        .map(|name| {
            if name.ends_with('!') {
                name
            } else {
                format!("{name}!")
            }
        })
}

fn deep_identifier(node: Node<'_>, source: &str) -> Option<String> {
    let mut found = None;
    collect_identifiers(node, source, &mut found);
    found
}

fn collect_identifiers(node: Node<'_>, source: &str, found: &mut Option<String>) {
    if identifier_like(node.kind()) {
        if let Some(text) = normalized_node_text(node, source) {
            *found = Some(text);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_identifiers(child, source, found);
    }
}

fn identifier_like(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "type_identifier"
            | "field_identifier"
            | "scoped_identifier"
            | "qualified_identifier"
            | "namespace_identifier"
            | "module_identifier"
            | "destructor_name"
    )
}

fn normalized_node_text(node: Node<'_>, source: &str) -> Option<String> {
    node_text(node, source).map(|text| compact_whitespace(text.trim()))
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn is_unsafe_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "unsafe_block" | "unsafe_function_item")
}

fn is_extern_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "extern_block" | "extern_crate_declaration" | "linkage_specification"
    )
}

fn nesting_increment(kind: &str) -> usize {
    matches!(
        kind,
        "block"
            | "compound_statement"
            | "if_expression"
            | "if_statement"
            | "for_expression"
            | "for_statement"
            | "while_expression"
            | "while_statement"
            | "loop_expression"
            | "match_expression"
            | "switch_statement"
            | "try_statement"
            | "catch_clause"
            | "lambda_expression"
    )
    .into()
}

fn enrich_symbol_metrics(metrics: &mut FileMetrics, symbols: &[NativeSymbol]) {
    metrics.public_items = symbols
        .iter()
        .filter(|symbol| symbol.visibility == SymbolVisibility::Public)
        .count();
    metrics.exported_items = symbols
        .iter()
        .filter(|symbol| symbol.linkage == SymbolLinkage::Exported)
        .count();
    metrics.foreign_items = symbols
        .iter()
        .filter(|symbol| symbol.flags.contains(&SymbolFlag::Foreign))
        .count();
    metrics.macro_items = symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Macro)
        .count();
}

fn module_name(path: &Path) -> String {
    let mut components = path.components();
    components
        .next()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_owned())
}

fn module_root(path: &Path) -> PathBuf {
    path.components()
        .next()
        .map(|component| PathBuf::from(component.as_os_str()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn relative_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn finding(
    severity: FindingSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    path: Option<PathBuf>,
    symbol: Option<String>,
    span: Option<ByteSpan>,
) -> NativeFinding {
    NativeFinding {
        severity,
        code: code.into(),
        message: message.into(),
        path,
        symbol,
        span,
    }
}

fn surface_id(path: &Path, symbol: &NativeSymbol) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.display().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(symbol.name.as_bytes());
    hasher.update(b"\0");
    hasher.update(symbol.signature.as_bytes());
    let digest = hasher.finalize();
    format!(
        "surf:{:x}",
        &digest[..8]
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
    )
}

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn name_after_keyword(line: &str, keyword: &str) -> Option<String> {
    let marker = format!("{keyword} ");
    let tail = line.split(&marker).nth(1)?;
    tail.split(|ch: char| {
        ch == '(' || ch == '<' || ch == ':' || ch == ';' || ch == '=' || ch.is_whitespace()
    })
    .find(|part| !part.is_empty())
    .map(str::to_owned)
}

fn name_after_any_keyword(line: &str, keywords: &[&str]) -> Option<String> {
    keywords
        .iter()
        .find_map(|keyword| name_after_keyword(line, keyword))
}

fn trim_rust_use(text: &str) -> String {
    text.trim()
        .trim_start_matches("use")
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_owned()
}

fn trim_extern_crate(text: &str) -> String {
    text.trim()
        .trim_start_matches("extern crate")
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_owned()
}

fn trim_rust_mod(text: &str) -> String {
    text.trim()
        .trim_start_matches("mod")
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_owned()
}

fn compact_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate(input: impl AsRef<str>, max_len: usize) -> String {
    let input = input.as_ref();
    if input.len() <= max_len {
        input.to_owned()
    } else {
        let mut end = max_len.saturating_sub(3);
        while !input.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        format!("{}...", &input[..end])
    }
}

fn dedupe_imports(imports: &mut Vec<NativeImport>) {
    imports.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then(left.target.cmp(&right.target))
            .then(left.span.start.cmp(&right.span.start))
    });
    imports.dedup_by(|left, right| {
        left.kind == right.kind
            && left.target == right.target
            && left.span.start == right.span.start
    });
}

fn dedupe_symbols(symbols: &mut Vec<NativeSymbol>) {
    symbols.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.kind.cmp(&right.kind))
            .then(left.span.start.cmp(&right.span.start))
    });
    symbols.dedup_by(|left, right| {
        left.kind == right.kind && left.name == right.name && left.signature == right.signature
    });
}

fn dedupe_calls(calls: &mut Vec<NativeCall>) {
    calls.sort_by(|left, right| {
        left.caller
            .cmp(&right.caller)
            .then(left.target.cmp(&right.target))
            .then(left.span.start.cmp(&right.span.start))
    });
    calls.dedup_by(|left, right| {
        left.caller == right.caller
            && left.target == right.target
            && left.span.start == right.span.start
    });
}

fn severity_rank(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Error => 0,
        FindingSeverity::Warning => 1,
        FindingSeverity::Info => 2,
    }
}

fn readiness_label(status: NativeReadinessStatus) -> &'static str {
    match status {
        NativeReadinessStatus::Ready => "ready",
        NativeReadinessStatus::NeedsAttention => "needs attention",
        NativeReadinessStatus::Blocked => "blocked",
        NativeReadinessStatus::Empty => "empty",
    }
}

fn severity_label(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "info",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

fn build_manifest_label(kind: BuildManifestKind) -> &'static str {
    match kind {
        BuildManifestKind::Cargo => "cargo",
        BuildManifestKind::CMake => "cmake",
        BuildManifestKind::Make => "make",
        BuildManifestKind::Meson => "meson",
        BuildManifestKind::Bazel => "bazel",
        BuildManifestKind::CompileCommands => "compile-commands",
        BuildManifestKind::BuildScript => "build-script",
        BuildManifestKind::Package => "package",
    }
}

fn symbol_kind_label(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Function => "function",
        SymbolKind::Method => "method",
        SymbolKind::Type => "type",
        SymbolKind::Trait => "trait",
        SymbolKind::Impl => "impl",
        SymbolKind::Module => "module",
        SymbolKind::Namespace => "namespace",
        SymbolKind::Macro => "macro",
        SymbolKind::Constant => "constant",
    }
}

fn linkage_label(linkage: SymbolLinkage) -> &'static str {
    match linkage {
        SymbolLinkage::Internal => "internal",
        SymbolLinkage::External => "external",
        SymbolLinkage::Exported => "exported",
        SymbolLinkage::Imported => "imported",
        SymbolLinkage::Unknown => "unknown",
    }
}

fn abi_label(abi: AbiKind) -> &'static str {
    match abi {
        AbiKind::Rust => "rust",
        AbiKind::C => "c",
        AbiKind::Cpp => "cpp",
        AbiKind::System => "system",
        AbiKind::Unknown => "unknown",
        AbiKind::None => "none",
    }
}

fn marker_kind_code(kind: MarkerKind) -> &'static str {
    match kind {
        MarkerKind::Todo => "todo-marker",
        MarkerKind::Fixme => "fixme-marker",
        MarkerKind::Safety => "safety-note",
        MarkerKind::Note => "source-note",
    }
}

fn markdown_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "<br>")
}

impl ByteSpan {
    fn from_node(node: Node<'_>) -> Self {
        Self {
            start: node.start_byte(),
            end: node.end_byte(),
        }
    }
}
