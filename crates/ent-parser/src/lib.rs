use ent_proof::{parse_proposition, parse_script, ProofParseError, ProofScript, Proposition};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{kind}: {message} at bytes {start}..{end}", start = span.start, end = span.end)]
pub struct ParseDiagnostic {
    pub kind: &'static str,
    pub message: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WorldAst {
    pub name: String,
    pub span: SourceSpan,
    pub modules: Vec<ModuleDecl>,
    pub imports: Vec<ImportDecl>,
    pub functions: Vec<FunctionDecl>,
    pub dimensions: Vec<DimensionDecl>,
    pub states: Vec<StateDecl>,
    pub relations: Vec<RelationDecl>,
    pub laws: Vec<LawDecl>,
    pub invariants: Vec<InvariantDecl>,
    pub effects: Vec<EffectDecl>,
    pub externals: Vec<ExternalDecl>,
    pub workspaces: Vec<WorkspaceDecl>,
    pub parsers: Vec<ParserDecl>,
    pub documents: Vec<DocumentDecl>,
    pub selections: Vec<SelectionDecl>,
    pub transforms: Vec<TransformDecl>,
    pub validators: Vec<ValidatorDecl>,
    pub graphics: Vec<GraphicsDecl>,
    pub render_targets: Vec<RenderTargetDecl>,
    pub render_pipelines: Vec<RenderPipelineDecl>,
    pub benchmarks: Vec<BenchmarkDecl>,
    pub tensors: Vec<TensorDecl>,
    pub accelerators: Vec<AcceleratorDecl>,
    pub datasets: Vec<DatasetDecl>,
    pub models: Vec<ModelDecl>,
    pub trainings: Vec<TrainingDecl>,
    pub machines: Vec<MachineDecl>,
    pub memories: Vec<MemoryDecl>,
    pub instructions: Vec<InstructionDecl>,
    pub abis: Vec<AbiDecl>,
    pub proof_artifacts: Vec<ProofArtifactDecl>,
    pub evolves: Vec<EvolveDecl>,
    pub ad: Vec<AdDecl>,
    pub measures: Vec<MeasureDecl>,
    pub theorems: Vec<TheoremDecl>,
    pub proofs: Vec<ProofDecl>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleDecl {
    pub name: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportDecl {
    pub path: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionDecl {
    pub name: String,
    pub signature: String,
    pub body: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionDecl {
    pub kind: DimensionKind,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DimensionKind {
    Agent,
    Space,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDecl {
    pub name: String,
    pub ty: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationDecl {
    pub name: String,
    pub binder: String,
    pub domain: String,
    pub preserves: Vec<String>,
    pub changes: Vec<String>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LawDecl {
    pub text: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InvariantDecl {
    pub name: String,
    pub argument: String,
    pub before: f64,
    pub after: f64,
    pub tolerance: f64,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvolveDecl {
    pub name: String,
    pub params: Vec<(String, String)>,
    pub backend: String,
    pub differentiable: bool,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdDecl {
    pub primal: String,
    pub tangent: String,
    pub adjoint: String,
    pub law: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MeasureDecl {
    pub name: String,
    pub weights: Vec<(String, f64)>,
    pub tolerance: f64,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectDecl {
    pub name: String,
    pub resource: String,
    pub access: EffectAccess,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectAccess {
    Read,
    Write,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalDecl {
    pub name: String,
    pub interface: String,
    pub resource: String,
    pub access: EffectAccess,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceDecl {
    pub name: String,
    pub boundary: String,
    pub access: EffectAccess,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParserDecl {
    pub name: String,
    pub language: String,
    pub adapter: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentDecl {
    pub name: String,
    pub adapter: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionDecl {
    pub name: String,
    pub predicate: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransformTargetDecl {
    Selection(String),
    File(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextReplacementDecl {
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransformDecl {
    pub name: String,
    pub operation: String,
    pub target: TransformTargetDecl,
    pub destination: Option<String>,
    pub predicate: Option<String>,
    pub replacement: Option<TextReplacementDecl>,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorDecl {
    pub name: String,
    pub argv: Vec<String>,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphicsDecl {
    pub name: String,
    pub entry: String,
    pub imports: Vec<String>,
    pub body: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderTargetDecl {
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderPipelineDecl {
    pub name: String,
    pub graphics: String,
    pub target: String,
    pub entry: String,
    pub mode: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkDecl {
    pub name: String,
    pub graphics: String,
    pub entry: String,
    pub warmup: u32,
    pub iterations: u32,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorDecl {
    pub name: String,
    pub shape: Vec<String>,
    pub dtype: String,
    pub gradient: String,
    pub layout: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceleratorDecl {
    pub name: String,
    pub kind: String,
    pub memory: String,
    pub precision: String,
    pub supports: Vec<String>,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetDecl {
    pub name: String,
    pub tensors: Vec<String>,
    pub source: String,
    pub source_digest: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelDecl {
    pub name: String,
    pub entry: String,
    pub inputs: Vec<String>,
    pub parameters: Vec<String>,
    pub outputs: Vec<String>,
    pub ops: Vec<String>,
    pub loss: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TrainingDecl {
    pub name: String,
    pub model: String,
    pub dataset: String,
    pub accelerator: String,
    pub optimizer: String,
    pub learning_rate: f64,
    pub steps: u32,
    pub batch: u32,
    pub objective: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineDecl {
    pub id: String,
    pub isa: String,
    pub profile: String,
    pub word_bits: u32,
    pub endianness: String,
    pub memory_model: String,
    pub semantic_source: String,
    pub source_digest: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegionDecl {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryDecl {
    pub name: String,
    pub machine: String,
    pub address_bits: u32,
    pub ordering: String,
    pub regions: Vec<MemoryRegionDecl>,
    pub frame_conditions: Vec<String>,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstructionDecl {
    pub name: String,
    pub machine: String,
    pub mnemonic: String,
    pub encoding: String,
    pub semantics: String,
    pub effects: Vec<String>,
    pub proof_artifact: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbiDecl {
    pub name: String,
    pub machine: String,
    pub target_triple: String,
    pub object_format: String,
    pub calling_convention: String,
    pub external_policy: String,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofArtifactDecl {
    pub name: String,
    pub prover: String,
    pub module: String,
    pub digest: String,
    pub obligations: Vec<String>,
    pub evidence: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TheoremDecl {
    pub name: String,
    pub proposition: Proposition,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofDecl {
    pub theorem: String,
    pub script: ProofScript,
    pub span: SourceSpan,
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("expected world declaration")]
    MissingWorld,
    #[error("malformed declaration: {0}")]
    Malformed(String),
    #[error("unsupported top-level item: {0}")]
    Unsupported(String),
    #[error("malformed proof block: {0}")]
    MalformedProof(String),
}

pub fn parse_world(source: &str) -> Result<WorldAst, ParseError> {
    parse_world_diagnostic(source).map_err(|diagnostic| diagnostic.error())
}

pub fn parse_world_diagnostic(source: &str) -> Result<WorldAst, ParseDiagnostic> {
    let stripped = strip_comments_preserve_width(source);
    let header_start = stripped
        .find("world ")
        .ok_or_else(|| ParseDiagnostic::new("missing-world", ParseError::MissingWorld, 0, 0))?;
    let brace = stripped[header_start..]
        .find('{')
        .map(|idx| header_start + idx)
        .ok_or_else(|| {
            ParseDiagnostic::new(
                "malformed-declaration",
                ParseError::Malformed("world header lacks body".to_owned()),
                header_start,
                stripped.len(),
            )
        })?;
    let close = matching_brace(&stripped, brace).ok_or_else(|| {
        ParseDiagnostic::new(
            "malformed-declaration",
            ParseError::Malformed("world body is not closed".to_owned()),
            brace,
            stripped.len(),
        )
    })?;
    let header = stripped[header_start + "world ".len()..brace].trim();
    let (name, dimensions) = parse_header(header).map_err(|error| {
        ParseDiagnostic::new("malformed-declaration", error, header_start, brace)
    })?;
    let body = &stripped[brace + 1..close];
    let surface = parse_surface_decls(&stripped[..header_start])?;

    let mut ast = WorldAst {
        name,
        span: SourceSpan {
            start: header_start,
            end: close + 1,
        },
        modules: surface.modules,
        imports: surface.imports,
        functions: surface.functions,
        dimensions,
        states: vec![],
        relations: vec![],
        laws: vec![],
        invariants: vec![],
        effects: vec![],
        externals: vec![],
        workspaces: vec![],
        parsers: vec![],
        documents: vec![],
        selections: vec![],
        transforms: vec![],
        validators: vec![],
        graphics: vec![],
        render_targets: vec![],
        render_pipelines: vec![],
        benchmarks: vec![],
        tensors: vec![],
        accelerators: vec![],
        datasets: vec![],
        models: vec![],
        trainings: vec![],
        machines: vec![],
        memories: vec![],
        instructions: vec![],
        abis: vec![],
        proof_artifacts: vec![],
        evolves: vec![],
        ad: vec![],
        measures: vec![],
        theorems: vec![],
        proofs: vec![],
    };

    let mut body_offset = brace + 1;
    let mut lines = body.split_inclusive('\n').peekable();
    while let Some(raw) = lines.next() {
        let line = raw.trim();
        if line.is_empty() {
            body_offset += raw.len();
            continue;
        }
        let local_start = raw.find(line).expect("trimmed line exists in raw line");
        let span = SourceSpan {
            start: body_offset + local_start,
            end: body_offset + local_start + line.len(),
        };
        if let Some(rest) = line.strip_prefix("state ") {
            ast.states
                .push(parse_state(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("relation ") {
            ast.relations
                .push(parse_relation(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("law ") {
            ast.laws.push(LawDecl {
                text: rest.trim().to_owned(),
                span,
            });
        } else if let Some(rest) = line.strip_prefix("invariant ") {
            ast.invariants
                .push(parse_invariant(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("effect ") {
            ast.effects
                .push(parse_effect(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("external ") {
            ast.externals
                .push(parse_external(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("workspace ") {
            ast.workspaces
                .push(parse_workspace(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("parser ") {
            ast.parsers
                .push(parse_parser(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("document ") {
            ast.documents
                .push(parse_document(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("select ") {
            ast.selections
                .push(parse_selection(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("transform ") {
            ast.transforms
                .push(parse_transform(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("validator ") {
            ast.validators
                .push(parse_validator(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("graphics ") {
            let (graphics, consumed) = parse_graphics_block(rest, span, &mut lines)
                .map_err(|error| diagnostic(error, span, line))?;
            body_offset += consumed;
            ast.graphics.push(graphics);
        } else if let Some(rest) = line.strip_prefix("render-target ") {
            ast.render_targets.push(
                parse_render_target(rest, span).map_err(|error| diagnostic(error, span, line))?,
            );
        } else if let Some(rest) = line.strip_prefix("render-pipeline ") {
            ast.render_pipelines.push(
                parse_render_pipeline(rest, span).map_err(|error| diagnostic(error, span, line))?,
            );
        } else if let Some(rest) = line.strip_prefix("benchmark ") {
            ast.benchmarks
                .push(parse_benchmark(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("tensor ") {
            ast.tensors
                .push(parse_tensor(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("accelerator ") {
            ast.accelerators.push(
                parse_accelerator(rest, span).map_err(|error| diagnostic(error, span, line))?,
            );
        } else if let Some(rest) = line.strip_prefix("dataset ") {
            ast.datasets
                .push(parse_dataset(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("model ") {
            ast.models
                .push(parse_model(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("training ") {
            ast.trainings
                .push(parse_training(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("machine ") {
            ast.machines
                .push(parse_machine(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("memory ") {
            ast.memories
                .push(parse_memory(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("instruction ") {
            ast.instructions.push(
                parse_instruction(rest, span).map_err(|error| diagnostic(error, span, line))?,
            );
        } else if let Some(rest) = line.strip_prefix("abi ") {
            ast.abis
                .push(parse_abi(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("proof-artifact ") {
            ast.proof_artifacts.push(
                parse_proof_artifact(rest, span).map_err(|error| diagnostic(error, span, line))?,
            );
        } else if let Some(rest) = line.strip_prefix("evolve ") {
            ast.evolves
                .push(parse_evolve(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("ad ") {
            ast.ad
                .push(parse_ad(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("measure ") {
            ast.measures
                .push(parse_measure(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("theorem ") {
            ast.theorems
                .push(parse_theorem(rest, span).map_err(|error| diagnostic(error, span, line))?);
        } else if let Some(rest) = line.strip_prefix("proof ") {
            let (proof, consumed) = parse_proof_block(rest, span, &mut lines)
                .map_err(|error| diagnostic(error, span, line))?;
            body_offset += consumed;
            ast.proofs.push(proof);
        } else {
            return Err(ParseDiagnostic::new(
                "unsupported-item",
                ParseError::Unsupported(line.to_owned()),
                span.start,
                span.end,
            ));
        }
        body_offset += raw.len();
    }

    Ok(ast)
}

impl ParseDiagnostic {
    fn new(kind: &'static str, error: ParseError, start: usize, end: usize) -> Self {
        Self {
            kind,
            message: error.to_string(),
            span: SourceSpan { start, end },
        }
    }

    fn error(&self) -> ParseError {
        match self.kind {
            "missing-world" => ParseError::MissingWorld,
            "unsupported-item" => self
                .message
                .strip_prefix("unsupported top-level item: ")
                .map(|item| ParseError::Unsupported(item.to_owned()))
                .unwrap_or_else(|| ParseError::Unsupported(self.message.clone())),
            "malformed-proof" => self
                .message
                .strip_prefix("malformed proof block: ")
                .map(|item| ParseError::MalformedProof(item.to_owned()))
                .unwrap_or_else(|| ParseError::MalformedProof(self.message.clone())),
            _ => self
                .message
                .strip_prefix("malformed declaration: ")
                .map(|item| ParseError::Malformed(item.to_owned()))
                .unwrap_or_else(|| ParseError::Malformed(self.message.clone())),
        }
    }
}

fn diagnostic(error: ParseError, span: SourceSpan, line: &str) -> ParseDiagnostic {
    let kind = if matches!(error, ParseError::MalformedProof(_)) {
        "malformed-proof"
    } else {
        "malformed-declaration"
    };
    let mut diagnostic = ParseDiagnostic::new(kind, error, span.start, span.end);
    diagnostic.message = format!("{} at `{line}`", diagnostic.message);
    diagnostic
}

#[derive(Default)]
struct SurfaceDecls {
    modules: Vec<ModuleDecl>,
    imports: Vec<ImportDecl>,
    functions: Vec<FunctionDecl>,
}

fn parse_surface_decls(source: &str) -> Result<SurfaceDecls, ParseDiagnostic> {
    let mut decls = SurfaceDecls::default();
    let mut offset = 0usize;
    let mut lines = source.split_inclusive('\n').peekable();
    while let Some(raw) = lines.next() {
        let line = raw.trim();
        if line.is_empty() {
            offset += raw.len();
            continue;
        }
        let local_start = raw.find(line).expect("trimmed line exists");
        let span = SourceSpan {
            start: offset + local_start,
            end: offset + local_start + line.len(),
        };
        if let Some(rest) = line.strip_prefix("module ") {
            let name = rest.trim();
            if name.is_empty() || name.split_whitespace().count() != 1 {
                return Err(diagnostic(
                    ParseError::Malformed(line.to_owned()),
                    span,
                    line,
                ));
            }
            decls.modules.push(ModuleDecl {
                name: name.to_owned(),
                span,
            });
        } else if let Some(rest) = line.strip_prefix("import ") {
            let path = rest.trim();
            if path.is_empty() || path.split_whitespace().count() != 1 {
                return Err(diagnostic(
                    ParseError::Malformed(line.to_owned()),
                    span,
                    line,
                ));
            }
            decls.imports.push(ImportDecl {
                path: path.to_owned(),
                span,
            });
        } else if let Some(rest) = line.strip_prefix("fn ") {
            let (function, consumed) = parse_surface_function(rest, span, &mut lines)
                .map_err(|error| diagnostic(error, span, line))?;
            offset += consumed;
            decls.functions.push(function);
        } else {
            return Err(ParseDiagnostic::new(
                "unsupported-item",
                ParseError::Unsupported(line.to_owned()),
                span.start,
                span.end,
            ));
        }
        offset += raw.len();
    }
    Ok(decls)
}

fn matching_brace(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in source.char_indices().skip_while(|(idx, _)| *idx < open) {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn strip_comments_preserve_width(source: &str) -> String {
    source
        .lines()
        .map(|line| {
            line.split_once("//").map_or_else(
                || line.to_owned(),
                |(head, tail)| format!("{head}{}", " ".repeat(tail.len() + 2)),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_header(header: &str) -> Result<(String, Vec<DimensionDecl>), ParseError> {
    let open = header
        .find('(')
        .ok_or_else(|| ParseError::Malformed(header.to_owned()))?;
    let close = header
        .rfind(')')
        .ok_or_else(|| ParseError::Malformed(header.to_owned()))?;
    let name = header[..open].trim();
    if name.is_empty() {
        return Err(ParseError::Malformed(header.to_owned()));
    }
    let dimensions = header[open + 1..close]
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            let mut words = part.split_whitespace();
            let kind = words
                .next()
                .ok_or_else(|| ParseError::Malformed(part.to_owned()))?;
            let name = words
                .next()
                .ok_or_else(|| ParseError::Malformed(part.to_owned()))?;
            let kind = match kind {
                "agent" => DimensionKind::Agent,
                "space" => DimensionKind::Space,
                other => DimensionKind::Other(other.to_owned()),
            };
            Ok(DimensionDecl {
                kind,
                name: name.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, ParseError>>()?;
    Ok((name.to_owned(), dimensions))
}

fn parse_state(rest: &str, span: SourceSpan) -> Result<StateDecl, ParseError> {
    let (name, ty) = rest
        .split_once(':')
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    Ok(StateDecl {
        name: name.trim().to_owned(),
        ty: ty.trim().to_owned(),
        span,
    })
}

fn parse_relation(rest: &str, span: SourceSpan) -> Result<RelationDecl, ParseError> {
    let bracket = rest
        .find('[')
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let close = rest
        .find(']')
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let name = rest[..bracket].trim().to_owned();
    let binder_text = &rest[bracket + 1..close];
    let (binder, domain) = binder_text
        .split_once(':')
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let after = rest[close + 1..].trim();
    let after = after
        .strip_prefix("preserves ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (preserves, changes) = after
        .split_once(" changes ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    Ok(RelationDecl {
        name,
        binder: binder.trim().to_owned(),
        domain: domain.trim().to_owned(),
        preserves: split_names(preserves),
        changes: split_names(changes),
        span,
    })
}

fn parse_invariant(rest: &str, span: SourceSpan) -> Result<InvariantDecl, ParseError> {
    let open = rest
        .find('(')
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let close = rest
        .rfind(')')
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let after = rest[close + 1..].trim();
    let (before, after_value, tolerance, evidence) = if after.is_empty() {
        (0.0, 0.0, 0.0, String::new())
    } else {
        parse_invariant_tail(after)?
    };
    Ok(InvariantDecl {
        name: rest[..open].trim().to_owned(),
        argument: rest[open + 1..close].trim().to_owned(),
        before,
        after: after_value,
        tolerance,
        evidence,
        span,
    })
}

fn parse_evolve(rest: &str, span: SourceSpan) -> Result<EvolveDecl, ParseError> {
    let open = rest
        .find('(')
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let close = rest
        .find(')')
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let name = rest[..open].trim().to_owned();
    let params = rest[open + 1..close]
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            let (name, ty) = part
                .split_once(':')
                .ok_or_else(|| ParseError::Malformed(part.to_owned()))?;
            Ok((name.trim().to_owned(), ty.trim().to_owned()))
        })
        .collect::<Result<Vec<_>, ParseError>>()?;
    let after = rest[close + 1..].trim();
    let after = after
        .strip_prefix("by ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let mut words = after.split_whitespace();
    let backend = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .to_owned();
    let mut differentiable = false;
    let mut evidence = String::new();
    let mut pending_evidence = false;
    for word in words {
        if pending_evidence {
            evidence = word.to_owned();
            pending_evidence = false;
        } else if word == "differentiable" {
            differentiable = true;
        } else if word == "evidence" {
            pending_evidence = true;
        } else {
            return Err(ParseError::Malformed(rest.to_owned()));
        }
    }
    if pending_evidence {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(EvolveDecl {
        name,
        params,
        backend,
        differentiable,
        evidence,
        span,
    })
}

fn parse_measure(rest: &str, span: SourceSpan) -> Result<MeasureDecl, ParseError> {
    if let Some((name, value)) = rest.split_once(" normalizes ") {
        let normalizes = value
            .trim()
            .parse::<f64>()
            .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
        return Ok(MeasureDecl {
            name: name.trim().to_owned(),
            weights: vec![("mass".to_owned(), normalizes)],
            tolerance: 0.0,
            evidence: String::new(),
            span,
        });
    }

    let (name, tail) = rest
        .split_once(" weights ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (weights_text, tail) = tail
        .split_once(" tolerance ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (tolerance, evidence) = tail
        .split_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let tolerance = tolerance
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    let weights = weights_text
        .split(',')
        .map(|part| {
            let (name, weight) = part
                .trim()
                .split_once('=')
                .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
            let weight = weight
                .trim()
                .parse::<f64>()
                .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
            Ok((name.trim().to_owned(), weight))
        })
        .collect::<Result<Vec<_>, ParseError>>()?;
    Ok(MeasureDecl {
        name: name.trim().to_owned(),
        weights,
        tolerance,
        evidence: evidence.trim().to_owned(),
        span,
    })
}

fn parse_effect(rest: &str, span: SourceSpan) -> Result<EffectDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("uses") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let resource = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let access = match words.next() {
        Some("read") => EffectAccess::Read,
        Some("write") => EffectAccess::Write,
        _ => return Err(ParseError::Malformed(rest.to_owned())),
    };
    let evidence = match words.next() {
        None => String::new(),
        Some("evidence") => words
            .next()
            .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
            .to_owned(),
        Some(_) => return Err(ParseError::Malformed(rest.to_owned())),
    };
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(EffectDecl {
        name: name.to_owned(),
        resource: resource.to_owned(),
        access,
        evidence,
        span,
    })
}

fn parse_external(rest: &str, span: SourceSpan) -> Result<ExternalDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("interface") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let interface = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("uses") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let resource = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let access = match words.next() {
        Some("read") => EffectAccess::Read,
        Some("write") => EffectAccess::Write,
        _ => return Err(ParseError::Malformed(rest.to_owned())),
    };
    if words.next() != Some("evidence") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(ExternalDecl {
        name: name.to_owned(),
        interface: interface.to_owned(),
        resource: resource.to_owned(),
        access,
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_workspace(rest: &str, span: SourceSpan) -> Result<WorkspaceDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("uses") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let boundary = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let access = match words.next() {
        Some("read") => EffectAccess::Read,
        Some("write") => EffectAccess::Write,
        _ => return Err(ParseError::Malformed(rest.to_owned())),
    };
    if words.next() != Some("evidence") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(WorkspaceDecl {
        name: name.to_owned(),
        boundary: boundary.to_owned(),
        access,
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_parser(rest: &str, span: SourceSpan) -> Result<ParserDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("language") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let language = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("via") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let adapter = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("evidence") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(ParserDecl {
        name: name.to_owned(),
        language: language.to_owned(),
        adapter: adapter.to_owned(),
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_document(rest: &str, span: SourceSpan) -> Result<DocumentDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("via") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let adapter = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("evidence") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(DocumentDecl {
        name: name.to_owned(),
        adapter: adapter.to_owned(),
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_selection(rest: &str, span: SourceSpan) -> Result<SelectionDecl, ParseError> {
    let (name, tail) = rest
        .split_once(" = files where ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (predicate, evidence) = tail
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let name = name.trim();
    let predicate = predicate.trim();
    let evidence = evidence.trim();
    if name.is_empty() || predicate.is_empty() || evidence.is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(SelectionDecl {
        name: name.to_owned(),
        predicate: predicate.to_owned(),
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_transform(rest: &str, span: SourceSpan) -> Result<TransformDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let evidence = evidence.trim();
    if evidence.is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let mut words = head.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let operation = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let after_operation = head
        .trim_start()
        .strip_prefix(name)
        .and_then(|tail| tail.trim_start().strip_prefix(operation))
        .map(str::trim_start)
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let after_on = after_operation
        .strip_prefix("on ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;

    let (before_replacement, replacement) = parse_optional_replacement(after_on)?;
    let (before_predicate, predicate) = split_optional_clause(before_replacement, " where ");
    let (target_text, destination) = split_optional_destination(before_predicate)?;
    let target = parse_transform_target(target_text.trim(), rest)?;

    Ok(TransformDecl {
        name: name.to_owned(),
        operation: operation.to_owned(),
        target,
        destination,
        predicate,
        replacement,
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_validator(rest: &str, span: SourceSpan) -> Result<ValidatorDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let evidence = evidence.trim();
    let (name, argv) = head
        .split_once(" argv ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let name = name.trim();
    if name.is_empty() || evidence.is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(ValidatorDecl {
        name: name.to_owned(),
        argv: parse_argv(argv.trim()).map_err(|_| ParseError::Malformed(rest.to_owned()))?,
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_surface_function<'a, I>(
    rest: &str,
    span: SourceSpan,
    lines: &mut std::iter::Peekable<I>,
) -> Result<(FunctionDecl, usize), ParseError>
where
    I: Iterator<Item = &'a str>,
{
    let header = rest.trim();
    let open = header
        .find('(')
        .ok_or_else(|| ParseError::Malformed(header.to_owned()))?;
    let name = header[..open].trim();
    if name.is_empty() || name.split_whitespace().count() != 1 || !header.contains('{') {
        return Err(ParseError::Malformed(header.to_owned()));
    }
    let mut body = String::new();
    let mut consumed = 0usize;
    let mut depth = brace_delta(header);
    while depth > 0 {
        let Some(raw) = lines.next() else {
            return Err(ParseError::Malformed(
                "function block is not closed".to_owned(),
            ));
        };
        consumed += raw.len();
        depth += brace_delta(raw);
        if depth > 0 || raw.trim() != "}" {
            body.push_str(raw);
        }
    }
    Ok((
        FunctionDecl {
            name: name.to_owned(),
            signature: header.trim_end_matches('{').trim().to_owned(),
            body,
            span,
        },
        consumed,
    ))
}

fn parse_graphics_block<'a, I>(
    rest: &str,
    span: SourceSpan,
    lines: &mut std::iter::Peekable<I>,
) -> Result<(GraphicsDecl, usize), ParseError>
where
    I: Iterator<Item = &'a str>,
{
    let header = rest.trim();
    let header = header
        .strip_suffix('{')
        .ok_or_else(|| ParseError::Malformed("graphics block must open with `{`".to_owned()))?
        .trim();
    let (head, evidence) = header
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let mut words = head.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let mut entry = "main".to_owned();
    if let Some(word) = words.next() {
        if word != "entry" {
            return Err(ParseError::Malformed(rest.to_owned()));
        }
        entry = words
            .next()
            .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
            .to_owned();
    }
    if words.next().is_some() || evidence.trim().is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }

    let mut body = String::new();
    let mut consumed = 0usize;
    let mut depth = 1isize;
    let mut closed = false;
    for raw in lines.by_ref() {
        consumed += raw.len();
        depth += brace_delta(raw);
        if depth == 0 {
            closed = true;
            let without_close = raw.trim_end();
            if without_close != "}" {
                body.push_str(raw.trim_end_matches('}'));
            }
            break;
        }
        body.push_str(raw);
    }
    if !closed {
        return Err(ParseError::Malformed(
            "graphics block is not closed".to_owned(),
        ));
    }
    let imports = body
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("import "))
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect();
    Ok((
        GraphicsDecl {
            name: name.to_owned(),
            entry,
            imports,
            body,
            evidence: evidence.trim().to_owned(),
            span,
        },
        consumed,
    ))
}

fn brace_delta(input: &str) -> isize {
    let mut opens = 0usize;
    let mut closes = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for ch in input.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => opens += 1,
            '}' => closes += 1,
            _ => {}
        }
    }
    opens as isize - closes as isize
}

fn parse_render_target(rest: &str, span: SourceSpan) -> Result<RenderTargetDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "width", rest)?;
    let width = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<u32>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "height", rest)?;
    let height = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<u32>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "format", rest)?;
    let format = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "evidence", rest)?;
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(RenderTargetDecl {
        name: name.to_owned(),
        width,
        height,
        format: format.to_owned(),
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_render_pipeline(rest: &str, span: SourceSpan) -> Result<RenderPipelineDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "graphics", rest)?;
    let graphics = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "target", rest)?;
    let target = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "entry", rest)?;
    let entry = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let mut mode = "native".to_owned();
    let next = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if next == "mode" {
        mode = words
            .next()
            .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
            .to_owned();
        expect_word(words.next(), "evidence", rest)?;
    } else if next != "evidence" {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(RenderPipelineDecl {
        name: name.to_owned(),
        graphics: graphics.to_owned(),
        target: target.to_owned(),
        entry: entry.to_owned(),
        mode,
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_benchmark(rest: &str, span: SourceSpan) -> Result<BenchmarkDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "graphics", rest)?;
    let graphics = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "entry", rest)?;
    let entry = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "warmup", rest)?;
    let warmup = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<u32>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "iterations", rest)?;
    let iterations = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<u32>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "evidence", rest)?;
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(BenchmarkDecl {
        name: name.to_owned(),
        graphics: graphics.to_owned(),
        entry: entry.to_owned(),
        warmup,
        iterations,
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_tensor(rest: &str, span: SourceSpan) -> Result<TensorDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, layout) = head
        .rsplit_once(" layout ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, gradient) = head
        .rsplit_once(" gradient ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, dtype) = head
        .rsplit_once(" dtype ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (name, shape) = head
        .split_once(" shape ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let name = name.trim();
    let evidence = evidence.trim();
    if name.is_empty()
        || dtype.trim().is_empty()
        || gradient.trim().is_empty()
        || layout.trim().is_empty()
        || evidence.is_empty()
    {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(TensorDecl {
        name: name.to_owned(),
        shape: parse_name_list(shape.trim()).map_err(|_| ParseError::Malformed(rest.to_owned()))?,
        dtype: dtype.trim().to_owned(),
        gradient: gradient.trim().to_owned(),
        layout: layout.trim().to_owned(),
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_accelerator(rest: &str, span: SourceSpan) -> Result<AcceleratorDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, supports) = head
        .rsplit_once(" supports ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let mut words = head.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "kind", rest)?;
    let kind = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "memory", rest)?;
    let memory = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "precision", rest)?;
    let precision = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() || evidence.trim().is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(AcceleratorDecl {
        name: name.to_owned(),
        kind: kind.to_owned(),
        memory: memory.to_owned(),
        precision: precision.to_owned(),
        supports: parse_name_list(supports.trim())
            .map_err(|_| ParseError::Malformed(rest.to_owned()))?,
        evidence: evidence.trim().to_owned(),
        span,
    })
}

fn parse_dataset(rest: &str, span: SourceSpan) -> Result<DatasetDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, source_digest) = split_quoted_tail(head, " digest ")?;
    let (head, source) = split_quoted_tail(head, " source ")?;
    let mut words = head.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "tensors", rest)?;
    let tensors = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() || evidence.trim().is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(DatasetDecl {
        name: name.to_owned(),
        tensors: parse_name_list(tensors).map_err(|_| ParseError::Malformed(rest.to_owned()))?,
        source,
        source_digest,
        evidence: evidence.trim().to_owned(),
        span,
    })
}

fn parse_model(rest: &str, span: SourceSpan) -> Result<ModelDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, loss) = head
        .rsplit_once(" loss ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, ops) = head
        .rsplit_once(" ops ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let mut words = head.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "entry", rest)?;
    let entry = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "inputs", rest)?;
    let inputs = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "parameters", rest)?;
    let parameters = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "outputs", rest)?;
    let outputs = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() || loss.trim().is_empty() || evidence.trim().is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(ModelDecl {
        name: name.to_owned(),
        entry: entry.to_owned(),
        inputs: parse_name_list(inputs).map_err(|_| ParseError::Malformed(rest.to_owned()))?,
        parameters: parse_name_list(parameters)
            .map_err(|_| ParseError::Malformed(rest.to_owned()))?,
        outputs: parse_name_list(outputs).map_err(|_| ParseError::Malformed(rest.to_owned()))?,
        ops: parse_argv(ops.trim()).map_err(|_| ParseError::Malformed(rest.to_owned()))?,
        loss: loss.trim().to_owned(),
        evidence: evidence.trim().to_owned(),
        span,
    })
}

fn parse_training(rest: &str, span: SourceSpan) -> Result<TrainingDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "model", rest)?;
    let model = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "dataset", rest)?;
    let dataset = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "accelerator", rest)?;
    let accelerator = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "optimizer", rest)?;
    let optimizer = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "learning-rate", rest)?;
    let learning_rate = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<f64>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "steps", rest)?;
    let steps = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<u32>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "batch", rest)?;
    let batch = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<u32>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "objective", rest)?;
    let objective = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "evidence", rest)?;
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(TrainingDecl {
        name: name.to_owned(),
        model: model.to_owned(),
        dataset: dataset.to_owned(),
        accelerator: accelerator.to_owned(),
        optimizer: optimizer.to_owned(),
        learning_rate,
        steps,
        batch,
        objective: objective.to_owned(),
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_machine(rest: &str, span: SourceSpan) -> Result<MachineDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, source_digest) = split_quoted_tail(head, " digest ")?;
    let (head, source) = split_quoted_tail(head, " source ")?;
    let mut words = head.split_whitespace();
    let id = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "isa", rest)?;
    let isa = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "profile", rest)?;
    let profile = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "word", rest)?;
    let word_bits = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<u32>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "endian", rest)?;
    let endianness = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "memory", rest)?;
    let memory_model = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "via", rest)?;
    let adapter = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() || evidence.trim().is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(MachineDecl {
        id: id.to_owned(),
        isa: isa.to_owned(),
        profile: profile.to_owned(),
        word_bits,
        endianness: endianness.to_owned(),
        memory_model: memory_model.to_owned(),
        semantic_source: format!("{adapter}:{source}"),
        source_digest,
        evidence: evidence.trim().to_owned(),
        span,
    })
}

fn parse_memory(rest: &str, span: SourceSpan) -> Result<MemoryDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, frame) = split_quoted_tail(head, " frame ")?;
    let (head, region) = split_quoted_tail(head, " region ")?;
    let mut words = head.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "for", rest)?;
    let machine = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "address", rest)?;
    let address_bits = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<u32>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "order", rest)?;
    let ordering = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() || evidence.trim().is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(MemoryDecl {
        name: name.to_owned(),
        machine: machine.to_owned(),
        address_bits,
        ordering: ordering.to_owned(),
        regions: vec![parse_memory_region(&region, rest)?],
        frame_conditions: split_csv(&frame),
        evidence: evidence.trim().to_owned(),
        span,
    })
}

fn parse_instruction(rest: &str, span: SourceSpan) -> Result<InstructionDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, proof_artifact) = head
        .rsplit_once(" proof ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, effects) = split_quoted_tail(head, " effects ")?;
    let (head, semantics) = head
        .rsplit_once(" semantics ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, encoding) = split_quoted_tail(head, " encoding ")?;
    let (head, mnemonic) = split_quoted_tail(head, " mnemonic ")?;
    let mut words = head.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "in", rest)?;
    let machine = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some()
        || semantics.trim().is_empty()
        || proof_artifact.trim().is_empty()
        || evidence.trim().is_empty()
    {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(InstructionDecl {
        name: name.to_owned(),
        machine: machine.to_owned(),
        mnemonic,
        encoding,
        semantics: semantics.trim().to_owned(),
        effects: split_csv(&effects),
        proof_artifact: proof_artifact.trim().to_owned(),
        evidence: evidence.trim().to_owned(),
        span,
    })
}

fn parse_abi(rest: &str, span: SourceSpan) -> Result<AbiDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, external_policy) = head
        .rsplit_once(" external ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let mut words = head.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "for", rest)?;
    let machine = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "target", rest)?;
    let target_triple = parse_quoted(
        words
            .next()
            .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?,
    )
    .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "object", rest)?;
    let object_format = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "calling", rest)?;
    let calling_convention = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() || external_policy.trim().is_empty() || evidence.trim().is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(AbiDecl {
        name: name.to_owned(),
        machine: machine.to_owned(),
        target_triple,
        object_format: object_format.to_owned(),
        calling_convention: calling_convention.to_owned(),
        external_policy: external_policy.trim().to_owned(),
        evidence: evidence.trim().to_owned(),
        span,
    })
}

fn parse_proof_artifact(rest: &str, span: SourceSpan) -> Result<ProofArtifactDecl, ParseError> {
    let (head, evidence) = rest
        .rsplit_once(" evidence ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, obligations) = head
        .rsplit_once(" obligations ")
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    let (head, digest) = split_quoted_tail(head, " digest ")?;
    let (head, module) = split_quoted_tail(head, " module ")?;
    let mut words = head.split_whitespace();
    let name = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    expect_word(words.next(), "prover", rest)?;
    let prover = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() || evidence.trim().is_empty() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(ProofArtifactDecl {
        name: name.to_owned(),
        prover: prover.to_owned(),
        module,
        digest,
        obligations: parse_name_list(obligations.trim())
            .map_err(|_| ParseError::Malformed(rest.to_owned()))?,
        evidence: evidence.trim().to_owned(),
        span,
    })
}

fn parse_ad(rest: &str, span: SourceSpan) -> Result<AdDecl, ParseError> {
    let mut words = rest.split_whitespace();
    let primal = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("tangent") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let tangent = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("adjoint") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let adjoint = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("law") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let law = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("evidence") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok(AdDecl {
        primal: primal.to_owned(),
        tangent: tangent.to_owned(),
        adjoint: adjoint.to_owned(),
        law: law.to_owned(),
        evidence: evidence.to_owned(),
        span,
    })
}

fn parse_theorem(rest: &str, span: SourceSpan) -> Result<TheoremDecl, ParseError> {
    let (name, proposition) = rest
        .split_once(':')
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?;
    Ok(TheoremDecl {
        name: name.trim().to_owned(),
        proposition: parse_proposition(proposition.trim()).map_err(proof_parse_error)?,
        span,
    })
}

fn parse_proof_block<'a, I>(
    rest: &str,
    span: SourceSpan,
    lines: &mut std::iter::Peekable<I>,
) -> Result<(ProofDecl, usize), ParseError>
where
    I: Iterator<Item = &'a str>,
{
    let header = rest.trim();
    let theorem = header
        .strip_suffix('{')
        .ok_or_else(|| ParseError::MalformedProof("proof block must open with `{`".to_owned()))?
        .trim();
    if theorem.is_empty() || theorem.split_whitespace().count() != 1 {
        return Err(ParseError::MalformedProof(
            "proof block must name one theorem".to_owned(),
        ));
    }
    let mut body = String::new();
    let mut consumed = 0;
    let mut closed = false;
    for raw in lines.by_ref() {
        consumed += raw.len();
        let line = raw.trim();
        if line == "}" {
            closed = true;
            break;
        }
        body.push_str(raw);
    }
    if !closed {
        return Err(ParseError::MalformedProof(
            "proof block is not closed".to_owned(),
        ));
    }
    let script = parse_script(theorem, &body).map_err(proof_parse_error)?;
    Ok(ProofDecl {
        theorem: theorem.to_owned(),
        script,
        span,
    })
    .map(|proof| (proof, consumed))
}

fn proof_parse_error(error: ProofParseError) -> ParseError {
    ParseError::MalformedProof(error.to_string())
}

fn parse_invariant_tail(rest: &str) -> Result<(f64, f64, f64, String), ParseError> {
    let mut words = rest.split_whitespace();
    if words.next() != Some("before") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let before = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<f64>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("after") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let after = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<f64>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("tolerance") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let tolerance = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .parse::<f64>()
        .map_err(|_| ParseError::Malformed(rest.to_owned()))?;
    if words.next() != Some("evidence") {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    let evidence = words
        .next()
        .ok_or_else(|| ParseError::Malformed(rest.to_owned()))?
        .to_owned();
    if words.next().is_some() {
        return Err(ParseError::Malformed(rest.to_owned()));
    }
    Ok((before, after, tolerance, evidence))
}

fn split_optional_clause<'a>(input: &'a str, marker: &str) -> (&'a str, Option<String>) {
    input
        .rsplit_once(marker)
        .map(|(head, clause)| (head.trim_end(), Some(clause.trim().to_owned())))
        .unwrap_or((input, None))
}

fn split_optional_destination(input: &str) -> Result<(&str, Option<String>), ParseError> {
    if let Some((head, destination)) = input.rsplit_once(" into ") {
        return Ok((
            head.trim_end(),
            Some(parse_quoted(destination.trim()).map_err(|_| {
                ParseError::Malformed(format!("invalid destination literal: {destination}"))
            })?),
        ));
    }
    Ok((input, None))
}

fn parse_optional_replacement(
    input: &str,
) -> Result<(&str, Option<TextReplacementDecl>), ParseError> {
    let Some((head, tail)) = input.rsplit_once(" from ") else {
        return Ok((input, None));
    };
    let (from, to) = tail
        .split_once(" to ")
        .ok_or_else(|| ParseError::Malformed(input.to_owned()))?;
    Ok((
        head.trim_end(),
        Some(TextReplacementDecl {
            from: parse_quoted(from.trim()).map_err(|_| ParseError::Malformed(input.to_owned()))?,
            to: parse_quoted(to.trim()).map_err(|_| ParseError::Malformed(input.to_owned()))?,
        }),
    ))
}

fn parse_transform_target(input: &str, source: &str) -> Result<TransformTargetDecl, ParseError> {
    if let Some(path) = input
        .strip_prefix("file(")
        .and_then(|tail| tail.strip_suffix(')'))
    {
        return Ok(TransformTargetDecl::File(
            parse_quoted(path.trim()).map_err(|_| ParseError::Malformed(source.to_owned()))?,
        ));
    }
    if input.is_empty() || input.split_whitespace().count() != 1 {
        return Err(ParseError::Malformed(source.to_owned()));
    }
    Ok(TransformTargetDecl::Selection(input.to_owned()))
}

fn parse_argv(input: &str) -> Result<Vec<String>, ()> {
    let body = input
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(())?;
    parse_quoted_list_body(body)
}

fn parse_quoted_list_body(body: &str) -> Result<Vec<String>, ()> {
    let mut values = Vec::new();
    let mut token = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in body.chars() {
        if escaped {
            token.push('\\');
            token.push(ch);
            escaped = false;
            continue;
        }
        if in_string && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            token.push(ch);
            continue;
        }
        if ch == ',' && !in_string {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                values.push(parse_quoted(trimmed)?);
            }
            token.clear();
            continue;
        }
        token.push(ch);
    }
    if in_string || escaped {
        return Err(());
    }
    let trimmed = token.trim();
    if !trimmed.is_empty() {
        values.push(parse_quoted(trimmed)?);
    }
    Ok(values)
}

fn parse_name_list(input: &str) -> Result<Vec<String>, ()> {
    let body = input
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(())?;
    if body.trim().is_empty() {
        return Ok(vec![]);
    }
    Ok(split_csv(body))
}

fn parse_quoted(input: &str) -> Result<String, ()> {
    let body = input
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(())?;
    let mut output = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('"') => output.push('"'),
                Some('\\') => output.push('\\'),
                Some('n') => output.push('\n'),
                Some(other) => {
                    output.push('\\');
                    output.push(other);
                }
                None => output.push('\\'),
            }
        } else {
            output.push(ch);
        }
    }
    Ok(output)
}

fn split_quoted_tail<'a>(input: &'a str, marker: &str) -> Result<(&'a str, String), ParseError> {
    let (head, value) = input
        .rsplit_once(marker)
        .ok_or_else(|| ParseError::Malformed(input.to_owned()))?;
    Ok((
        head.trim_end(),
        parse_quoted(value.trim()).map_err(|_| ParseError::Malformed(input.to_owned()))?,
    ))
}

fn expect_word(found: Option<&str>, expected: &str, source: &str) -> Result<(), ParseError> {
    if found == Some(expected) {
        Ok(())
    } else {
        Err(ParseError::Malformed(source.to_owned()))
    }
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_memory_region(input: &str, source: &str) -> Result<MemoryRegionDecl, ParseError> {
    let mut parts = input.split(':');
    let name = parts
        .next()
        .ok_or_else(|| ParseError::Malformed(source.to_owned()))?;
    let base = parts
        .next()
        .ok_or_else(|| ParseError::Malformed(source.to_owned()))
        .and_then(|value| parse_u64(value, source))?;
    let size = parts
        .next()
        .ok_or_else(|| ParseError::Malformed(source.to_owned()))
        .and_then(|value| parse_u64(value, source))?;
    let permissions = parts
        .next()
        .ok_or_else(|| ParseError::Malformed(source.to_owned()))?
        .split('-')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if parts.next().is_some() || name.trim().is_empty() || permissions.is_empty() {
        return Err(ParseError::Malformed(source.to_owned()));
    }
    Ok(MemoryRegionDecl {
        name: name.trim().to_owned(),
        base,
        size,
        permissions,
    })
}

fn parse_u64(value: &str, source: &str) -> Result<u64, ParseError> {
    value
        .strip_prefix("0x")
        .map(|hex| u64::from_str_radix(hex, 16))
        .unwrap_or_else(|| value.parse::<u64>())
        .map_err(|_| ParseError::Malformed(source.to_owned()))
}

fn split_names(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|part| part.trim().trim_end_matches("[c]").to_owned())
        .filter(|part| !part.is_empty())
        .collect()
}
