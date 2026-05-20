use std::path::Path;
use thiserror::Error;
use tree_sitter::{Language, Node, Parser};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
            "h" | "hh" | "hpp" | "hxx" | "cc" | "cpp" | "cxx" => Some(Self::Cpp),
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

#[derive(Debug, Error)]
pub enum CodeMapError {
    #[error("failed to initialize {dialect} syntax parser: {message}")]
    ParserInit {
        dialect: &'static str,
        message: String,
    },
    #[error("{dialect} syntax parser produced no tree")]
    EmptyTree { dialect: &'static str },
}

#[derive(Clone, Debug, Default)]
pub struct CodeAnalysis {
    pub dialect: Option<SourceDialect>,
    pub parse_error: bool,
    pub metrics: CodeMetrics,
    pub imports: Vec<CodeImport>,
    pub symbols: Vec<CodeSymbol>,
    pub calls: Vec<CodeCall>,
    pub markers: Vec<CodeMarker>,
}

#[derive(Clone, Debug, Default)]
pub struct CodeMetrics {
    pub code_lines: usize,
    pub comment_lines: usize,
    pub blank_lines: usize,
    pub max_nesting: usize,
    pub unsafe_blocks: usize,
    pub extern_blocks: usize,
    pub public_items: usize,
    pub function_count: usize,
    pub type_count: usize,
    pub import_count: usize,
    pub call_count: usize,
    pub marker_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeSpan {
    pub start: usize,
    pub end: usize,
}

impl CodeSpan {
    fn from_node(node: Node<'_>) -> Self {
        Self {
            start: node.start_byte(),
            end: node.end_byte(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeImportKind {
    Include,
    Use,
    Module,
    ExternCrate,
    Namespace,
}

#[derive(Clone, Debug)]
pub struct CodeImport {
    pub kind: CodeImportKind,
    pub target: String,
    pub span: CodeSpan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeSymbolKind {
    Function,
    Method,
    Type,
    Namespace,
    Module,
    Trait,
    Impl,
    Macro,
    Constant,
}

#[derive(Clone, Debug)]
pub struct CodeSymbol {
    pub kind: CodeSymbolKind,
    pub name: String,
    pub detail: String,
    pub public: bool,
    pub span: CodeSpan,
}

#[derive(Clone, Debug)]
pub struct CodeCall {
    pub caller: Option<String>,
    pub target: String,
    pub span: CodeSpan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeMarkerKind {
    Todo,
    Fixme,
    Safety,
    Note,
}

#[derive(Clone, Debug)]
pub struct CodeMarker {
    pub kind: CodeMarkerKind,
    pub text: String,
    pub span: CodeSpan,
}

pub fn analyze_code(source: &str, dialect: SourceDialect) -> Result<CodeAnalysis, CodeMapError> {
    let mut parser = Parser::new();
    let language = dialect.language();
    parser
        .set_language(&language)
        .map_err(|error| CodeMapError::ParserInit {
            dialect: dialect.label(),
            message: error.to_string(),
        })?;
    let tree = parser.parse(source, None).ok_or(CodeMapError::EmptyTree {
        dialect: dialect.label(),
    })?;

    let mut analysis = CodeAnalysis {
        dialect: Some(dialect),
        parse_error: tree.root_node().has_error(),
        metrics: line_metrics(source),
        imports: vec![],
        symbols: vec![],
        calls: vec![],
        markers: vec![],
    };
    analysis.markers = extract_markers(source);

    let mut state = WalkState {
        source,
        dialect,
        analysis,
        current_symbols: vec![],
        nesting: 0,
    };
    walk_node(tree.root_node(), &mut state);
    state.finish()
}

pub fn import_kind_label(kind: CodeImportKind) -> &'static str {
    match kind {
        CodeImportKind::Include => "include",
        CodeImportKind::Use => "use",
        CodeImportKind::Module => "module",
        CodeImportKind::ExternCrate => "extern_crate",
        CodeImportKind::Namespace => "namespace",
    }
}

pub fn symbol_kind_label(kind: CodeSymbolKind) -> &'static str {
    match kind {
        CodeSymbolKind::Function => "function",
        CodeSymbolKind::Method => "method",
        CodeSymbolKind::Type => "type",
        CodeSymbolKind::Namespace => "namespace",
        CodeSymbolKind::Module => "module",
        CodeSymbolKind::Trait => "trait",
        CodeSymbolKind::Impl => "impl",
        CodeSymbolKind::Macro => "macro",
        CodeSymbolKind::Constant => "constant",
    }
}

pub fn marker_kind_label(kind: CodeMarkerKind) -> &'static str {
    match kind {
        CodeMarkerKind::Todo => "todo",
        CodeMarkerKind::Fixme => "fixme",
        CodeMarkerKind::Safety => "safety",
        CodeMarkerKind::Note => "note",
    }
}

struct WalkState<'a> {
    source: &'a str,
    dialect: SourceDialect,
    analysis: CodeAnalysis,
    current_symbols: Vec<String>,
    nesting: usize,
}

impl WalkState<'_> {
    fn finish(mut self) -> Result<CodeAnalysis, CodeMapError> {
        dedupe_imports(&mut self.analysis.imports);
        dedupe_symbols(&mut self.analysis.symbols);
        dedupe_calls(&mut self.analysis.calls);

        self.analysis.metrics.import_count = self.analysis.imports.len();
        self.analysis.metrics.call_count = self.analysis.calls.len();
        self.analysis.metrics.marker_count = self.analysis.markers.len();
        self.analysis.metrics.function_count = self
            .analysis
            .symbols
            .iter()
            .filter(|symbol| {
                matches!(
                    symbol.kind,
                    CodeSymbolKind::Function | CodeSymbolKind::Method
                )
            })
            .count();
        self.analysis.metrics.type_count = self
            .analysis
            .symbols
            .iter()
            .filter(|symbol| {
                matches!(
                    symbol.kind,
                    CodeSymbolKind::Type | CodeSymbolKind::Trait | CodeSymbolKind::Impl
                )
            })
            .count();
        self.analysis.metrics.public_items = self
            .analysis
            .symbols
            .iter()
            .filter(|symbol| symbol.public)
            .count();
        Ok(self.analysis)
    }
}

fn walk_node(node: Node<'_>, state: &mut WalkState<'_>) {
    if node.is_named() {
        if let Some(import) = import_from_node(state.dialect, node, state.source) {
            state.analysis.imports.push(import);
        }
        if let Some(call) =
            call_from_node(state.dialect, node, state.source, &state.current_symbols)
        {
            state.analysis.calls.push(call);
        }
        if is_unsafe_node(node) {
            state.analysis.metrics.unsafe_blocks += 1;
        }
        if is_extern_node(node) {
            state.analysis.metrics.extern_blocks += 1;
        }
    }

    let symbol = symbol_from_node(state.dialect, node, state.source);
    let symbol_name = symbol.as_ref().and_then(|symbol| {
        if matches!(
            symbol.kind,
            CodeSymbolKind::Function | CodeSymbolKind::Method
        ) {
            Some(symbol.name.clone())
        } else {
            None
        }
    });
    if let Some(symbol) = symbol {
        state.analysis.symbols.push(symbol);
    }
    if let Some(ref name) = symbol_name {
        state.current_symbols.push(name.clone());
    }

    let nesting_increment = nesting_increment(node.kind());
    state.nesting += nesting_increment;
    state.analysis.metrics.max_nesting = state.analysis.metrics.max_nesting.max(state.nesting);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_node(child, state);
    }
    state.nesting = state.nesting.saturating_sub(nesting_increment);

    if symbol_name.is_some() {
        state.current_symbols.pop();
    }
}

fn symbol_from_node(dialect: SourceDialect, node: Node<'_>, source: &str) -> Option<CodeSymbol> {
    let kind = node.kind();
    let symbol_kind = match (dialect, kind) {
        (SourceDialect::Rust, "function_item") => CodeSymbolKind::Function,
        (SourceDialect::Rust, "struct_item" | "enum_item" | "union_item" | "type_item") => {
            CodeSymbolKind::Type
        }
        (SourceDialect::Rust, "trait_item") => CodeSymbolKind::Trait,
        (SourceDialect::Rust, "impl_item") => CodeSymbolKind::Impl,
        (SourceDialect::Rust, "mod_item") => CodeSymbolKind::Module,
        (SourceDialect::Rust, "macro_definition") => CodeSymbolKind::Macro,
        (SourceDialect::Rust, "const_item" | "static_item") => CodeSymbolKind::Constant,
        (SourceDialect::C | SourceDialect::Cpp, "function_definition") => {
            if function_looks_like_method(node, source) {
                CodeSymbolKind::Method
            } else {
                CodeSymbolKind::Function
            }
        }
        (SourceDialect::C | SourceDialect::Cpp, "struct_specifier" | "enum_specifier") => {
            CodeSymbolKind::Type
        }
        (SourceDialect::C, "union_specifier") => CodeSymbolKind::Type,
        (SourceDialect::Cpp, "class_specifier" | "union_specifier" | "type_definition") => {
            CodeSymbolKind::Type
        }
        (SourceDialect::Cpp, "namespace_definition") => CodeSymbolKind::Namespace,
        (SourceDialect::C | SourceDialect::Cpp, "preproc_function_def" | "preproc_def") => {
            CodeSymbolKind::Macro
        }
        _ => return None,
    };

    let name = name_for_symbol(dialect, symbol_kind, node, source)?;
    let detail = signature_for_node(node, source);
    Some(CodeSymbol {
        kind: symbol_kind,
        name,
        detail,
        public: is_public_symbol(dialect, node, source),
        span: CodeSpan::from_node(node),
    })
}

fn name_for_symbol(
    dialect: SourceDialect,
    symbol_kind: CodeSymbolKind,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    if symbol_kind == CodeSymbolKind::Impl {
        return node
            .child_by_field_name("type")
            .and_then(|node| normalized_node_text(node, source))
            .or_else(|| deep_identifier(node, source));
    }
    if matches!(
        symbol_kind,
        CodeSymbolKind::Function | CodeSymbolKind::Method
    ) && matches!(dialect, SourceDialect::C | SourceDialect::Cpp)
    {
        return node
            .child_by_field_name("declarator")
            .and_then(|node| deep_identifier(node, source))
            .or_else(|| deep_identifier(node, source));
    }
    if matches!(
        symbol_kind,
        CodeSymbolKind::Macro | CodeSymbolKind::Constant | CodeSymbolKind::Module
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

fn import_from_node(dialect: SourceDialect, node: Node<'_>, source: &str) -> Option<CodeImport> {
    let kind = node.kind();
    let text = node_text(node, source)?;
    match (dialect, kind) {
        (SourceDialect::Rust, "use_declaration") => Some(CodeImport {
            kind: CodeImportKind::Use,
            target: trim_rust_use(text),
            span: CodeSpan::from_node(node),
        }),
        (SourceDialect::Rust, "extern_crate_declaration") => Some(CodeImport {
            kind: CodeImportKind::ExternCrate,
            target: trim_extern_crate(text),
            span: CodeSpan::from_node(node),
        }),
        (SourceDialect::Rust, "mod_item") if text.trim_end().ends_with(';') => Some(CodeImport {
            kind: CodeImportKind::Module,
            target: node
                .child_by_field_name("name")
                .and_then(|node| normalized_node_text(node, source))
                .unwrap_or_else(|| trim_rust_mod(text)),
            span: CodeSpan::from_node(node),
        }),
        (SourceDialect::C | SourceDialect::Cpp, "preproc_include") => Some(CodeImport {
            kind: CodeImportKind::Include,
            target: trim_include(text),
            span: CodeSpan::from_node(node),
        }),
        (SourceDialect::Cpp, "using_declaration" | "namespace_alias_definition") => {
            Some(CodeImport {
                kind: CodeImportKind::Namespace,
                target: compact_whitespace(text.trim_end_matches(';')),
                span: CodeSpan::from_node(node),
            })
        }
        _ => None,
    }
}

fn call_from_node(
    dialect: SourceDialect,
    node: Node<'_>,
    source: &str,
    current_symbols: &[String],
) -> Option<CodeCall> {
    let target = match (dialect, node.kind()) {
        (_, "call_expression") => node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
            .and_then(|node| normalized_node_text(node, source)),
        (SourceDialect::Rust, "macro_invocation") => rust_macro_call_name(node, source),
        _ => None,
    }?;
    let target = target.trim();
    if target.is_empty() || target.len() > 160 {
        return None;
    }
    Some(CodeCall {
        caller: current_symbols.last().cloned(),
        target: target.to_owned(),
        span: CodeSpan::from_node(node),
    })
}

fn line_metrics(source: &str) -> CodeMetrics {
    let mut metrics = CodeMetrics::default();
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

fn extract_markers(source: &str) -> Vec<CodeMarker> {
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
                Some(CodeMarkerKind::Fixme)
            } else if lower.contains("todo") {
                Some(CodeMarkerKind::Todo)
            } else if lower.contains("safety") {
                Some(CodeMarkerKind::Safety)
            } else if lower.contains("note") {
                Some(CodeMarkerKind::Note)
            } else {
                None
            };
            if let Some(kind) = kind {
                markers.push(CodeMarker {
                    kind,
                    text: truncate(compact_whitespace(trimmed), 180),
                    span: CodeSpan {
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

fn is_unsafe_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "unsafe_block" | "unsafe_function_item")
}

fn is_extern_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "extern_block" | "extern_crate_declaration" | "linkage_specification"
    )
}

fn is_public_symbol(dialect: SourceDialect, node: Node<'_>, source: &str) -> bool {
    match dialect {
        SourceDialect::Rust => {
            node.child_by_field_name("visibility").is_some()
                || signature_for_node(node, source).starts_with("pub ")
        }
        SourceDialect::C => !signature_for_node(node, source).starts_with("static "),
        SourceDialect::Cpp => {
            let signature = signature_for_node(node, source);
            !signature.starts_with("static ") && !signature.contains(" private:")
        }
    }
}

fn function_looks_like_method(node: Node<'_>, source: &str) -> bool {
    node.child_by_field_name("declarator")
        .and_then(|node| normalized_node_text(node, source))
        .is_some_and(|declarator| {
            declarator.contains("::") || declarator.contains('.') || declarator.contains("->")
        })
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
    let signature = compact_whitespace(&source[start..end]);
    truncate(
        signature.trim_end_matches('{').trim_end_matches(';').trim(),
        240,
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

fn trim_include(text: &str) -> String {
    let text = text.trim().trim_start_matches("#include").trim();
    if let Some(body) = text
        .strip_prefix('<')
        .and_then(|tail| tail.split('>').next())
    {
        return body.trim().to_owned();
    }
    if let Some(body) = text
        .strip_prefix('"')
        .and_then(|tail| tail.split('"').next())
    {
        return body.trim().to_owned();
    }
    compact_whitespace(text)
}

fn compact_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate(input: impl AsRef<str>, max_len: usize) -> String {
    let input = input.as_ref();
    if input.len() <= max_len {
        input.to_owned()
    } else {
        format!("{}...", &input[..max_len.saturating_sub(3)])
    }
}

fn dedupe_imports(imports: &mut Vec<CodeImport>) {
    imports.sort_by(|left, right| {
        import_kind_label(left.kind)
            .cmp(import_kind_label(right.kind))
            .then(left.target.cmp(&right.target))
            .then(left.span.start.cmp(&right.span.start))
    });
    imports.dedup_by(|left, right| {
        left.kind == right.kind
            && left.target == right.target
            && left.span.start == right.span.start
    });
}

fn dedupe_symbols(symbols: &mut Vec<CodeSymbol>) {
    symbols.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(symbol_kind_label(left.kind).cmp(symbol_kind_label(right.kind)))
            .then(left.span.start.cmp(&right.span.start))
    });
    symbols.dedup_by(|left, right| {
        left.kind == right.kind && left.name == right.name && left.span.start == right.span.start
    });
}

fn dedupe_calls(calls: &mut Vec<CodeCall>) {
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
