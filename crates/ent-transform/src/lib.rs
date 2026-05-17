use ent_core::{
    Certificate, ParserContract, TextReplacement, TransformContract, TransformTarget,
    ValidatorContract,
};
use ent_kernel::verify;
use pulldown_cmark::{Event, Parser as MarkdownParser, Tag, TagEnd};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use streaming_iterator::StreamingIterator;
use tempfile::TempDir;
use thiserror::Error;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApplyReport {
    pub world: String,
    pub changed_files: Vec<FileChange>,
    pub validators: Vec<ValidatorReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileChange {
    pub path: String,
    pub action: FileAction,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAction {
    Write,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ValidatorReport {
    pub name: String,
    pub argv: Vec<String>,
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Error)]
pub enum TransformError {
    #[error("trusted kernel rejected transform certificate: {0}")]
    Kernel(#[from] ent_kernel::KernelError),
    #[error("workspace transforms require a declared writable filesystem workspace")]
    MissingWritableWorkspace,
    #[error("invalid repository path: {0}")]
    InvalidRepo(String),
    #[error("invalid relative path in transform contract: {0}")]
    InvalidRelativePath(String),
    #[error("selection is undeclared: {0}")]
    UnknownSelection(String),
    #[error("parser adapter is undeclared: {0}")]
    UnknownParser(String),
    #[error("unsupported selection predicate: {0}")]
    UnsupportedSelectionPredicate(String),
    #[error("unsupported transform operation: {0}")]
    UnsupportedTransform(String),
    #[error("unsupported file for transform {transform}: {path}")]
    UnsupportedFile { transform: String, path: String },
    #[error("multiple parser adapters match {path}: {parsers:?}")]
    AmbiguousParser { path: String, parsers: Vec<String> },
    #[error("syntax parser rejected {path}: {message}")]
    SyntaxRejected { path: String, message: String },
    #[error("flatten_modules is only defined for Rust source selections")]
    NonRustFlattenSelection,
    #[error("flatten_modules found a destination filename collision: {0}")]
    FlattenCollision(String),
    #[error("flatten_modules cannot resolve external module {module} in {file}")]
    UnresolvedRustModule { file: String, module: String },
    #[error("validator failed: {name} exited with status {status}")]
    ValidatorFailed { name: String, status: i32 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingAction {
    Write,
    Delete,
}

pub fn apply_certificate(cert: &Certificate, repo: &Path) -> Result<ApplyReport, TransformError> {
    verify(cert)?;
    let repo = repo
        .canonicalize()
        .map_err(|_| TransformError::InvalidRepo(repo.display().to_string()))?;
    if !repo.is_dir() {
        return Err(TransformError::InvalidRepo(repo.display().to_string()));
    }
    if !cert.workspaces.iter().any(|workspace| {
        workspace.boundary == "filesystem" && workspace.access == ent_core::ResourceAccess::Write
    }) {
        return Err(TransformError::MissingWritableWorkspace);
    }

    let stage = TempDir::new()?;
    copy_tree(&repo, stage.path())?;
    let mut context = TransformContext {
        cert,
        root: stage.path().to_path_buf(),
        pending: BTreeMap::new(),
        files_cache: None,
        syntax: SyntaxRegistry::default(),
    };

    for transform in &cert.transforms {
        context.apply_transform(transform)?;
    }

    let validator_reports = run_validators(&cert.validators, stage.path())?;
    let changed_files = context.materialize_report(&repo)?;
    apply_pending_changes(&repo, stage.path(), &context.pending)?;

    Ok(ApplyReport {
        world: cert.world.clone(),
        changed_files,
        validators: validator_reports,
    })
}

struct TransformContext<'a> {
    cert: &'a Certificate,
    root: PathBuf,
    pending: BTreeMap<PathBuf, PendingAction>,
    files_cache: Option<Vec<PathBuf>>,
    syntax: SyntaxRegistry,
}

impl TransformContext<'_> {
    fn apply_transform(&mut self, transform: &TransformContract) -> Result<(), TransformError> {
        match transform.operation.as_str() {
            "remove_comments" => self.remove_comments(transform),
            "flatten_modules" => self.flatten_modules(transform),
            "delete_files" => self.delete_files(transform),
            "delete_lines" => self.delete_lines(transform),
            "replace_text" => self.replace_text(transform, false),
            "replace_word" => self.replace_text(transform, true),
            other => Err(TransformError::UnsupportedTransform(other.to_owned())),
        }
    }

    fn remove_comments(&mut self, transform: &TransformContract) -> Result<(), TransformError> {
        for rel in self.files_for_transform_target(transform)? {
            let Some(parser) = self.parser_for_file(&rel)? else {
                return Err(TransformError::UnsupportedFile {
                    transform: transform.name.clone(),
                    path: display_rel(&rel),
                });
            };
            let language = parser.language.clone();
            let adapter = parser.adapter.clone();
            let path = self.root.join(&rel);
            let source = fs::read_to_string(&path)?;
            let rewritten = match (language.as_str(), adapter.as_str()) {
                ("rust", "tree-sitter") => self.syntax.remove_comments("rust", &source, &rel)?,
                ("c", "tree-sitter") => self.syntax.remove_comments("c", &source, &rel)?,
                ("cpp", "tree-sitter") => self.syntax.remove_comments("cpp", &source, &rel)?,
                ("ent", "native") => remove_ent_comments(&source, &rel)?,
                _ => {
                    return Err(TransformError::UnsupportedFile {
                        transform: transform.name.clone(),
                        path: display_rel(&rel),
                    });
                }
            };
            if rewritten != source {
                fs::write(&path, rewritten)?;
                self.mark_write(rel);
            }
        }
        Ok(())
    }

    fn delete_files(&mut self, transform: &TransformContract) -> Result<(), TransformError> {
        for rel in self.files_for_transform_target(transform)? {
            let path = self.root.join(&rel);
            if path.exists() {
                fs::remove_file(&path)?;
                self.mark_delete(rel);
            }
        }
        Ok(())
    }

    fn delete_lines(&mut self, transform: &TransformContract) -> Result<(), TransformError> {
        let rel = direct_file(transform)?;
        let predicate = transform
            .predicate
            .as_deref()
            .ok_or_else(|| TransformError::UnsupportedTransform(transform.name.clone()))?;
        let line_predicate = LinePredicate::parse(predicate)?;
        let path = self.root.join(&rel);
        let source = fs::read_to_string(&path)?;
        let mut rewritten = String::new();
        for line in source.split_inclusive('\n') {
            let comparable = line.trim_end_matches('\n').trim_end_matches('\r');
            if !line_predicate.matches(comparable) {
                rewritten.push_str(line);
            }
        }
        if !source.ends_with('\n') && rewritten.ends_with('\n') {
            rewritten.pop();
        }
        if rewritten != source {
            fs::write(&path, rewritten)?;
            self.mark_write(rel);
        }
        Ok(())
    }

    fn replace_text(
        &mut self,
        transform: &TransformContract,
        word_mode: bool,
    ) -> Result<(), TransformError> {
        let rel = direct_file(transform)?;
        let replacement = transform
            .replacement
            .as_ref()
            .ok_or_else(|| TransformError::UnsupportedTransform(transform.name.clone()))?;
        let path = self.root.join(&rel);
        let source = fs::read_to_string(&path)?;
        let rewritten = if word_mode {
            replace_word(&source, replacement)
        } else {
            source.replace(&replacement.from, &replacement.to)
        };
        if rewritten != source {
            fs::write(&path, rewritten)?;
            self.mark_write(rel);
        }
        Ok(())
    }

    fn flatten_modules(&mut self, transform: &TransformContract) -> Result<(), TransformError> {
        let selected = self.files_for_transform_target(transform)?;
        let rust_files = selected
            .iter()
            .filter(|rel| {
                self.parser_for_file(rel)
                    .is_ok_and(|parser| parser.is_some_and(|parser| parser.language == "rust"))
            })
            .cloned()
            .collect::<Vec<_>>();
        if rust_files.is_empty() || rust_files.len() != selected.len() {
            return Err(TransformError::NonRustFlattenSelection);
        }
        let destination = sanitize_relative(
            transform
                .destination
                .as_deref()
                .ok_or_else(|| TransformError::UnsupportedTransform(transform.name.clone()))?,
        )?;
        let source_root = rust_source_root(&self.root);
        let target_base = source_root.join(&destination);
        fs::create_dir_all(&target_base)?;

        let mut move_map = BTreeMap::new();
        let mut new_names = BTreeSet::new();
        let source_root_rel = source_root
            .strip_prefix(&self.root)
            .unwrap_or(Path::new(""));
        let destination_rel = source_root_rel.join(&destination);
        for rel in rust_files {
            if is_rust_entrypoint(&rel) || rel.starts_with(&destination_rel) {
                continue;
            }
            let old_abs = self.root.join(&rel);
            let module_path = rust_module_path(&source_root, &old_abs)?;
            if module_path.is_empty() {
                continue;
            }
            let file_name = format!("{}.rs", module_path.join("__"));
            if !new_names.insert(file_name.clone()) {
                return Err(TransformError::FlattenCollision(file_name));
            }
            let new_abs = target_base.join(file_name);
            let new_rel = new_abs.strip_prefix(&self.root).unwrap().to_path_buf();
            move_map.insert(rel, new_rel);
        }

        if move_map.is_empty() {
            return Ok(());
        }

        let all_rust = all_files(&self.root)?
            .into_iter()
            .filter(|rel| rel.extension().is_some_and(|ext| ext == "rs"))
            .collect::<Vec<_>>();
        let mut rewritten_sources = BTreeMap::new();
        for rel in &all_rust {
            let current_rel = move_map.get(rel).unwrap_or(rel);
            let source = fs::read_to_string(self.root.join(rel))?;
            let rewritten =
                rewrite_rust_mod_paths(&source, rel, current_rel, &move_map, &self.root)?;
            rewritten_sources.insert(current_rel.clone(), rewritten);
        }

        for (old_rel, new_rel) in &move_map {
            let old_abs = self.root.join(old_rel);
            if old_abs.exists() {
                fs::remove_file(&old_abs)?;
                self.mark_delete(old_rel.clone());
            }
            let new_abs = self.root.join(new_rel);
            if let Some(parent) = new_abs.parent() {
                fs::create_dir_all(parent)?;
            }
            let contents = rewritten_sources
                .remove(new_rel)
                .unwrap_or_else(|| fs::read_to_string(&new_abs).unwrap_or_default());
            fs::write(&new_abs, contents)?;
            self.mark_write(new_rel.clone());
        }

        for (rel, source) in rewritten_sources {
            if move_map.values().any(|new_rel| new_rel == &rel) {
                continue;
            }
            let path = self.root.join(&rel);
            if path.exists() && fs::read_to_string(&path)? != source {
                fs::write(&path, source)?;
                self.mark_write(rel);
            }
        }

        for rel in all_files(&self.root)? {
            if rel.extension().is_some_and(|ext| ext == "rs") {
                let source = fs::read_to_string(self.root.join(&rel))?;
                self.syntax.validate("rust", &source, &rel)?;
            }
        }

        Ok(())
    }

    fn files_for_transform_target(
        &mut self,
        transform: &TransformContract,
    ) -> Result<Vec<PathBuf>, TransformError> {
        match &transform.target {
            TransformTarget::Selection(selection) => self.select_files(selection),
            TransformTarget::File(path) => Ok(vec![sanitize_relative(path)?]),
        }
    }

    fn select_files(&mut self, selection_name: &str) -> Result<Vec<PathBuf>, TransformError> {
        let selection = self
            .cert
            .selections
            .iter()
            .find(|selection| selection.name == selection_name)
            .ok_or_else(|| TransformError::UnknownSelection(selection_name.to_owned()))?;
        let predicate = SelectionPredicate::parse(&selection.predicate)?;
        let files = self.current_files()?;
        let mut selected = Vec::new();
        for rel in files {
            if predicate.matches(self, &rel)? {
                selected.push(rel);
            }
        }
        Ok(selected)
    }

    fn parser_for_file(&self, rel: &Path) -> Result<Option<&ParserContract>, TransformError> {
        let matches = self
            .cert
            .parsers
            .iter()
            .filter(|parser| parser_matches_file(parser, rel))
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(TransformError::AmbiguousParser {
                path: display_rel(rel),
                parsers: matches.iter().map(|parser| parser.name.clone()).collect(),
            });
        }
        Ok(matches.into_iter().next())
    }

    fn current_files(&mut self) -> Result<Vec<PathBuf>, TransformError> {
        if self.files_cache.is_none() {
            self.files_cache = Some(all_files(&self.root)?);
        }
        Ok(self.files_cache.clone().expect("cache was populated"))
    }

    fn invalidate_files(&mut self) {
        self.files_cache = None;
    }

    fn parser_named(&self, name: &str) -> Option<&ParserContract> {
        self.cert.parsers.iter().find(|parser| parser.name == name)
    }

    fn mark_write(&mut self, rel: PathBuf) {
        if !matches!(self.pending.get(&rel), Some(PendingAction::Delete)) {
            self.pending.insert(rel, PendingAction::Write);
        }
        self.invalidate_files();
    }

    fn mark_delete(&mut self, rel: PathBuf) {
        self.pending.insert(rel, PendingAction::Delete);
        self.invalidate_files();
    }

    fn materialize_report(&self, repo: &Path) -> Result<Vec<FileChange>, TransformError> {
        let mut changes = Vec::new();
        for (rel, action) in &self.pending {
            let before = read_optional(repo.join(rel))?;
            let after = read_optional(self.root.join(rel))?;
            if before == after && !matches!(action, PendingAction::Delete) {
                continue;
            }
            changes.push(FileChange {
                path: display_rel(rel),
                action: match action {
                    PendingAction::Write => FileAction::Write,
                    PendingAction::Delete => FileAction::Delete,
                },
                before_hash: before.as_deref().map(sha256_uri),
                after_hash: after.as_deref().map(sha256_uri),
            });
        }
        Ok(changes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SelectionPredicate {
    ParsedBy(Vec<String>),
    Extension(String),
    File(PathBuf),
    MarkdownHeading(String),
}

impl SelectionPredicate {
    fn parse(input: &str) -> Result<Self, TransformError> {
        let input = input.trim();
        if let Some(body) = input
            .strip_prefix("parsed_by(")
            .and_then(|tail| tail.strip_suffix(')'))
        {
            let names = body
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            return Ok(Self::ParsedBy(names));
        }
        if let Some(body) = input
            .strip_prefix("extension(")
            .and_then(|tail| tail.strip_suffix(')'))
        {
            return Ok(Self::Extension(parse_quoted(body.trim())?));
        }
        if let Some(body) = input
            .strip_prefix("file(")
            .and_then(|tail| tail.strip_suffix(')'))
        {
            return Ok(Self::File(sanitize_relative(&parse_quoted(body.trim())?)?));
        }
        if let Some(body) = input
            .strip_prefix("markdown_heading(")
            .and_then(|tail| tail.strip_suffix(')'))
        {
            return Ok(Self::MarkdownHeading(parse_quoted(body.trim())?));
        }
        Err(TransformError::UnsupportedSelectionPredicate(
            input.to_owned(),
        ))
    }

    fn matches(&self, context: &TransformContext<'_>, rel: &Path) -> Result<bool, TransformError> {
        match self {
            Self::ParsedBy(names) => {
                for name in names {
                    let parser = context
                        .parser_named(name)
                        .ok_or_else(|| TransformError::UnknownParser(name.clone()))?;
                    if parser_matches_file(parser, rel) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::Extension(extension) => Ok(extension_matches(rel, extension)),
            Self::File(path) => Ok(rel == path),
            Self::MarkdownHeading(heading) => {
                if !extension_matches(rel, ".md") && !extension_matches(rel, ".markdown") {
                    return Ok(false);
                }
                let source = fs::read_to_string(context.root.join(rel))?;
                Ok(markdown_has_heading(&source, heading))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LinePredicate {
    ContainsWord(String),
    ContainsText(String),
}

impl LinePredicate {
    fn parse(input: &str) -> Result<Self, TransformError> {
        let input = input.trim();
        if let Some(body) = input
            .strip_prefix("contains_word(")
            .and_then(|tail| tail.strip_suffix(')'))
        {
            return Ok(Self::ContainsWord(parse_quoted(body.trim())?));
        }
        if let Some(body) = input
            .strip_prefix("contains_text(")
            .and_then(|tail| tail.strip_suffix(')'))
        {
            return Ok(Self::ContainsText(parse_quoted(body.trim())?));
        }
        Err(TransformError::UnsupportedSelectionPredicate(
            input.to_owned(),
        ))
    }

    fn matches(&self, line: &str) -> bool {
        match self {
            Self::ContainsWord(word) => contains_word(line, word),
            Self::ContainsText(text) => line.contains(text),
        }
    }
}

fn direct_file(transform: &TransformContract) -> Result<PathBuf, TransformError> {
    match &transform.target {
        TransformTarget::File(path) => sanitize_relative(path),
        TransformTarget::Selection(_) => {
            Err(TransformError::UnsupportedTransform(transform.name.clone()))
        }
    }
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), TransformError> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let dest = to.join(name);
        if path.is_dir() {
            copy_tree(&path, &dest)?;
        } else {
            fs::copy(&path, &dest)?;
        }
    }
    Ok(())
}

fn all_files(root: &Path) -> Result<Vec<PathBuf>, TransformError> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), TransformError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_name() == ".git" {
            continue;
        }
        if path.is_dir() {
            collect_files(root, &path, files)?;
        } else {
            files.push(path.strip_prefix(root).unwrap().to_path_buf());
        }
    }
    Ok(())
}

fn apply_pending_changes(
    repo: &Path,
    stage: &Path,
    pending: &BTreeMap<PathBuf, PendingAction>,
) -> Result<(), TransformError> {
    for (rel, action) in pending {
        let target = repo.join(rel);
        match action {
            PendingAction::Delete => {
                if target.exists() {
                    fs::remove_file(target)?;
                }
            }
            PendingAction::Write => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(stage.join(rel), target)?;
            }
        }
    }
    Ok(())
}

fn run_validators(
    validators: &[ValidatorContract],
    root: &Path,
) -> Result<Vec<ValidatorReport>, TransformError> {
    let mut reports = Vec::new();
    for validator in validators {
        let output = Command::new(&validator.argv[0])
            .args(&validator.argv[1..])
            .current_dir(root)
            .output()?;
        let status = output.status.code().unwrap_or(-1);
        let report = ValidatorReport {
            name: validator.name.clone(),
            argv: validator.argv.clone(),
            status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        if !output.status.success() {
            return Err(TransformError::ValidatorFailed {
                name: validator.name.clone(),
                status,
            });
        }
        reports.push(report);
    }
    Ok(reports)
}

#[derive(Default)]
struct SyntaxRegistry {
    rust: Option<TreeSitterAdapter>,
    c: Option<TreeSitterAdapter>,
    cpp: Option<TreeSitterAdapter>,
}

impl SyntaxRegistry {
    fn remove_comments(
        &mut self,
        language: &'static str,
        source: &str,
        rel: &Path,
    ) -> Result<String, TransformError> {
        let adapter = self.adapter(language, rel)?;
        let rewritten = adapter.remove_comments(source, rel)?;
        adapter.validate(&rewritten, rel)?;
        Ok(rewritten)
    }

    fn validate(
        &mut self,
        language: &'static str,
        source: &str,
        rel: &Path,
    ) -> Result<(), TransformError> {
        self.adapter(language, rel)?.validate(source, rel)
    }

    fn adapter(
        &mut self,
        language: &'static str,
        rel: &Path,
    ) -> Result<&mut TreeSitterAdapter, TransformError> {
        match language {
            "rust" => {
                if self.rust.is_none() {
                    self.rust = Some(TreeSitterAdapter::new(
                        "rust",
                        tree_sitter_rust::LANGUAGE.into(),
                        "(line_comment) @comment\n(block_comment) @comment",
                        rel,
                    )?);
                }
                Ok(self.rust.as_mut().expect("rust adapter initialized"))
            }
            "c" => {
                if self.c.is_none() {
                    self.c = Some(TreeSitterAdapter::new(
                        "c",
                        tree_sitter_c::LANGUAGE.into(),
                        "(comment) @comment",
                        rel,
                    )?);
                }
                Ok(self.c.as_mut().expect("c adapter initialized"))
            }
            "cpp" => {
                if self.cpp.is_none() {
                    self.cpp = Some(TreeSitterAdapter::new(
                        "cpp",
                        tree_sitter_cpp::LANGUAGE.into(),
                        "(comment) @comment",
                        rel,
                    )?);
                }
                Ok(self.cpp.as_mut().expect("cpp adapter initialized"))
            }
            other => Err(TransformError::UnsupportedTransform(other.to_owned())),
        }
    }
}

struct TreeSitterAdapter {
    language_name: &'static str,
    parser: Parser,
    comment_query: Query,
}

impl TreeSitterAdapter {
    fn new(
        language_name: &'static str,
        language: Language,
        comment_query: &str,
        rel: &Path,
    ) -> Result<Self, TransformError> {
        let mut parser = Parser::new();
        parser
            .set_language(&language)
            .map_err(|error| TransformError::SyntaxRejected {
                path: display_rel(rel),
                message: error.to_string(),
            })?;
        let comment_query = Query::new(&language, comment_query).map_err(|error| {
            TransformError::SyntaxRejected {
                path: display_rel(rel),
                message: error.to_string(),
            }
        })?;
        Ok(Self {
            language_name,
            parser,
            comment_query,
        })
    }

    fn remove_comments(&mut self, source: &str, rel: &Path) -> Result<String, TransformError> {
        let tree = self.parse(source, rel, "source contains parse errors")?;
        let mut cursor = QueryCursor::new();
        let mut ranges = Vec::new();
        let mut matches = cursor.matches(&self.comment_query, tree.root_node(), source.as_bytes());
        while let Some(query_match) = matches.next() {
            ranges.extend(
                query_match
                    .captures
                    .iter()
                    .map(|capture| (capture.node.start_byte(), capture.node.end_byte())),
            );
        }
        ranges.sort();
        Ok(replace_ranges_with_space(source, &ranges))
    }

    fn validate(&mut self, source: &str, rel: &Path) -> Result<(), TransformError> {
        self.parse(source, rel, "rewritten source contains parse errors")?;
        Ok(())
    }

    fn parse(
        &mut self,
        source: &str,
        rel: &Path,
        error_message: &str,
    ) -> Result<tree_sitter::Tree, TransformError> {
        let tree =
            self.parser
                .parse(source, None)
                .ok_or_else(|| TransformError::SyntaxRejected {
                    path: display_rel(rel),
                    message: format!("{} parser produced no syntax tree", self.language_name),
                })?;
        if tree.root_node().has_error() {
            return Err(TransformError::SyntaxRejected {
                path: display_rel(rel),
                message: format!("{}: {error_message}", self.language_name),
            });
        }
        Ok(tree)
    }
}

fn remove_ent_comments(source: &str, rel: &Path) -> Result<String, TransformError> {
    ent_parser::parse_world_diagnostic(source).map_err(|error| TransformError::SyntaxRejected {
        path: display_rel(rel),
        message: error.to_string(),
    })?;
    let rewritten = remove_line_comments_outside_strings(source);
    ent_parser::parse_world_diagnostic(&rewritten).map_err(|error| {
        TransformError::SyntaxRejected {
            path: display_rel(rel),
            message: error.to_string(),
        }
    })?;
    Ok(rewritten)
}

fn replace_ranges_with_space(source: &str, ranges: &[(usize, usize)]) -> String {
    let mut bytes = source.as_bytes().to_vec();
    for (start, end) in ranges {
        for byte in &mut bytes[*start..*end] {
            if *byte != b'\n' && *byte != b'\r' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("replacement preserves UTF-8 because only ASCII spaces change")
}

fn remove_line_comments_outside_strings(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        let mut in_string = false;
        let mut escaped = false;
        let mut comment_at = None;
        let bytes = line.as_bytes();
        let mut idx = 0;
        while idx + 1 < bytes.len() {
            let ch = bytes[idx] as char;
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
            } else if ch == '"' {
                in_string = true;
            } else if bytes[idx] == b'/' && bytes[idx + 1] == b'/' {
                comment_at = Some(idx);
                break;
            }
            idx += 1;
        }
        if let Some(start) = comment_at {
            output.push_str(&line[..start]);
            let comment = &line[start..];
            for ch in comment.chars() {
                if ch == '\n' || ch == '\r' {
                    output.push(ch);
                } else {
                    output.push(' ');
                }
            }
        } else {
            output.push_str(line);
        }
    }
    output
}

fn rewrite_rust_mod_paths(
    source: &str,
    original_rel: &Path,
    current_rel: &Path,
    move_map: &BTreeMap<PathBuf, PathBuf>,
    root: &Path,
) -> Result<String, TransformError> {
    let language = tree_sitter_rust::LANGUAGE.into();
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| TransformError::SyntaxRejected {
            path: display_rel(original_rel),
            message: error.to_string(),
        })?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| TransformError::SyntaxRejected {
            path: display_rel(original_rel),
            message: "parser produced no syntax tree".to_owned(),
        })?;
    let mut replacements = Vec::new();
    collect_mod_replacements(
        tree.root_node(),
        source,
        original_rel,
        current_rel,
        move_map,
        root,
        &mut replacements,
    )?;
    replacements.sort_by(|left, right| right.0.cmp(&left.0));
    let mut rewritten = source.to_owned();
    for (start, end, replacement) in replacements {
        rewritten.replace_range(start..end, &replacement);
    }
    Ok(rewritten)
}

fn collect_mod_replacements(
    node: Node<'_>,
    source: &str,
    original_rel: &Path,
    current_rel: &Path,
    move_map: &BTreeMap<PathBuf, PathBuf>,
    root: &Path,
    replacements: &mut Vec<(usize, usize, String)>,
) -> Result<(), TransformError> {
    if node.kind() == "mod_item" && node.child_by_field_name("body").is_none() {
        let text = &source[node.start_byte()..node.end_byte()];
        if text.trim_end().ends_with(';') {
            if let Some(name_node) = node.child_by_field_name("name") {
                let module_name = &source[name_node.start_byte()..name_node.end_byte()];
                if let Some(old_child_rel) =
                    resolve_rust_module_file(root, original_rel, module_name)
                {
                    if let Some(new_child_rel) = move_map.get(&old_child_rel) {
                        let current_parent = current_rel.parent().unwrap_or(Path::new(""));
                        let path_attr = relative_between(current_parent, new_child_rel);
                        let indent = leading_indent(source, node.start_byte());
                        let prefix = text
                            .split_once("mod")
                            .map(|(prefix, _)| prefix.trim())
                            .filter(|prefix| !prefix.is_empty())
                            .map(|prefix| format!("{prefix} "))
                            .unwrap_or_default();
                        replacements.push((
                            node.start_byte(),
                            node.end_byte(),
                            format!(
                                "#[path = \"{}\"]\n{}{}mod {};",
                                path_attr.to_string_lossy().replace('\\', "/"),
                                indent,
                                prefix,
                                module_name
                            ),
                        ));
                    }
                } else {
                    return Err(TransformError::UnresolvedRustModule {
                        file: display_rel(original_rel),
                        module: module_name.to_owned(),
                    });
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_mod_replacements(
            child,
            source,
            original_rel,
            current_rel,
            move_map,
            root,
            replacements,
        )?;
    }
    Ok(())
}

fn resolve_rust_module_file(root: &Path, parent_rel: &Path, module_name: &str) -> Option<PathBuf> {
    let parent_abs = root.join(parent_rel);
    let parent_dir = parent_abs.parent()?;
    let parent_stem = parent_abs.file_stem()?.to_string_lossy();
    let search_dir = if parent_stem == "mod" || is_rust_entrypoint(parent_rel) {
        parent_dir.to_path_buf()
    } else {
        parent_dir.join(parent_stem.as_ref())
    };
    let candidates = [
        search_dir.join(format!("{module_name}.rs")),
        search_dir.join(module_name).join("mod.rs"),
    ];
    candidates
        .into_iter()
        .find(|candidate| candidate.exists())
        .and_then(|candidate| candidate.strip_prefix(root).ok().map(Path::to_path_buf))
}

fn rust_source_root(root: &Path) -> PathBuf {
    let src = root.join("src");
    if src.is_dir() {
        src
    } else {
        root.to_path_buf()
    }
}

fn rust_module_path(source_root: &Path, file: &Path) -> Result<Vec<String>, TransformError> {
    let rel = file
        .strip_prefix(source_root)
        .map_err(|_| TransformError::InvalidRelativePath(file.display().to_string()))?;
    let mut parts = rel
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if let Some(last) = parts.last_mut() {
        if last == "mod.rs" {
            parts.pop();
        } else if let Some(stem) = last.strip_suffix(".rs") {
            *last = stem.to_owned();
        }
    }
    Ok(parts)
}

fn is_rust_entrypoint(rel: &Path) -> bool {
    rel.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "lib.rs" || name == "main.rs")
}

fn leading_indent(source: &str, start: usize) -> String {
    let line_start = source[..start].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
    source[line_start..start]
        .chars()
        .take_while(|ch| ch.is_whitespace())
        .collect()
}

fn relative_between(from_dir: &Path, to: &Path) -> PathBuf {
    let from_parts = normal_components(from_dir);
    let to_parts = normal_components(to);
    let common = from_parts
        .iter()
        .zip(to_parts.iter())
        .take_while(|(left, right)| left == right)
        .count();
    let mut rel = PathBuf::new();
    for _ in common..from_parts.len() {
        rel.push("..");
    }
    for part in &to_parts[common..] {
        rel.push(part);
    }
    rel
}

fn normal_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect()
}

fn parser_matches_file(parser: &ParserContract, rel: &Path) -> bool {
    let extension = rel.extension().and_then(|ext| ext.to_str());
    match (parser.language.as_str(), parser.adapter.as_str()) {
        ("rust", "tree-sitter") => extension.is_some_and(|ext| ext == "rs"),
        ("c", "tree-sitter") => extension.is_some_and(|ext| matches!(ext, "c" | "h")),
        ("cpp", "tree-sitter") => extension
            .is_some_and(|ext| matches!(ext, "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx")),
        ("ent", "native") => extension.is_some_and(|ext| ext == "ent"),
        ("markdown", "pulldown_cmark") => {
            extension.is_some_and(|ext| ext == "md" || ext == "markdown")
        }
        _ => false,
    }
}

fn extension_matches(rel: &Path, extension: &str) -> bool {
    let extension = extension.trim_start_matches('.');
    rel.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == extension)
}

fn markdown_has_heading(source: &str, expected: &str) -> bool {
    let mut in_heading = false;
    let mut heading = String::new();
    for event in MarkdownParser::new(source) {
        match event {
            Event::Start(Tag::Heading { .. }) => {
                in_heading = true;
                heading.clear();
            }
            Event::Text(text) | Event::Code(text) if in_heading => heading.push_str(&text),
            Event::End(TagEnd::Heading(_)) if in_heading => {
                if heading.trim() == expected {
                    return true;
                }
                in_heading = false;
            }
            _ => {}
        }
    }
    false
}

fn replace_word(source: &str, replacement: &TextReplacement) -> String {
    let mut output = String::with_capacity(source.len());
    let mut idx = 0;
    while let Some(found) = source[idx..].find(&replacement.from) {
        let start = idx + found;
        let end = start + replacement.from.len();
        output.push_str(&source[idx..start]);
        if is_word_boundary(source, start) && is_word_boundary(source, end) {
            output.push_str(&replacement.to);
        } else {
            output.push_str(&source[start..end]);
        }
        idx = end;
    }
    output.push_str(&source[idx..]);
    output
}

fn contains_word(source: &str, word: &str) -> bool {
    let mut idx = 0;
    while let Some(found) = source[idx..].find(word) {
        let start = idx + found;
        let end = start + word.len();
        if is_word_boundary(source, start) && is_word_boundary(source, end) {
            return true;
        }
        idx = end;
    }
    false
}

fn is_word_boundary(source: &str, idx: usize) -> bool {
    if idx == 0 || idx == source.len() {
        return true;
    }
    source[..idx]
        .chars()
        .next_back()
        .zip(source[idx..].chars().next())
        .is_some_and(|(left, right)| !is_word_char(left) || !is_word_char(right))
}

fn is_word_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn sanitize_relative(input: &str) -> Result<PathBuf, TransformError> {
    let path = Path::new(input);
    if path.is_absolute() {
        return Err(TransformError::InvalidRelativePath(input.to_owned()));
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            _ => return Err(TransformError::InvalidRelativePath(input.to_owned())),
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(TransformError::InvalidRelativePath(input.to_owned()));
    }
    Ok(clean)
}

fn parse_quoted(input: &str) -> Result<String, TransformError> {
    let body = input
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| TransformError::UnsupportedSelectionPredicate(input.to_owned()))?;
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

fn read_optional(path: impl AsRef<Path>) -> Result<Option<Vec<u8>>, TransformError> {
    let path = path.as_ref();
    if path.exists() {
        Ok(Some(fs::read(path)?))
    } else {
        Ok(None)
    }
}

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn display_rel(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
