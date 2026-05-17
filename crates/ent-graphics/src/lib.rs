use anyhow::{Context, Result};
use ent_elab::elaborate_source;
use ent_kernel::verify;
use ent_parser::parse_world_diagnostic;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenderMode {
    Interpret,
    Ir,
    Native,
}

impl RenderMode {
    pub fn label(self) -> &'static str {
        match self {
            RenderMode::Interpret => "interpret",
            RenderMode::Ir => "ir",
            RenderMode::Native => "native",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RenderOptions {
    pub mode: RenderMode,
    pub width: u32,
    pub height: u32,
    pub output: Option<PathBuf>,
    pub source_path: Option<PathBuf>,
    pub library_roots: Vec<PathBuf>,
    pub smoke_test: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RenderReport {
    pub world: String,
    pub graphics: String,
    pub entry: String,
    pub mode: RenderMode,
    pub width: u32,
    pub height: u32,
    pub triangles_submitted: usize,
    pub triangles_rasterized: usize,
    pub pixels_touched: usize,
    pub source_digest: String,
    pub elapsed_ms: f64,
    pub output: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BenchReport {
    pub files: Vec<BenchFileReport>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BenchFileReport {
    pub source: String,
    pub modes: Vec<BenchModeReport>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BenchModeReport {
    pub mode: RenderMode,
    pub warmup: u32,
    pub iterations: u32,
    pub mean_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub triangles_rasterized: usize,
    pub pixels_touched: usize,
}

#[derive(Debug, Error)]
pub enum GraphicsError {
    #[error("graphics source does not declare a graphics block")]
    MissingGraphics,
    #[error("graphics function is undeclared: {0}")]
    MissingFunction(String),
    #[error("graphics variable is undeclared: {0}")]
    MissingVariable(String),
    #[error("graphics expression is malformed: {0}")]
    MalformedExpression(String),
    #[error("graphics statement is malformed: {0}")]
    MalformedStatement(String),
    #[error("graphics import cannot be resolved: {0}")]
    ImportNotFound(String),
    #[error("graphics builtin received invalid arguments: {0}")]
    BadBuiltin(String),
}

pub fn render_file(path: &Path, mut options: RenderOptions) -> Result<RenderReport> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read graphics source {}", path.display()))?;
    options.source_path = Some(path.to_path_buf());
    render_source(&source, options)
}

pub fn render_source(source: &str, options: RenderOptions) -> Result<RenderReport> {
    let cert = elaborate_source(source).context("graphics source failed to elaborate")?;
    let kernel_report = verify(&cert).context("graphics certificate rejected by kernel")?;
    let ast = parse_world_diagnostic(source).context("failed to parse graphics source")?;
    let graphics = ast.graphics.first().ok_or(GraphicsError::MissingGraphics)?;
    let entry = if graphics.entry.is_empty() {
        "main"
    } else {
        graphics.entry.as_str()
    };

    let mut loader = SourceLoader::new(options.source_path.as_deref(), &options.library_roots);
    let program_source = loader.load_program_source(graphics)?;
    let program = Program::parse(&program_source)?;
    let mut runtime = Runtime::new(options.mode, options.width, options.height);
    let started = Instant::now();
    runtime.call_function(&program, entry, vec![])?;
    runtime.flush_batches();
    if options.smoke_test && runtime.frame.empty() {
        anyhow::bail!("graphics smoke test rendered an empty frame");
    }
    if let Some(output) = &options.output {
        runtime
            .frame
            .write(output)
            .with_context(|| format!("failed to write render output {}", output.display()))?;
    }
    let stats = runtime.stats;
    Ok(RenderReport {
        world: kernel_report.world,
        graphics: graphics.name.clone(),
        entry: entry.to_owned(),
        mode: options.mode,
        width: options.width,
        height: options.height,
        triangles_submitted: stats.triangles_submitted,
        triangles_rasterized: stats.triangles_rasterized,
        pixels_touched: stats.pixels_touched,
        source_digest: sha256_uri(graphics.body.as_bytes()),
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        output: options
            .output
            .as_ref()
            .map(|path| path.display().to_string()),
    })
}

pub fn bench_path(
    path: &Path,
    modes: &[RenderMode],
    warmup: u32,
    iterations: u32,
    width: u32,
    height: u32,
) -> Result<BenchReport> {
    let mut files = Vec::new();
    collect_ent_files(path, &mut files)?;
    files.sort();
    let mut reports = Vec::new();
    for file in files {
        let source = fs::read_to_string(&file)?;
        let mut mode_reports = Vec::new();
        for &mode in modes {
            for _ in 0..warmup {
                let options = RenderOptions {
                    mode,
                    width,
                    height,
                    output: None,
                    source_path: Some(file.clone()),
                    library_roots: vec![],
                    smoke_test: true,
                };
                render_source(&source, options)?;
            }
            let mut times = Vec::new();
            let mut last = None;
            for _ in 0..iterations {
                let options = RenderOptions {
                    mode,
                    width,
                    height,
                    output: None,
                    source_path: Some(file.clone()),
                    library_roots: vec![],
                    smoke_test: true,
                };
                let report = render_source(&source, options)?;
                times.push(report.elapsed_ms);
                last = Some(report);
            }
            let mean = times.iter().sum::<f64>() / times.len().max(1) as f64;
            let min = times.iter().copied().fold(f64::INFINITY, f64::min);
            let max = times.iter().copied().fold(0.0, f64::max);
            let last = last.context("benchmark did not run any iterations")?;
            mode_reports.push(BenchModeReport {
                mode,
                warmup,
                iterations,
                mean_ms: mean,
                min_ms: min,
                max_ms: max,
                triangles_rasterized: last.triangles_rasterized,
                pixels_touched: last.pixels_touched,
            });
        }
        reports.push(BenchFileReport {
            source: file.display().to_string(),
            modes: mode_reports,
        });
    }
    Ok(BenchReport { files: reports })
}

fn collect_ent_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if path.extension().is_some_and(|ext| ext == "ent") {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_ent_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "ent") {
            out.push(path);
        }
    }
    Ok(())
}

struct SourceLoader {
    roots: Vec<PathBuf>,
    loaded: BTreeSet<String>,
}

impl SourceLoader {
    fn new(source_path: Option<&Path>, explicit_roots: &[PathBuf]) -> Self {
        let mut roots = explicit_roots.to_vec();
        if let Some(path) = source_path.and_then(Path::parent) {
            roots.push(path.to_path_buf());
        }
        if let Ok(cwd) = std::env::current_dir() {
            roots.push(cwd);
        }
        Self {
            roots,
            loaded: BTreeSet::new(),
        }
    }

    fn load_program_source(&mut self, graphics: &ent_parser::GraphicsDecl) -> Result<String> {
        let mut output = String::new();
        for import in &graphics.imports {
            self.load_import(import, &mut output)?;
        }
        output.push('\n');
        output.push_str(&graphics.body);
        Ok(output)
    }

    fn load_import(&mut self, import: &str, output: &mut String) -> Result<()> {
        if !self.loaded.insert(import.to_owned()) {
            return Ok(());
        }
        let rel = import.replace('.', "/") + ".ent";
        for root in &self.roots {
            let direct = root.join(&rel);
            let entlib = root.join("entlib").join(&rel);
            let candidate = if direct.exists() {
                Some(direct)
            } else if entlib.exists() {
                Some(entlib)
            } else {
                None
            };
            if let Some(path) = candidate {
                let source = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read import {}", path.display()))?;
                for nested in import_lines(&source) {
                    self.load_import(&nested, output)?;
                }
                output.push_str(&source);
                output.push('\n');
                return Ok(());
            }
        }
        Err(GraphicsError::ImportNotFound(import.to_owned()).into())
    }
}

fn import_lines(source: &str) -> Vec<String> {
    source
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("import "))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

#[derive(Clone, Debug)]
struct Program {
    functions: BTreeMap<String, Function>,
}

impl Program {
    fn parse(source: &str) -> Result<Self> {
        let source = strip_comments(source);
        let mut functions = BTreeMap::new();
        let mut offset = 0usize;
        while let Some(relative) = source[offset..].find("fn ") {
            let start = offset + relative;
            let header_end = source[start..]
                .find('{')
                .map(|idx| start + idx)
                .ok_or_else(|| GraphicsError::MalformedStatement("function lacks body".into()))?;
            let close = find_matching(&source, header_end).ok_or_else(|| {
                GraphicsError::MalformedStatement("function body is not closed".into())
            })?;
            let header = source[start + 3..header_end].trim();
            let body = source[header_end + 1..close].to_owned();
            let function = Function::parse(header, &body)?;
            functions.insert(function.name.clone(), function);
            offset = close + 1;
        }
        Ok(Self { functions })
    }
}

#[derive(Clone, Debug)]
struct Function {
    name: String,
    params: Vec<String>,
    body: Vec<Stmt>,
}

impl Function {
    fn parse(header: &str, body: &str) -> Result<Self> {
        let open = header
            .find('(')
            .ok_or_else(|| GraphicsError::MalformedStatement(header.to_owned()))?;
        let close = header
            .find(')')
            .ok_or_else(|| GraphicsError::MalformedStatement(header.to_owned()))?;
        let name = header[..open].trim().to_owned();
        let params = header[open + 1..close]
            .split(',')
            .filter_map(|part| part.trim().split_once(':').map(|(name, _)| name.trim()))
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect();
        Ok(Self {
            name,
            params,
            body: parse_statements(body)?,
        })
    }
}

#[derive(Clone, Debug)]
enum Stmt {
    Let(String, Expr),
    Assign(String, Expr),
    Expr(Expr),
    Return(Expr),
    For {
        var: String,
        start: Expr,
        end: Expr,
        body: Vec<Stmt>,
    },
    If {
        condition: Expr,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
}

fn parse_statements(source: &str) -> Result<Vec<Stmt>> {
    let lines = normalized_lines(source);
    let mut index = 0usize;
    parse_stmt_lines(&lines, &mut index)
}

fn parse_stmt_lines(lines: &[String], index: &mut usize) -> Result<Vec<Stmt>> {
    let mut stmts = Vec::new();
    while *index < lines.len() {
        let line = lines[*index].trim();
        if line == "}" || line == "else {" {
            break;
        }
        if let Some(rest) = line.strip_prefix("for ") {
            let header = rest
                .strip_suffix('{')
                .ok_or_else(|| GraphicsError::MalformedStatement(line.to_owned()))?
                .trim();
            let (var, range) = header
                .split_once(" in range(")
                .ok_or_else(|| GraphicsError::MalformedStatement(line.to_owned()))?;
            let range = range
                .strip_suffix(')')
                .ok_or_else(|| GraphicsError::MalformedStatement(line.to_owned()))?;
            let (start, end) = split_once_top(range, ',')
                .ok_or_else(|| GraphicsError::MalformedStatement(line.to_owned()))?;
            *index += 1;
            let body = parse_stmt_lines(lines, index)?;
            expect_close(lines, index)?;
            stmts.push(Stmt::For {
                var: var.trim().to_owned(),
                start: parse_expr(start.trim())?,
                end: parse_expr(end.trim())?,
                body,
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("if ") {
            let condition = rest
                .strip_suffix('{')
                .ok_or_else(|| GraphicsError::MalformedStatement(line.to_owned()))?
                .trim();
            *index += 1;
            let then_body = parse_stmt_lines(lines, index)?;
            expect_close(lines, index)?;
            let else_body = if *index < lines.len() && lines[*index].trim() == "else {" {
                *index += 1;
                let body = parse_stmt_lines(lines, index)?;
                expect_close(lines, index)?;
                body
            } else {
                vec![]
            };
            stmts.push(Stmt::If {
                condition: parse_expr(condition)?,
                then_body,
                else_body,
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("let ") {
            let (name, expr) = rest
                .split_once(" = ")
                .ok_or_else(|| GraphicsError::MalformedStatement(line.to_owned()))?;
            let name = name.split_once(':').map_or(name, |(name, _)| name).trim();
            stmts.push(Stmt::Let(name.to_owned(), parse_expr(expr.trim())?));
        } else if let Some(rest) = line.strip_prefix("return ") {
            stmts.push(Stmt::Return(parse_expr(rest.trim())?));
        } else if let Some((name, expr)) = assignment(line) {
            stmts.push(Stmt::Assign(
                name.trim().to_owned(),
                parse_expr(expr.trim())?,
            ));
        } else {
            stmts.push(Stmt::Expr(parse_expr(line)?));
        }
        *index += 1;
    }
    Ok(stmts)
}

fn expect_close(lines: &[String], index: &mut usize) -> Result<()> {
    if *index >= lines.len() || lines[*index].trim() != "}" {
        return Err(GraphicsError::MalformedStatement("block is not closed".into()).into());
    }
    *index += 1;
    Ok(())
}

fn normalized_lines(source: &str) -> Vec<String> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("module ") && !line.starts_with("import "))
        .map(str::to_owned)
        .collect()
}

fn assignment(line: &str) -> Option<(&str, &str)> {
    let (left, right) = split_once_top(line, '=')?;
    if left.ends_with('!') || line.contains("==") || line.contains(">=") || line.contains("<=") {
        return None;
    }
    if left
        .trim()
        .chars()
        .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        Some((left, right))
    } else {
        None
    }
}

#[derive(Clone, Debug)]
enum Expr {
    Number(f64),
    Bool(bool),
    Var(String),
    Unary {
        op: String,
        rhs: Box<Expr>,
    },
    Binary {
        lhs: Box<Expr>,
        op: String,
        rhs: Box<Expr>,
    },
    Call {
        name: String,
        args: Vec<Expr>,
    },
    Text(String),
}

fn parse_expr(source: &str) -> Result<Expr> {
    let tokens = tokenize(source)?;
    let mut parser = ExprParser { tokens, index: 0 };
    let expr = parser.parse_or()?;
    if parser.index != parser.tokens.len() {
        return Err(GraphicsError::MalformedExpression(source.to_owned()).into());
    }
    Ok(expr)
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Number(f64),
    Text(String),
    Ident(String),
    Op(String),
    LParen,
    RParen,
    Comma,
}

fn tokenize(source: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.peek().copied() {
        if ch.is_whitespace() {
            chars.next();
        } else if ch.is_ascii_digit() || ch == '.' {
            let mut text = String::new();
            while let Some(ch) = chars.peek().copied() {
                if ch.is_ascii_digit() || ch == '.' {
                    text.push(ch);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(Token::Number(text.parse::<f64>().map_err(|_| {
                GraphicsError::MalformedExpression(source.to_owned())
            })?));
        } else if ch == '"' {
            chars.next();
            let mut text = String::new();
            for ch in chars.by_ref() {
                if ch == '"' {
                    break;
                }
                text.push(ch);
            }
            tokens.push(Token::Text(text));
        } else if ch == '_' || ch.is_ascii_alphabetic() {
            let mut ident = String::new();
            while let Some(ch) = chars.peek().copied() {
                if ch == '_' || ch.is_ascii_alphanumeric() {
                    ident.push(ch);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(Token::Ident(ident));
        } else {
            let two = {
                let mut it = chars.clone();
                let a = it.next().unwrap_or_default();
                let b = it.next().unwrap_or_default();
                format!("{a}{b}")
            };
            if matches!(two.as_str(), "==" | "!=" | ">=" | "<=" | "&&" | "||") {
                tokens.push(Token::Op(two));
                chars.next();
                chars.next();
            } else {
                match ch {
                    '(' => tokens.push(Token::LParen),
                    ')' => tokens.push(Token::RParen),
                    ',' => tokens.push(Token::Comma),
                    '+' | '-' | '*' | '/' | '<' | '>' | '!' => {
                        tokens.push(Token::Op(ch.to_string()))
                    }
                    _ => return Err(GraphicsError::MalformedExpression(source.to_owned()).into()),
                }
                chars.next();
            }
        }
    }
    Ok(tokens)
}

struct ExprParser {
    tokens: Vec<Token>,
    index: usize,
}

impl ExprParser {
    fn parse_or(&mut self) -> Result<Expr> {
        self.parse_binary(Self::parse_and, &["||"])
    }

    fn parse_and(&mut self) -> Result<Expr> {
        self.parse_binary(Self::parse_cmp, &["&&"])
    }

    fn parse_cmp(&mut self) -> Result<Expr> {
        self.parse_binary(Self::parse_add, &["==", "!=", ">", ">=", "<", "<="])
    }

    fn parse_add(&mut self) -> Result<Expr> {
        self.parse_binary(Self::parse_mul, &["+", "-"])
    }

    fn parse_mul(&mut self) -> Result<Expr> {
        self.parse_binary(Self::parse_unary, &["*", "/"])
    }

    fn parse_binary(&mut self, next: fn(&mut Self) -> Result<Expr>, ops: &[&str]) -> Result<Expr> {
        let mut lhs = next(self)?;
        while let Some(Token::Op(op)) = self.tokens.get(self.index) {
            if !ops.contains(&op.as_str()) {
                break;
            }
            let op = op.clone();
            self.index += 1;
            let rhs = next(self)?;
            lhs = Expr::Binary {
                lhs: Box::new(lhs),
                op,
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        if let Some(Token::Op(op)) = self.tokens.get(self.index) {
            if op == "-" || op == "!" {
                let op = op.clone();
                self.index += 1;
                return Ok(Expr::Unary {
                    op,
                    rhs: Box::new(self.parse_unary()?),
                });
            }
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        let Some(token) = self.tokens.get(self.index).cloned() else {
            return Err(GraphicsError::MalformedExpression("unexpected end".into()).into());
        };
        self.index += 1;
        match token {
            Token::Number(value) => Ok(Expr::Number(value)),
            Token::Text(value) => Ok(Expr::Text(value)),
            Token::Ident(name) if name == "true" => Ok(Expr::Bool(true)),
            Token::Ident(name) if name == "false" => Ok(Expr::Bool(false)),
            Token::Ident(name) => {
                if self.tokens.get(self.index) == Some(&Token::LParen) {
                    self.index += 1;
                    let mut args = Vec::new();
                    if self.tokens.get(self.index) != Some(&Token::RParen) {
                        loop {
                            args.push(self.parse_or()?);
                            if self.tokens.get(self.index) == Some(&Token::Comma) {
                                self.index += 1;
                                continue;
                            }
                            break;
                        }
                    }
                    if self.tokens.get(self.index) != Some(&Token::RParen) {
                        return Err(GraphicsError::MalformedExpression(name).into());
                    }
                    self.index += 1;
                    Ok(Expr::Call { name, args })
                } else {
                    Ok(Expr::Var(name))
                }
            }
            Token::LParen => {
                let expr = self.parse_or()?;
                if self.tokens.get(self.index) != Some(&Token::RParen) {
                    return Err(GraphicsError::MalformedExpression("missing ')'".into()).into());
                }
                self.index += 1;
                Ok(expr)
            }
            _ => Err(GraphicsError::MalformedExpression("unexpected token".into()).into()),
        }
    }
}

#[derive(Clone, Debug)]
enum Value {
    Number(f64),
    Bool(bool),
    Text(String),
    Unit,
}

impl Value {
    fn number(&self) -> Result<f64> {
        match self {
            Value::Number(value) => Ok(*value),
            Value::Bool(value) => Ok(if *value { 1.0 } else { 0.0 }),
            Value::Text(_) => Err(GraphicsError::BadBuiltin("expected number".into()).into()),
            Value::Unit => Err(GraphicsError::BadBuiltin("expected number".into()).into()),
        }
    }

    fn truthy(&self) -> bool {
        match self {
            Value::Number(value) => *value != 0.0,
            Value::Bool(value) => *value,
            Value::Text(value) => !value.is_empty(),
            Value::Unit => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RenderStats {
    triangles_submitted: usize,
    triangles_rasterized: usize,
    pixels_touched: usize,
}

struct Runtime {
    mode: RenderMode,
    frame: FrameBuffer,
    scopes: Vec<BTreeMap<String, Value>>,
    batches: Vec<Triangle>,
    stats: RenderStats,
}

impl Runtime {
    fn new(mode: RenderMode, width: u32, height: u32) -> Self {
        let mut frame = FrameBuffer::default();
        frame.resize(width, height);
        let mut globals = BTreeMap::new();
        globals.insert("PI".into(), Value::Number(std::f64::consts::PI));
        globals.insert("TAU".into(), Value::Number(std::f64::consts::TAU));
        globals.insert("FRAME_WIDTH".into(), Value::Number(width as f64));
        globals.insert("FRAME_HEIGHT".into(), Value::Number(height as f64));
        Self {
            mode,
            frame,
            scopes: vec![globals],
            batches: vec![],
            stats: RenderStats::default(),
        }
    }

    fn call_function(&mut self, program: &Program, name: &str, args: Vec<Value>) -> Result<Value> {
        if let Some(value) = self.call_builtin(name, &args)? {
            return Ok(value);
        }
        let function = program
            .functions
            .get(name)
            .ok_or_else(|| GraphicsError::MissingFunction(name.to_owned()))?;
        if function.params.len() != args.len() {
            return Err(GraphicsError::BadBuiltin(format!(
                "function {name} expected {} args, got {}",
                function.params.len(),
                args.len()
            ))
            .into());
        }
        let mut scope = BTreeMap::new();
        for (param, value) in function.params.iter().zip(args) {
            scope.insert(param.clone(), value);
        }
        self.scopes.push(scope);
        let result = self.exec_block(program, &function.body)?;
        self.scopes.pop();
        Ok(result.unwrap_or(Value::Unit))
    }

    fn exec_block(&mut self, program: &Program, body: &[Stmt]) -> Result<Option<Value>> {
        for stmt in body {
            if let Some(value) = self.exec_stmt(program, stmt)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn exec_stmt(&mut self, program: &Program, stmt: &Stmt) -> Result<Option<Value>> {
        match stmt {
            Stmt::Let(name, expr) => {
                let value = self.eval(program, expr)?;
                self.scopes
                    .last_mut()
                    .expect("runtime always has a scope")
                    .insert(name.clone(), value);
                Ok(None)
            }
            Stmt::Assign(name, expr) => {
                let value = self.eval(program, expr)?;
                self.assign(name, value)?;
                Ok(None)
            }
            Stmt::Expr(expr) => {
                self.eval(program, expr)?;
                Ok(None)
            }
            Stmt::Return(expr) => Ok(Some(self.eval(program, expr)?)),
            Stmt::For {
                var,
                start,
                end,
                body,
            } => {
                let start = self.eval(program, start)?.number()? as i64;
                let end = self.eval(program, end)?.number()? as i64;
                for value in start..end {
                    self.scopes
                        .last_mut()
                        .expect("runtime always has a scope")
                        .insert(var.clone(), Value::Number(value as f64));
                    if let Some(returned) = self.exec_block(program, body)? {
                        return Ok(Some(returned));
                    }
                }
                Ok(None)
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                if self.eval(program, condition)?.truthy() {
                    self.exec_block(program, then_body)
                } else {
                    self.exec_block(program, else_body)
                }
            }
        }
    }

    fn eval(&mut self, program: &Program, expr: &Expr) -> Result<Value> {
        match expr {
            Expr::Number(value) => Ok(Value::Number(*value)),
            Expr::Bool(value) => Ok(Value::Bool(*value)),
            Expr::Text(value) => Ok(Value::Text(value.clone())),
            Expr::Var(name) => self.lookup(name),
            Expr::Unary { op, rhs } => {
                let rhs = self.eval(program, rhs)?;
                match op.as_str() {
                    "-" => Ok(Value::Number(-rhs.number()?)),
                    "!" => Ok(Value::Bool(!rhs.truthy())),
                    _ => Err(GraphicsError::MalformedExpression(op.clone()).into()),
                }
            }
            Expr::Binary { lhs, op, rhs } => {
                let lhs = self.eval(program, lhs)?;
                let rhs = self.eval(program, rhs)?;
                match op.as_str() {
                    "+" => Ok(Value::Number(lhs.number()? + rhs.number()?)),
                    "-" => Ok(Value::Number(lhs.number()? - rhs.number()?)),
                    "*" => Ok(Value::Number(lhs.number()? * rhs.number()?)),
                    "/" => Ok(Value::Number(lhs.number()? / rhs.number()?)),
                    "==" => Ok(Value::Bool(
                        (lhs.number()? - rhs.number()?).abs() <= f64::EPSILON,
                    )),
                    "!=" => Ok(Value::Bool(
                        (lhs.number()? - rhs.number()?).abs() > f64::EPSILON,
                    )),
                    ">" => Ok(Value::Bool(lhs.number()? > rhs.number()?)),
                    ">=" => Ok(Value::Bool(lhs.number()? >= rhs.number()?)),
                    "<" => Ok(Value::Bool(lhs.number()? < rhs.number()?)),
                    "<=" => Ok(Value::Bool(lhs.number()? <= rhs.number()?)),
                    "&&" => Ok(Value::Bool(lhs.truthy() && rhs.truthy())),
                    "||" => Ok(Value::Bool(lhs.truthy() || rhs.truthy())),
                    _ => Err(GraphicsError::MalformedExpression(op.clone()).into()),
                }
            }
            Expr::Call { name, args } => {
                let args = args
                    .iter()
                    .map(|arg| self.eval(program, arg))
                    .collect::<Result<Vec<_>>>()?;
                self.call_function(program, name, args)
            }
        }
    }

    fn lookup(&self, name: &str) -> Result<Value> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).cloned())
            .ok_or_else(|| GraphicsError::MissingVariable(name.to_owned()).into())
    }

    fn assign(&mut self, name: &str, value: Value) -> Result<()> {
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(name) {
                scope.insert(name.to_owned(), value);
                return Ok(());
            }
        }
        Err(GraphicsError::MissingVariable(name.to_owned()).into())
    }

    fn call_builtin(&mut self, name: &str, args: &[Value]) -> Result<Option<Value>> {
        let nums = || {
            args.iter()
                .map(|value| value.number())
                .collect::<Result<Vec<_>>>()
        };
        let value = match name {
            "width" => Some(Value::Number(self.frame.width as f64)),
            "height" => Some(Value::Number(self.frame.height as f64)),
            "begin_frame" => {
                let args = nums()?;
                expect_argc(name, &args, 2)?;
                self.frame.resize(args[0] as u32, args[1] as u32);
                Some(Value::Unit)
            }
            "clear" => {
                let args = nums()?;
                expect_argc(name, &args, 3)?;
                self.frame.clear(args[0], args[1], args[2]);
                Some(Value::Unit)
            }
            "draw_triangle" => {
                let args = nums()?;
                expect_argc(name, &args, 18)?;
                let triangle = Triangle::from_args(&args);
                self.stats.triangles_submitted += 1;
                match self.mode {
                    RenderMode::Interpret => self.frame.draw_triangle(triangle, &mut self.stats),
                    RenderMode::Ir | RenderMode::Native => self.batches.push(triangle),
                }
                Some(Value::Unit)
            }
            "draw_text" => {
                if args.len() != 7 {
                    return Err(GraphicsError::BadBuiltin(format!(
                        "draw_text expected 7 args, got {}",
                        args.len()
                    ))
                    .into());
                }
                let x = args[0].number()?;
                let y = args[1].number()?;
                let size = args[2].number()?;
                let r = args[3].number()?;
                let g = args[4].number()?;
                let b = args[5].number()?;
                let Value::Text(text) = &args[6] else {
                    return Err(GraphicsError::BadBuiltin(
                        "draw_text expects a string as its last argument".into(),
                    )
                    .into());
                };
                self.flush_batches();
                self.frame.draw_text([x, y], size, [r, g, b], text);
                Some(Value::Unit)
            }
            "flush" => {
                self.flush_batches();
                Some(Value::Unit)
            }
            "sin" => unary(args, f64::sin)?,
            "cos" => unary(args, f64::cos)?,
            "tan" => unary(args, f64::tan)?,
            "floor" => unary(args, f64::floor)?,
            "sqrt" => unary(args, f64::sqrt)?,
            "abs" => unary(args, f64::abs)?,
            "pow" => binary(args, f64::powf)?,
            "min" => binary(args, f64::min)?,
            "max" => binary(args, f64::max)?,
            "fract" => unary(args, |v| v - v.floor())?,
            "clamp" => {
                let args = nums()?;
                expect_argc(name, &args, 3)?;
                Some(Value::Number(args[0].clamp(args[1], args[2])))
            }
            "mix" => {
                let args = nums()?;
                expect_argc(name, &args, 3)?;
                Some(Value::Number(args[0] * (1.0 - args[2]) + args[1] * args[2]))
            }
            "smoothstep" => {
                let args = nums()?;
                expect_argc(name, &args, 3)?;
                let t = ((args[2] - args[0]) / (args[1] - args[0]).max(0.000001)).clamp(0.0, 1.0);
                Some(Value::Number(t * t * (3.0 - 2.0 * t)))
            }
            _ => None,
        };
        Ok(value)
    }

    fn flush_batches(&mut self) {
        if self.batches.is_empty() {
            return;
        }
        let mut batches = Vec::new();
        std::mem::swap(&mut self.batches, &mut batches);
        for triangle in batches {
            self.frame.draw_triangle(triangle, &mut self.stats);
        }
    }
}

fn expect_argc(name: &str, args: &[f64], expected: usize) -> Result<()> {
    if args.len() != expected {
        return Err(GraphicsError::BadBuiltin(format!(
            "{name} expected {expected} args, got {}",
            args.len()
        ))
        .into());
    }
    Ok(())
}

fn unary(args: &[Value], op: impl FnOnce(f64) -> f64) -> Result<Option<Value>> {
    if args.len() != 1 {
        return Err(GraphicsError::BadBuiltin("unary builtin arity".into()).into());
    }
    Ok(Some(Value::Number(op(args[0].number()?))))
}

fn binary(args: &[Value], op: impl FnOnce(f64, f64) -> f64) -> Result<Option<Value>> {
    if args.len() != 2 {
        return Err(GraphicsError::BadBuiltin("binary builtin arity".into()).into());
    }
    Ok(Some(Value::Number(op(
        args[0].number()?,
        args[1].number()?,
    ))))
}

#[derive(Clone, Copy, Debug)]
struct Vertex {
    x: f64,
    y: f64,
    z: f64,
    r: f64,
    g: f64,
    b: f64,
}

#[derive(Clone, Copy, Debug)]
struct Triangle {
    a: Vertex,
    b: Vertex,
    c: Vertex,
}

impl Triangle {
    fn from_args(args: &[f64]) -> Self {
        let v = |i: usize| Vertex {
            x: args[i],
            y: args[i + 1],
            z: args[i + 2],
            r: args[i + 3],
            g: args[i + 4],
            b: args[i + 5],
        };
        Self {
            a: v(0),
            b: v(6),
            c: v(12),
        }
    }
}

#[derive(Default)]
struct FrameBuffer {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
    depth: Vec<f64>,
}

impl FrameBuffer {
    fn resize(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
        let pixels = width as usize * height as usize;
        self.rgba = vec![0; pixels * 4];
        self.depth = vec![1.0; pixels];
    }

    fn empty(&self) -> bool {
        self.rgba.chunks_exact(4).all(|px| px[3] == 0)
    }

    fn clear(&mut self, r: f64, g: f64, b: f64) {
        for pixel in self.rgba.chunks_exact_mut(4) {
            pixel[0] = byte(r);
            pixel[1] = byte(g);
            pixel[2] = byte(b);
            pixel[3] = 255;
        }
        self.depth.fill(1.0);
    }

    fn draw_triangle(&mut self, triangle: Triangle, stats: &mut RenderStats) {
        if self.width == 0 || self.height == 0 {
            return;
        }
        let area = edge(triangle.a, triangle.b, triangle.c.x, triangle.c.y);
        if area.abs() <= 0.000001 {
            return;
        }
        let min_x = triangle
            .a
            .x
            .min(triangle.b.x)
            .min(triangle.c.x)
            .floor()
            .max(0.0) as i32;
        let max_x = triangle
            .a
            .x
            .max(triangle.b.x)
            .max(triangle.c.x)
            .ceil()
            .min(self.width.saturating_sub(1) as f64) as i32;
        let min_y = triangle
            .a
            .y
            .min(triangle.b.y)
            .min(triangle.c.y)
            .floor()
            .max(0.0) as i32;
        let max_y = triangle
            .a
            .y
            .max(triangle.b.y)
            .max(triangle.c.y)
            .ceil()
            .min(self.height.saturating_sub(1) as f64) as i32;
        let inv_area = 1.0 / area;
        let mut touched = 0usize;
        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let px = x as f64 + 0.5;
                let py = y as f64 + 0.5;
                let wa = edge(triangle.b, triangle.c, px, py) * inv_area;
                let wb = edge(triangle.c, triangle.a, px, py) * inv_area;
                let wc = edge(triangle.a, triangle.b, px, py) * inv_area;
                if wa < 0.0 || wb < 0.0 || wc < 0.0 {
                    continue;
                }
                let depth = triangle.a.z * wa + triangle.b.z * wb + triangle.c.z * wc;
                let pixel = y as usize * self.width as usize + x as usize;
                if !(0.0..=1.0).contains(&depth) || depth >= self.depth[pixel] {
                    continue;
                }
                self.depth[pixel] = depth;
                let base = pixel * 4;
                self.rgba[base] = byte(triangle.a.r * wa + triangle.b.r * wb + triangle.c.r * wc);
                self.rgba[base + 1] =
                    byte(triangle.a.g * wa + triangle.b.g * wb + triangle.c.g * wc);
                self.rgba[base + 2] =
                    byte(triangle.a.b * wa + triangle.b.b * wb + triangle.c.b * wc);
                self.rgba[base + 3] = 255;
                touched += 1;
            }
        }
        stats.triangles_rasterized += 1;
        stats.pixels_touched += touched;
    }

    fn draw_text(&mut self, origin: [f64; 2], size: f64, color: [f64; 3], text: &str) {
        let scale = size.max(1.0) as i32;
        let mut cursor = origin[0] as i32;
        let top = origin[1] as i32;
        for ch in text.chars() {
            if ch == ' ' {
                cursor += scale * 4;
                continue;
            }
            let rows = glyph_rows(ch);
            for (row, bits) in rows.iter().enumerate() {
                for col in 0..5 {
                    if (bits & (1 << (4 - col))) != 0 {
                        self.fill_rect(
                            cursor + col * scale,
                            top + row as i32 * scale,
                            scale,
                            scale,
                            [byte(color[0]), byte(color[1]), byte(color[2]), 255],
                        );
                    }
                }
            }
            cursor += scale * 6;
        }
    }

    fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, color: [u8; 4]) {
        for py in y.max(0)..(y + h).min(self.height as i32) {
            for px in x.max(0)..(x + w).min(self.width as i32) {
                let base = (py as usize * self.width as usize + px as usize) * 4;
                self.rgba[base..base + 4].copy_from_slice(&color);
            }
        }
    }

    fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("png") => self.write_png(path),
            _ => self.write_ppm(path),
        }
    }

    fn write_ppm(&self, path: &Path) -> Result<()> {
        let mut bytes = format!("P6\n{} {}\n255\n", self.width, self.height).into_bytes();
        for pixel in self.rgba.chunks_exact(4) {
            bytes.extend_from_slice(&pixel[..3]);
        }
        fs::write(path, bytes)?;
        Ok(())
    }

    fn write_png(&self, path: &Path) -> Result<()> {
        let file = fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        let mut encoder = png::Encoder::new(writer, self.width, self.height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&self.rgba)?;
        Ok(())
    }
}

fn edge(a: Vertex, b: Vertex, x: f64, y: f64) -> f64 {
    (x - a.x) * (b.y - a.y) - (y - a.y) * (b.x - a.x)
}

fn byte(value: f64) -> u8 {
    (value.clamp(0.0, 1.0) * 255.0 + 0.5) as u8
}

fn glyph_rows(ch: char) -> [u8; 7] {
    match ch.to_ascii_uppercase() {
        'A' => [
            0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
        'B' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110,
        ],
        'C' => [
            0b01111, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b01111,
        ],
        'D' => [
            0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110,
        ],
        'E' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111,
        ],
        'F' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
        'G' => [
            0b01111, 0b10000, 0b10000, 0b10111, 0b10001, 0b10001, 0b01111,
        ],
        'H' => [
            0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
        'I' => [
            0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b11111,
        ],
        'J' => [
            0b00111, 0b00010, 0b00010, 0b00010, 0b10010, 0b10010, 0b01100,
        ],
        'K' => [
            0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001,
        ],
        'L' => [
            0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111,
        ],
        'M' => [
            0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001,
        ],
        'N' => [
            0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001,
        ],
        'O' => [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
        'P' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
        'Q' => [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101,
        ],
        'R' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001,
        ],
        'S' => [
            0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110,
        ],
        'T' => [
            0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
        'U' => [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
        'V' => [
            0b10001, 0b10001, 0b10001, 0b01010, 0b01010, 0b01010, 0b00100,
        ],
        'W' => [
            0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b11011, 0b10001,
        ],
        'X' => [
            0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001,
        ],
        'Y' => [
            0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
        'Z' => [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111,
        ],
        '0' => [
            0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110,
        ],
        '1' => [
            0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
        '2' => [
            0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111,
        ],
        '3' => [
            0b11110, 0b00001, 0b00001, 0b01110, 0b00001, 0b00001, 0b11110,
        ],
        '4' => [
            0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010,
        ],
        '5' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b00001, 0b00001, 0b11110,
        ],
        '6' => [
            0b01110, 0b10000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110,
        ],
        '7' => [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000,
        ],
        '8' => [
            0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110,
        ],
        '9' => [
            0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00001, 0b01110,
        ],
        '.' => [
            0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b01100, 0b01100,
        ],
        '/' => [
            0b00001, 0b00010, 0b00010, 0b00100, 0b01000, 0b01000, 0b10000,
        ],
        '-' => [
            0b00000, 0b00000, 0b00000, 0b11111, 0b00000, 0b00000, 0b00000,
        ],
        _ => [
            0b11111, 0b10001, 0b00010, 0b00100, 0b00000, 0b00100, 0b00100,
        ],
    }
}

fn strip_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(head, _)| head))
        .collect::<Vec<_>>()
        .join("\n")
}

fn find_matching(source: &str, open: usize) -> Option<usize> {
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

fn split_once_top(input: &str, needle: char) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    for (idx, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if ch == needle && depth == 0 => return Some((&input[..idx], &input[idx + 1..])),
            _ => {}
        }
    }
    None
}

fn sha256_uri(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hex = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}
