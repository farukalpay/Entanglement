use anyhow::{Context, Result};
use ent_core::{Certificate, ModelContract, TensorContract, TrainingContract};
use ent_elab::elaborate_source;
use ent_kernel::verify;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::Instant;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct TensorBenchOptions {
    pub iterations: u32,
}

impl Default for TensorBenchOptions {
    fn default() -> Self {
        Self { iterations: 1 }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TensorBenchReport {
    pub world: String,
    pub training: String,
    pub model: String,
    pub dataset: String,
    pub backend: BackendPlanReport,
    pub iterations: u32,
    pub runs: Vec<TensorRunReport>,
    pub op_count: usize,
    pub parameter_count: usize,
    pub source_digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BackendPlanReport {
    pub executor: String,
    pub device: String,
    pub memory: String,
    pub precision: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TensorRunReport {
    pub steps: u32,
    pub first_loss: f32,
    pub final_loss: f32,
    pub elapsed_ms: f64,
}

#[derive(Debug, Error)]
pub enum TensorRuntimeError {
    #[error("source does not declare a training contract")]
    MissingTraining,
    #[error("training references missing model: {0}")]
    MissingModel(String),
    #[error("training references missing dataset: {0}")]
    MissingDataset(String),
    #[error("tensor is undeclared: {0}")]
    MissingTensor(String),
    #[error("dataset source must be explicit inline data: {0}")]
    UnsupportedDataset(String),
    #[error("dataset source lacks tensor values: {0}")]
    MissingTensorValues(String),
    #[error("tensor {name} expected {expected} values, got {actual}")]
    BadTensorValueCount {
        name: String,
        expected: usize,
        actual: usize,
    },
    #[error("tensor shape is not fully concrete for runtime: {0}")]
    SymbolicRuntimeShape(String),
    #[error("model op is malformed: {0}")]
    MalformedOp(String),
    #[error("model op is unsupported by the current executor: {0}")]
    UnsupportedOp(String),
    #[error("model op references unknown value: {0}")]
    UnknownValue(String),
    #[error("shape mismatch: {0}")]
    ShapeMismatch(String),
    #[error("loss value is not scalar: {0}")]
    NonScalarLoss(String),
    #[error("optimizer is unsupported by the current executor: {0}")]
    UnsupportedOptimizer(String),
    #[error("dataset digest mismatch for {name}: expected {expected}, got {actual}")]
    DatasetDigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
}

pub fn run_tensor_benchmark(path: &Path, options: TensorBenchOptions) -> Result<TensorBenchReport> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read tensor source {}", path.display()))?;
    run_tensor_source(&source, options)
}

pub fn run_tensor_source(source: &str, options: TensorBenchOptions) -> Result<TensorBenchReport> {
    let cert = elaborate_source(source).context("tensor source failed to elaborate")?;
    let kernel_report = verify(&cert).context("tensor certificate rejected by kernel")?;
    let training = cert
        .trainings
        .first()
        .ok_or(TensorRuntimeError::MissingTraining)?;
    let model = cert
        .models
        .iter()
        .find(|model| model.name == training.model)
        .ok_or_else(|| TensorRuntimeError::MissingModel(training.model.clone()))?;
    let dataset = cert
        .datasets
        .iter()
        .find(|dataset| dataset.name == training.dataset)
        .ok_or_else(|| TensorRuntimeError::MissingDataset(training.dataset.clone()))?;

    let actual_digest = sha256_uri(dataset.source.as_bytes());
    if actual_digest != dataset.source_digest {
        return Err(TensorRuntimeError::DatasetDigestMismatch {
            name: dataset.name.clone(),
            expected: dataset.source_digest.clone(),
            actual: actual_digest,
        }
        .into());
    }

    let tensor_specs = tensor_specs(&cert);
    let values = InlineDataset::parse(&dataset.source)?;
    let backend = backend_plan(&cert, training);
    let iterations = options.iterations.max(1);
    let mut runs = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        runs.push(run_training(training, model, &tensor_specs, &values)?);
    }

    Ok(TensorBenchReport {
        world: kernel_report.world,
        training: training.name.clone(),
        model: model.name.clone(),
        dataset: dataset.name.clone(),
        backend,
        iterations,
        runs,
        op_count: model.ops.len(),
        parameter_count: model.parameters.len(),
        source_digest: sha256_uri(source.as_bytes()),
    })
}

fn backend_plan(cert: &Certificate, training: &TrainingContract) -> BackendPlanReport {
    let accelerator = cert
        .accelerators
        .iter()
        .find(|accelerator| accelerator.name == training.accelerator);
    BackendPlanReport {
        executor: "ent-tensor-cpu".to_owned(),
        device: accelerator
            .map(|accelerator| accelerator.kind.clone())
            .unwrap_or_else(|| "cpu".to_owned()),
        memory: accelerator
            .map(|accelerator| accelerator.memory.clone())
            .unwrap_or_else(|| "host".to_owned()),
        precision: accelerator
            .map(|accelerator| accelerator.precision.clone())
            .unwrap_or_else(|| "f32".to_owned()),
        evidence: accelerator
            .map(|accelerator| accelerator.evidence.clone())
            .unwrap_or_else(|| "local-cpu-executor".to_owned()),
    }
}

fn tensor_specs(cert: &Certificate) -> BTreeMap<String, TensorSpec> {
    cert.tensors
        .iter()
        .map(|tensor| (tensor.name.clone(), TensorSpec::from_contract(tensor)))
        .collect()
}

#[derive(Clone, Debug)]
struct TensorSpec {
    shape: Vec<String>,
    gradient: String,
}

impl TensorSpec {
    fn from_contract(contract: &TensorContract) -> Self {
        Self {
            shape: contract.shape.clone(),
            gradient: contract.gradient.clone(),
        }
    }

    fn concrete_shape(&self, name: &str) -> Result<Vec<usize>> {
        self.shape
            .iter()
            .map(|dim| {
                dim.parse::<usize>()
                    .map_err(|_| TensorRuntimeError::SymbolicRuntimeShape(name.to_owned()).into())
            })
            .collect()
    }

    fn tracked(&self) -> bool {
        self.gradient == "tracked"
    }
}

#[derive(Clone, Debug)]
struct InlineDataset {
    values: BTreeMap<String, Vec<f32>>,
}

impl InlineDataset {
    fn parse(source: &str) -> Result<Self> {
        let Some(body) = source.strip_prefix("inline:") else {
            return Err(TensorRuntimeError::UnsupportedDataset(source.to_owned()).into());
        };
        let mut values = BTreeMap::new();
        for assignment in body
            .split('|')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            let (name, data) = assignment
                .split_once('=')
                .ok_or_else(|| TensorRuntimeError::UnsupportedDataset(source.to_owned()))?;
            let mut flattened = Vec::new();
            for row in data.split(';').map(str::trim).filter(|row| !row.is_empty()) {
                for value in row
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    flattened.push(
                        value.parse::<f32>().map_err(|_| {
                            TensorRuntimeError::UnsupportedDataset(source.to_owned())
                        })?,
                    );
                }
            }
            values.insert(name.trim().to_owned(), flattened);
        }
        Ok(Self { values })
    }

    fn tensor(&self, name: &str, spec: &TensorSpec) -> Result<Tensor> {
        let shape = spec.concrete_shape(name)?;
        let expected = shape.iter().product();
        let data = self
            .values
            .get(name)
            .ok_or_else(|| TensorRuntimeError::MissingTensorValues(name.to_owned()))?;
        if data.len() != expected {
            return Err(TensorRuntimeError::BadTensorValueCount {
                name: name.to_owned(),
                expected,
                actual: data.len(),
            }
            .into());
        }
        Ok(Tensor {
            shape,
            data: data.clone(),
        })
    }
}

fn run_training(
    training: &TrainingContract,
    model: &ModelContract,
    specs: &BTreeMap<String, TensorSpec>,
    dataset: &InlineDataset,
) -> Result<TensorRunReport> {
    if !matches!(training.optimizer.as_str(), "sgd" | "gradient-descent") {
        return Err(TensorRuntimeError::UnsupportedOptimizer(training.optimizer.clone()).into());
    }

    let mut parameters = BTreeMap::new();
    for name in &model.parameters {
        let spec = specs
            .get(name)
            .ok_or_else(|| TensorRuntimeError::MissingTensor(name.clone()))?;
        parameters.insert(name.clone(), dataset.tensor(name, spec)?);
    }

    let started = Instant::now();
    let mut first_loss = None;
    let mut final_loss = 0.0f32;
    for _ in 0..training.steps {
        let mut tape = Tape::default();
        let mut values = BTreeMap::new();
        for name in model.inputs.iter().chain(model.parameters.iter()) {
            let spec = specs
                .get(name)
                .ok_or_else(|| TensorRuntimeError::MissingTensor(name.clone()))?;
            let tensor = parameters
                .get(name)
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| dataset.tensor(name, spec))?;
            let id = tape.leaf(tensor, spec.tracked() || model.parameters.contains(name));
            values.insert(name.clone(), id);
        }

        execute_model(model, &mut tape, &mut values)?;
        let loss_id = *values
            .get(&model.loss)
            .ok_or_else(|| TensorRuntimeError::UnknownValue(model.loss.clone()))?;
        let loss = tape.value(loss_id).tensor.scalar(&model.loss)?;
        first_loss.get_or_insert(loss);
        final_loss = loss;
        tape.backward(loss_id)?;

        for name in &model.parameters {
            let id = *values
                .get(name)
                .ok_or_else(|| TensorRuntimeError::UnknownValue(name.clone()))?;
            let grad = tape.value(id).grad.clone();
            let parameter = parameters
                .get_mut(name)
                .ok_or_else(|| TensorRuntimeError::UnknownValue(name.clone()))?;
            for (value, grad) in parameter.data.iter_mut().zip(grad) {
                *value -= training.learning_rate as f32 * grad;
            }
        }
    }

    Ok(TensorRunReport {
        steps: training.steps,
        first_loss: first_loss.unwrap_or(final_loss),
        final_loss,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
    })
}

fn execute_model(
    model: &ModelContract,
    tape: &mut Tape,
    values: &mut BTreeMap<String, ValueId>,
) -> Result<()> {
    for op in &model.ops {
        let parsed = ParsedOp::parse(op)?;
        let args = parsed
            .args
            .iter()
            .map(|name| {
                values
                    .get(name)
                    .copied()
                    .ok_or_else(|| TensorRuntimeError::UnknownValue(name.clone()))
            })
            .collect::<Result<Vec<_>, TensorRuntimeError>>()?;
        let id = match parsed.name.as_str() {
            "matmul" => {
                expect_args(&parsed, 2)?;
                tape.matmul(args[0], args[1])?
            }
            "add" => {
                expect_args(&parsed, 2)?;
                tape.add(args[0], args[1])?
            }
            "relu" => {
                expect_args(&parsed, 1)?;
                tape.relu(args[0])?
            }
            "linear" => {
                expect_args(&parsed, 3)?;
                let projected = tape.matmul(args[0], args[1])?;
                tape.add(projected, args[2])?
            }
            "softmax_cross_entropy" => {
                expect_args(&parsed, 2)?;
                tape.softmax_cross_entropy(args[0], args[1])?
            }
            "mse" => {
                expect_args(&parsed, 2)?;
                tape.mse(args[0], args[1])?
            }
            "mean" => {
                expect_args(&parsed, 1)?;
                tape.mean(args[0])?
            }
            other => return Err(TensorRuntimeError::UnsupportedOp(other.to_owned()).into()),
        };
        values.insert(parsed.output, id);
    }
    Ok(())
}

fn expect_args(op: &ParsedOp, expected: usize) -> Result<(), TensorRuntimeError> {
    if op.args.len() == expected {
        Ok(())
    } else {
        Err(TensorRuntimeError::MalformedOp(format!(
            "{} expected {expected} args, got {}",
            op.name,
            op.args.len()
        )))
    }
}

#[derive(Clone, Debug)]
struct ParsedOp {
    name: String,
    args: Vec<String>,
    output: String,
}

impl ParsedOp {
    fn parse(input: &str) -> Result<Self, TensorRuntimeError> {
        let (call, output) = input
            .split_once("->")
            .ok_or_else(|| TensorRuntimeError::MalformedOp(input.to_owned()))?;
        let open = call
            .find('(')
            .ok_or_else(|| TensorRuntimeError::MalformedOp(input.to_owned()))?;
        let close = call
            .rfind(')')
            .ok_or_else(|| TensorRuntimeError::MalformedOp(input.to_owned()))?;
        if close <= open || !call[close + 1..].trim().is_empty() {
            return Err(TensorRuntimeError::MalformedOp(input.to_owned()));
        }
        let args = call[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|arg| !arg.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let output = output.trim();
        if output.is_empty() {
            return Err(TensorRuntimeError::MalformedOp(input.to_owned()));
        }
        Ok(Self {
            name: call[..open].trim().to_owned(),
            args,
            output: output.to_owned(),
        })
    }
}

#[derive(Clone, Debug)]
struct Tensor {
    shape: Vec<usize>,
    data: Vec<f32>,
}

impl Tensor {
    fn scalar(&self, name: &str) -> Result<f32> {
        if self.shape.is_empty() || self.shape == [1] {
            self.data
                .first()
                .copied()
                .ok_or_else(|| TensorRuntimeError::NonScalarLoss(name.to_owned()).into())
        } else {
            Err(TensorRuntimeError::NonScalarLoss(name.to_owned()).into())
        }
    }

    fn zeros_like(&self) -> Vec<f32> {
        vec![0.0; self.data.len()]
    }

    fn matmul(&self, rhs: &Self) -> Result<Self> {
        let (m, k) = matrix_shape(&self.shape)?;
        let (rhs_k, n) = matrix_shape(&rhs.shape)?;
        if k != rhs_k {
            return Err(TensorRuntimeError::ShapeMismatch(format!(
                "matmul {:?} x {:?}",
                self.shape, rhs.shape
            ))
            .into());
        }
        let mut data = vec![0.0; m * n];
        for row in 0..m {
            for col in 0..n {
                let mut sum = 0.0;
                for inner in 0..k {
                    sum += self.data[row * k + inner] * rhs.data[inner * n + col];
                }
                data[row * n + col] = sum;
            }
        }
        Ok(Self {
            shape: vec![m, n],
            data,
        })
    }

    fn add(&self, rhs: &Self) -> Result<Self> {
        let shape = broadcast_shape(&self.shape, &rhs.shape)?;
        let mut data = vec![0.0; shape.iter().product()];
        for (idx, value) in data.iter_mut().enumerate() {
            *value = broadcast_get(self, &shape, idx)? + broadcast_get(rhs, &shape, idx)?;
        }
        Ok(Self { shape, data })
    }

    fn relu(&self) -> Self {
        Self {
            shape: self.shape.clone(),
            data: self.data.iter().map(|value| value.max(0.0)).collect(),
        }
    }

    fn mean(&self) -> Self {
        let sum: f32 = self.data.iter().sum();
        Self {
            shape: vec![1],
            data: vec![sum / self.data.len().max(1) as f32],
        }
    }

    fn mse(&self, target: &Self) -> Result<Self> {
        if self.shape != target.shape {
            return Err(TensorRuntimeError::ShapeMismatch(format!(
                "mse {:?} vs {:?}",
                self.shape, target.shape
            ))
            .into());
        }
        let loss = self
            .data
            .iter()
            .zip(&target.data)
            .map(|(left, right)| {
                let diff = left - right;
                diff * diff
            })
            .sum::<f32>()
            / self.data.len().max(1) as f32;
        Ok(Self {
            shape: vec![1],
            data: vec![loss],
        })
    }

    fn softmax_cross_entropy(&self, labels: &Self) -> Result<Self> {
        let (rows, cols) = matrix_shape(&self.shape)?;
        if labels.shape != self.shape {
            return Err(TensorRuntimeError::ShapeMismatch(format!(
                "cross entropy {:?} vs {:?}",
                self.shape, labels.shape
            ))
            .into());
        }
        let mut loss = 0.0;
        for row in 0..rows {
            let logits = &self.data[row * cols..(row + 1) * cols];
            let labels = &labels.data[row * cols..(row + 1) * cols];
            let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let denom = logits.iter().map(|value| (*value - max).exp()).sum::<f32>();
            for (logit, label) in logits.iter().zip(labels) {
                if *label > 0.0 {
                    let log_prob = (*logit - max).exp().ln() - denom.ln();
                    loss -= *label * log_prob;
                }
            }
        }
        Ok(Self {
            shape: vec![1],
            data: vec![loss / rows.max(1) as f32],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ValueId(usize);

#[derive(Clone, Debug)]
enum OpNode {
    Leaf,
    MatMul(ValueId, ValueId),
    Add(ValueId, ValueId),
    Relu(ValueId),
    Mean(ValueId),
    Mse(ValueId, ValueId),
    SoftmaxCrossEntropy(ValueId, ValueId),
}

#[derive(Clone, Debug)]
struct ValueNode {
    tensor: Tensor,
    grad: Vec<f32>,
    op: OpNode,
    requires_grad: bool,
}

#[derive(Default)]
struct Tape {
    values: Vec<ValueNode>,
}

impl Tape {
    fn value(&self, id: ValueId) -> &ValueNode {
        &self.values[id.0]
    }

    fn leaf(&mut self, tensor: Tensor, requires_grad: bool) -> ValueId {
        self.push(tensor, OpNode::Leaf, requires_grad)
    }

    fn matmul(&mut self, left: ValueId, right: ValueId) -> Result<ValueId> {
        let tensor = self.value(left).tensor.matmul(&self.value(right).tensor)?;
        let requires_grad = self.value(left).requires_grad || self.value(right).requires_grad;
        Ok(self.push(tensor, OpNode::MatMul(left, right), requires_grad))
    }

    fn add(&mut self, left: ValueId, right: ValueId) -> Result<ValueId> {
        let tensor = self.value(left).tensor.add(&self.value(right).tensor)?;
        let requires_grad = self.value(left).requires_grad || self.value(right).requires_grad;
        Ok(self.push(tensor, OpNode::Add(left, right), requires_grad))
    }

    fn relu(&mut self, input: ValueId) -> Result<ValueId> {
        let tensor = self.value(input).tensor.relu();
        let requires_grad = self.value(input).requires_grad;
        Ok(self.push(tensor, OpNode::Relu(input), requires_grad))
    }

    fn mean(&mut self, input: ValueId) -> Result<ValueId> {
        let tensor = self.value(input).tensor.mean();
        let requires_grad = self.value(input).requires_grad;
        Ok(self.push(tensor, OpNode::Mean(input), requires_grad))
    }

    fn mse(&mut self, pred: ValueId, target: ValueId) -> Result<ValueId> {
        let tensor = self.value(pred).tensor.mse(&self.value(target).tensor)?;
        let requires_grad = self.value(pred).requires_grad || self.value(target).requires_grad;
        Ok(self.push(tensor, OpNode::Mse(pred, target), requires_grad))
    }

    fn softmax_cross_entropy(&mut self, logits: ValueId, labels: ValueId) -> Result<ValueId> {
        let tensor = self
            .value(logits)
            .tensor
            .softmax_cross_entropy(&self.value(labels).tensor)?;
        let requires_grad = self.value(logits).requires_grad || self.value(labels).requires_grad;
        Ok(self.push(
            tensor,
            OpNode::SoftmaxCrossEntropy(logits, labels),
            requires_grad,
        ))
    }

    fn push(&mut self, tensor: Tensor, op: OpNode, requires_grad: bool) -> ValueId {
        let grad = tensor.zeros_like();
        let id = ValueId(self.values.len());
        self.values.push(ValueNode {
            tensor,
            grad,
            op,
            requires_grad,
        });
        id
    }

    fn backward(&mut self, loss: ValueId) -> Result<()> {
        if self.value(loss).tensor.data.len() != 1 {
            return Err(TensorRuntimeError::NonScalarLoss("loss".to_owned()).into());
        }
        self.values[loss.0].grad[0] = 1.0;
        for id in (0..self.values.len()).rev().map(ValueId) {
            let op = self.value(id).op.clone();
            let grad = self.value(id).grad.clone();
            match op {
                OpNode::Leaf => {}
                OpNode::MatMul(left, right) => {
                    let left_tensor = self.value(left).tensor.clone();
                    let right_tensor = self.value(right).tensor.clone();
                    let out_shape = self.value(id).tensor.shape.clone();
                    let left_grad = matmul_backward_left(&grad, &out_shape, &right_tensor)?;
                    let right_grad = matmul_backward_right(&grad, &out_shape, &left_tensor)?;
                    self.add_grad(left, &left_grad);
                    self.add_grad(right, &right_grad);
                }
                OpNode::Add(left, right) => {
                    let out_shape = self.value(id).tensor.shape.clone();
                    let left_shape = self.value(left).tensor.shape.clone();
                    let right_shape = self.value(right).tensor.shape.clone();
                    self.add_grad(left, &unbroadcast_grad(&grad, &out_shape, &left_shape)?);
                    self.add_grad(right, &unbroadcast_grad(&grad, &out_shape, &right_shape)?);
                }
                OpNode::Relu(input) => {
                    let input_tensor = self.value(input).tensor.clone();
                    let grad = grad
                        .iter()
                        .zip(input_tensor.data)
                        .map(|(grad, value)| if value > 0.0 { *grad } else { 0.0 })
                        .collect::<Vec<_>>();
                    self.add_grad(input, &grad);
                }
                OpNode::Mean(input) => {
                    let len = self.value(input).tensor.data.len().max(1);
                    let grad = vec![grad[0] / len as f32; len];
                    self.add_grad(input, &grad);
                }
                OpNode::Mse(pred, target) => {
                    let pred_tensor = self.value(pred).tensor.clone();
                    let target_tensor = self.value(target).tensor.clone();
                    let scale = 2.0 * grad[0] / pred_tensor.data.len().max(1) as f32;
                    let pred_grad = pred_tensor
                        .data
                        .iter()
                        .zip(&target_tensor.data)
                        .map(|(pred, target)| (pred - target) * scale)
                        .collect::<Vec<_>>();
                    let target_grad = pred_grad.iter().map(|value| -*value).collect::<Vec<_>>();
                    self.add_grad(pred, &pred_grad);
                    self.add_grad(target, &target_grad);
                }
                OpNode::SoftmaxCrossEntropy(logits, labels) => {
                    let logits_tensor = self.value(logits).tensor.clone();
                    let labels_tensor = self.value(labels).tensor.clone();
                    let logits_grad = softmax_cross_entropy_grad(&logits_tensor, &labels_tensor)?
                        .into_iter()
                        .map(|value| value * grad[0])
                        .collect::<Vec<_>>();
                    self.add_grad(logits, &logits_grad);
                }
            }
        }
        Ok(())
    }

    fn add_grad(&mut self, id: ValueId, grad: &[f32]) {
        if !self.values[id.0].requires_grad {
            return;
        }
        for (slot, value) in self.values[id.0].grad.iter_mut().zip(grad) {
            *slot += *value;
        }
    }
}

fn matrix_shape(shape: &[usize]) -> Result<(usize, usize)> {
    match shape {
        [rows, cols] => Ok((*rows, *cols)),
        _ => {
            Err(TensorRuntimeError::ShapeMismatch(format!("expected matrix, got {shape:?}")).into())
        }
    }
}

fn broadcast_shape(left: &[usize], right: &[usize]) -> Result<Vec<usize>> {
    if left == right {
        return Ok(left.to_vec());
    }
    if left == [1] {
        return Ok(right.to_vec());
    }
    if right == [1] {
        return Ok(left.to_vec());
    }
    if left.len() == 2 && right.len() == 2 && left[1] == right[1] && right[0] == 1 {
        return Ok(left.to_vec());
    }
    if left.len() == 2 && right.len() == 2 && left[1] == right[1] && left[0] == 1 {
        return Ok(right.to_vec());
    }
    Err(TensorRuntimeError::ShapeMismatch(format!("broadcast {left:?} and {right:?}")).into())
}

fn broadcast_get(tensor: &Tensor, out_shape: &[usize], out_index: usize) -> Result<f32> {
    if tensor.shape == out_shape {
        return Ok(tensor.data[out_index]);
    }
    if tensor.shape == [1] {
        return Ok(tensor.data[0]);
    }
    if tensor.shape.len() == 2 && out_shape.len() == 2 && tensor.shape[0] == 1 {
        let cols = out_shape[1];
        let col = out_index % cols;
        return Ok(tensor.data[col]);
    }
    Err(TensorRuntimeError::ShapeMismatch(format!(
        "cannot broadcast {:?} to {:?}",
        tensor.shape, out_shape
    ))
    .into())
}

fn unbroadcast_grad(grad: &[f32], out_shape: &[usize], target_shape: &[usize]) -> Result<Vec<f32>> {
    if out_shape == target_shape {
        return Ok(grad.to_vec());
    }
    if target_shape == [1] {
        return Ok(vec![grad.iter().sum()]);
    }
    if target_shape.len() == 2 && out_shape.len() == 2 && target_shape[0] == 1 {
        let rows = out_shape[0];
        let cols = out_shape[1];
        let mut output = vec![0.0; cols];
        for row in 0..rows {
            for col in 0..cols {
                output[col] += grad[row * cols + col];
            }
        }
        return Ok(output);
    }
    Err(TensorRuntimeError::ShapeMismatch(format!(
        "cannot unbroadcast gradient {:?} to {:?}",
        out_shape, target_shape
    ))
    .into())
}

fn matmul_backward_left(grad: &[f32], out_shape: &[usize], right: &Tensor) -> Result<Vec<f32>> {
    let (m, n) = matrix_shape(out_shape)?;
    let (k, right_n) = matrix_shape(&right.shape)?;
    if n != right_n {
        return Err(TensorRuntimeError::ShapeMismatch("matmul backward lhs".to_owned()).into());
    }
    let mut output = vec![0.0; m * k];
    for row in 0..m {
        for inner in 0..k {
            let mut sum = 0.0;
            for col in 0..n {
                sum += grad[row * n + col] * right.data[inner * n + col];
            }
            output[row * k + inner] = sum;
        }
    }
    Ok(output)
}

fn matmul_backward_right(grad: &[f32], out_shape: &[usize], left: &Tensor) -> Result<Vec<f32>> {
    let (m, n) = matrix_shape(out_shape)?;
    let (left_m, k) = matrix_shape(&left.shape)?;
    if m != left_m {
        return Err(TensorRuntimeError::ShapeMismatch("matmul backward rhs".to_owned()).into());
    }
    let mut output = vec![0.0; k * n];
    for inner in 0..k {
        for col in 0..n {
            let mut sum = 0.0;
            for row in 0..m {
                sum += left.data[row * k + inner] * grad[row * n + col];
            }
            output[inner * n + col] = sum;
        }
    }
    Ok(output)
}

fn softmax_cross_entropy_grad(logits: &Tensor, labels: &Tensor) -> Result<Vec<f32>> {
    let (rows, cols) = matrix_shape(&logits.shape)?;
    if labels.shape != logits.shape {
        return Err(TensorRuntimeError::ShapeMismatch(format!(
            "cross entropy grad {:?} vs {:?}",
            logits.shape, labels.shape
        ))
        .into());
    }
    let mut grad = vec![0.0; logits.data.len()];
    for row in 0..rows {
        let row_start = row * cols;
        let row_end = row_start + cols;
        let row_logits = &logits.data[row_start..row_end];
        let max = row_logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let denom = row_logits
            .iter()
            .map(|value| (*value - max).exp())
            .sum::<f32>();
        for col in 0..cols {
            let softmax = (logits.data[row_start + col] - max).exp() / denom;
            grad[row_start + col] = (softmax - labels.data[row_start + col]) / rows.max(1) as f32;
        }
    }
    Ok(grad)
}

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[allow(dead_code)]
fn declared_names(values: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    values.into_iter().collect()
}
