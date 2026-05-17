use anyhow::{Context, Result};
use ent_core::{
    ArtifactContract, Certificate, ExecutorContract, LoweringContract, ModelContract,
    TensorContract, TrainingContract,
};
use ent_elab::elaborate_source;
use ent_kernel::verify;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
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

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactVerificationReport {
    pub world: String,
    pub artifact: String,
    pub manifest: String,
    pub canonical: String,
    pub expected_digest: String,
    pub actual_digest: String,
    pub tensors: Vec<TensorManifestCheck>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TensorManifestCheck {
    pub name: String,
    pub shape: Vec<usize>,
    pub dtype: String,
    pub layout: String,
    pub tensor_digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct WitnessVerificationReport {
    pub world: String,
    pub witness: String,
    pub training: String,
    pub artifact: String,
    pub lowering: String,
    pub executor: String,
    pub dataset_digest: String,
    pub trace_ops: Vec<String>,
    pub requirements: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BindingReport {
    pub world: String,
    pub artifact: String,
    pub training: String,
    pub lowering: String,
    pub executor: String,
    pub framework: String,
    pub output: PathBuf,
    pub expected_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TensorManifest {
    pub schema: String,
    pub canonical: String,
    pub tensors: BTreeMap<String, TensorManifestEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TensorManifestEntry {
    pub shape: Vec<usize>,
    pub dtype: String,
    pub layout: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWitness {
    pub schema: String,
    pub training: String,
    pub artifact: String,
    pub lowering: String,
    pub executor: String,
    pub observed: WitnessObserved,
    pub metrics: BTreeMap<String, f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessObserved {
    pub dataset_digest: String,
    pub trace_ops: Vec<String>,
    pub optimizer: String,
    pub learning_rate: f64,
    pub steps: u32,
    pub batch: u32,
    pub device: String,
    pub network_access: String,
    pub seed: u64,
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
    #[error("source does not declare an artifact contract")]
    MissingArtifact,
    #[error("source does not declare a lowering contract")]
    MissingLowering,
    #[error("source does not declare an executor contract")]
    MissingExecutor,
    #[error("source does not declare a witness contract")]
    MissingWitness,
    #[error("artifact manifest digest mismatch for {name}: expected {expected}, got {actual}")]
    ArtifactDigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    #[error("artifact manifest is missing tensor: {0}")]
    ManifestMissingTensor(String),
    #[error(
        "artifact manifest tensor {name} has {field} mismatch: expected {expected}, got {actual}"
    )]
    ManifestTensorMismatch {
        name: String,
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("runtime witness mismatch for {field}: expected {expected}, got {actual}")]
    WitnessMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("runtime witness requirement failed: {0}")]
    WitnessRequirementFailed(String),
    #[error("runtime witness requirement is malformed: {0}")]
    MalformedRequirement(String),
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

pub fn verify_artifact_manifest(
    ent_path: &Path,
    manifest_path: Option<&Path>,
) -> Result<ArtifactVerificationReport> {
    let cert = load_verified_certificate(ent_path)?;
    let artifact = cert
        .artifacts
        .first()
        .ok_or(TensorRuntimeError::MissingArtifact)?;
    verify_artifact_manifest_for(&cert, ent_path, artifact, manifest_path)
}

pub fn verify_witness(ent_path: &Path, witness_path: &Path) -> Result<WitnessVerificationReport> {
    let cert = load_verified_certificate(ent_path)?;
    let witness_contract = cert
        .witnesses
        .first()
        .ok_or(TensorRuntimeError::MissingWitness)?;
    let artifact = find_artifact(&cert, &witness_contract.artifact)?;
    let lowering = find_lowering(&cert, &witness_contract.lowering)?;
    let executor = find_executor(&cert, &witness_contract.executor)?;
    let training = find_training(&cert, &witness_contract.training)?;
    let model = find_model(&cert, &training.model)?;

    verify_artifact_manifest_for(&cert, ent_path, artifact, None)?;

    let witness_bytes = fs::read(witness_path)
        .with_context(|| format!("failed to read witness {}", witness_path.display()))?;
    let witness: RuntimeWitness =
        serde_json::from_slice(&witness_bytes).context("failed to parse runtime witness")?;
    require_equal("schema", "ent.runtime-witness.v1", &witness.schema)?;
    let expected_trace_ops = expected_lowered_trace(model, lowering)?;

    require_equal("training", &witness_contract.training, &witness.training)?;
    require_equal("artifact", &witness_contract.artifact, &witness.artifact)?;
    require_equal("lowering", &witness_contract.lowering, &witness.lowering)?;
    require_equal("executor", &witness_contract.executor, &witness.executor)?;
    require_equal(
        "training.artifact",
        &artifact.name,
        training.artifact.as_deref().unwrap_or_default(),
    )?;
    require_equal(
        "dataset_digest",
        &artifact.digest,
        &witness.observed.dataset_digest,
    )?;
    require_equal(
        "optimizer",
        &training.optimizer,
        &witness.observed.optimizer,
    )?;
    require_equal(
        "learning_rate",
        &canonical_f64(training.learning_rate),
        &canonical_f64(witness.observed.learning_rate),
    )?;
    require_equal(
        "steps",
        &training.steps.to_string(),
        &witness.observed.steps.to_string(),
    )?;
    require_equal(
        "batch",
        &training.batch.to_string(),
        &witness.observed.batch.to_string(),
    )?;
    require_equal("device", &executor.device, &witness.observed.device)?;
    require_equal(
        "network_access",
        &executor.network,
        &witness.observed.network_access,
    )?;
    require_equal(
        "seed",
        &executor.seed.to_string(),
        &witness.observed.seed.to_string(),
    )?;
    if witness.observed.trace_ops != expected_trace_ops {
        return Err(TensorRuntimeError::WitnessMismatch {
            field: "trace_ops",
            expected: expected_trace_ops.join(","),
            actual: witness.observed.trace_ops.join(","),
        }
        .into());
    }
    for requirement in &witness_contract.requirements {
        if !evaluate_requirement(requirement, &witness.metrics)? {
            return Err(TensorRuntimeError::WitnessRequirementFailed(requirement.clone()).into());
        }
    }

    Ok(WitnessVerificationReport {
        world: cert.world.clone(),
        witness: witness_contract.name.clone(),
        training: training.name.clone(),
        artifact: artifact.name.clone(),
        lowering: lowering.name.clone(),
        executor: executor.name.clone(),
        dataset_digest: artifact.digest.clone(),
        trace_ops: expected_trace_ops,
        requirements: witness_contract.requirements.clone(),
    })
}

pub fn generate_python_binding(
    ent_path: &Path,
    output: &Path,
    framework: &str,
) -> Result<BindingReport> {
    let cert = load_verified_certificate(ent_path)?;
    let witness = cert
        .witnesses
        .first()
        .ok_or(TensorRuntimeError::MissingWitness)?;
    let artifact = find_artifact(&cert, &witness.artifact)?;
    let lowering = find_lowering(&cert, &witness.lowering)?;
    let executor = find_executor(&cert, &witness.executor)?;
    let training = find_training(&cert, &witness.training)?;
    let model = find_model(&cert, &training.model)?;
    if lowering.framework != framework {
        return Err(TensorRuntimeError::WitnessMismatch {
            field: "framework",
            expected: lowering.framework.clone(),
            actual: framework.to_owned(),
        }
        .into());
    }
    let tensor_specs = binding_tensor_specs(&cert, artifact)?;
    let expected_trace_ops = expected_lowered_trace(model, lowering)?;
    let module = python_binding_module(
        &cert,
        artifact,
        lowering,
        executor,
        training,
        witness,
        &tensor_specs,
        &expected_trace_ops,
    )?;
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create binding dir {}", parent.display()))?;
    }
    fs::write(output, module)
        .with_context(|| format!("failed to write binding {}", output.display()))?;
    Ok(BindingReport {
        world: cert.world.clone(),
        artifact: artifact.name.clone(),
        training: training.name.clone(),
        lowering: lowering.name.clone(),
        executor: executor.name.clone(),
        framework: framework.to_owned(),
        output: output.to_path_buf(),
        expected_digest: artifact.digest.clone(),
    })
}

fn load_verified_certificate(path: &Path) -> Result<Certificate> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read tensor source {}", path.display()))?;
    let cert = elaborate_source(&source).context("tensor source failed to elaborate")?;
    verify(&cert).context("tensor certificate rejected by kernel")?;
    Ok(cert)
}

fn verify_artifact_manifest_for(
    cert: &Certificate,
    ent_path: &Path,
    artifact: &ArtifactContract,
    manifest_path: Option<&Path>,
) -> Result<ArtifactVerificationReport> {
    let manifest_path = manifest_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| resolve_ent_relative(ent_path, &artifact.manifest));
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("failed to read manifest {}", manifest_path.display()))?;
    let manifest: TensorManifest =
        serde_json::from_slice(&manifest_bytes).context("failed to parse tensor manifest")?;
    if manifest.schema != "ent.tensor-manifest.v1" {
        return Err(TensorRuntimeError::ManifestTensorMismatch {
            name: artifact.name.clone(),
            field: "schema",
            expected: "ent.tensor-manifest.v1".to_owned(),
            actual: manifest.schema.clone(),
        }
        .into());
    }
    if manifest.canonical != artifact.canonical {
        return Err(TensorRuntimeError::ManifestTensorMismatch {
            name: artifact.name.clone(),
            field: "canonical",
            expected: artifact.canonical.clone(),
            actual: manifest.canonical.clone(),
        }
        .into());
    }
    let actual_digest = sha256_uri(&canonical_json_bytes(&manifest)?);
    if actual_digest != artifact.digest {
        return Err(TensorRuntimeError::ArtifactDigestMismatch {
            name: artifact.name.clone(),
            expected: artifact.digest.clone(),
            actual: actual_digest,
        }
        .into());
    }

    let tensors = cert
        .tensors
        .iter()
        .map(|tensor| (tensor.name.as_str(), tensor))
        .collect::<BTreeMap<_, _>>();
    let mut checks = Vec::with_capacity(artifact.tensors.len());
    for name in &artifact.tensors {
        let contract = tensors
            .get(name.as_str())
            .ok_or_else(|| TensorRuntimeError::MissingTensor(name.clone()))?;
        let entry = manifest
            .tensors
            .get(name)
            .ok_or_else(|| TensorRuntimeError::ManifestMissingTensor(name.clone()))?;
        let expected_shape = concrete_shape(contract)?;
        if entry.shape != expected_shape {
            return Err(TensorRuntimeError::ManifestTensorMismatch {
                name: name.clone(),
                field: "shape",
                expected: format!("{expected_shape:?}"),
                actual: format!("{:?}", entry.shape),
            }
            .into());
        }
        if entry.dtype != contract.dtype {
            return Err(TensorRuntimeError::ManifestTensorMismatch {
                name: name.clone(),
                field: "dtype",
                expected: contract.dtype.clone(),
                actual: entry.dtype.clone(),
            }
            .into());
        }
        if entry.layout != contract.layout {
            return Err(TensorRuntimeError::ManifestTensorMismatch {
                name: name.clone(),
                field: "layout",
                expected: contract.layout.clone(),
                actual: entry.layout.clone(),
            }
            .into());
        }
        if !valid_sha256_uri(&entry.sha256) {
            return Err(TensorRuntimeError::ManifestTensorMismatch {
                name: name.clone(),
                field: "sha256",
                expected: "sha256:<digest>".to_owned(),
                actual: entry.sha256.clone(),
            }
            .into());
        }
        checks.push(TensorManifestCheck {
            name: name.clone(),
            shape: entry.shape.clone(),
            dtype: entry.dtype.clone(),
            layout: entry.layout.clone(),
            tensor_digest: entry.sha256.clone(),
        });
    }

    Ok(ArtifactVerificationReport {
        world: cert.world.clone(),
        artifact: artifact.name.clone(),
        manifest: manifest_path.display().to_string(),
        canonical: manifest.canonical,
        expected_digest: artifact.digest.clone(),
        actual_digest,
        tensors: checks,
    })
}

fn binding_tensor_specs(
    cert: &Certificate,
    artifact: &ArtifactContract,
) -> Result<BTreeMap<String, TensorManifestEntry>> {
    let tensors = cert
        .tensors
        .iter()
        .map(|tensor| (tensor.name.as_str(), tensor))
        .collect::<BTreeMap<_, _>>();
    artifact
        .tensors
        .iter()
        .map(|name| {
            let tensor = tensors
                .get(name.as_str())
                .ok_or_else(|| TensorRuntimeError::MissingTensor(name.clone()))?;
            Ok((
                name.clone(),
                TensorManifestEntry {
                    shape: concrete_shape(tensor)?,
                    dtype: tensor.dtype.clone(),
                    layout: tensor.layout.clone(),
                    sha256: String::new(),
                },
            ))
        })
        .collect()
}

fn expected_lowered_trace(
    model: &ModelContract,
    lowering: &LoweringContract,
) -> Result<Vec<String>> {
    let mapping = lowering
        .mappings
        .iter()
        .map(|row| {
            let (op, targets) = row
                .split_once('=')
                .ok_or_else(|| TensorRuntimeError::MalformedOp(row.clone()))?;
            let targets = targets
                .split('+')
                .map(str::trim)
                .filter(|target| !target.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            Ok((op.trim().to_owned(), targets))
        })
        .collect::<Result<BTreeMap<_, _>, TensorRuntimeError>>()?;
    let mut trace = Vec::new();
    for op in &model.ops {
        let parsed = ParsedOp::parse(op)?;
        let Some(targets) = mapping.get(&parsed.name) else {
            return Err(TensorRuntimeError::UnsupportedOp(parsed.name).into());
        };
        trace.extend(targets.iter().cloned());
    }
    Ok(trace)
}

fn python_binding_module(
    cert: &Certificate,
    artifact: &ArtifactContract,
    lowering: &LoweringContract,
    executor: &ExecutorContract,
    training: &TrainingContract,
    witness: &ent_core::WitnessContract,
    tensor_specs: &BTreeMap<String, TensorManifestEntry>,
    expected_trace_ops: &[String],
) -> Result<String> {
    let constants = serde_json::json!({
        "world": &cert.world,
        "artifact": &artifact.name,
        "artifact_digest": &artifact.digest,
        "canonical": &artifact.canonical,
        "tensor_specs": tensor_specs,
        "training": {
            "name": &training.name,
            "optimizer": &training.optimizer,
            "learning_rate": training.learning_rate,
            "steps": training.steps,
            "batch": training.batch,
        },
        "lowering": {
            "name": &lowering.name,
            "framework": &lowering.framework,
            "trace_ops": expected_trace_ops,
            "tolerance": lowering.tolerance,
        },
        "executor": {
            "name": &executor.name,
            "device": &executor.device,
            "network_access": &executor.network,
            "seed": executor.seed,
            "deterministic": executor.deterministic,
        },
        "witness": {
            "name": &witness.name,
            "requirements": &witness.requirements,
        },
    });
    let constants = serde_json::to_string_pretty(&constants)?;
    let mut module = String::new();
    module.push_str(
        r#"# Generated by entc bind. Do not edit by hand.
import hashlib
import json
from pathlib import Path

CONTRACT = "#,
    );
    module.push_str(&constants);
    module.push_str(
        r#"


def _canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_uri(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _array_bytes(value):
    if hasattr(value, "detach"):
        value = value.detach().cpu().contiguous().numpy()
    if hasattr(value, "tobytes"):
        return value.tobytes()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _shape(value):
    if hasattr(value, "detach"):
        value = value.detach().cpu().contiguous().numpy()
    if hasattr(value, "shape"):
        return [int(dim) for dim in value.shape]
    if isinstance(value, (list, tuple)):
        rows = len(value)
        if rows and isinstance(value[0], (list, tuple)):
            return [rows, len(value[0])]
        return [rows]
    return []


def tensor_digest(value, dtype, layout):
    payload = {
        "schema": "ent.tensor-digest.v1",
        "shape": _shape(value),
        "dtype": dtype,
        "layout": layout,
        "data_hex": _array_bytes(value).hex(),
    }
    return _sha256_uri(_canonical_bytes(payload))


class ContractSession:
    def __init__(self):
        self._bound = {}
        self._manifest = None

    def bind_tensors(self, **tensors):
        entries = {}
        for name, spec in CONTRACT["tensor_specs"].items():
            if name not in tensors:
                raise RuntimeError(f"missing tensor binding: {name}")
            value = tensors[name]
            shape = _shape(value)
            if shape != spec["shape"]:
                raise RuntimeError(
                    f"shape mismatch for {name}: expected {spec['shape']}, got {shape}"
                )
            entries[name] = {
                "shape": shape,
                "dtype": spec["dtype"],
                "layout": spec["layout"],
                "sha256": tensor_digest(value, spec["dtype"], spec["layout"]),
            }
            self._bound[name] = value
        manifest = {
            "schema": "ent.tensor-manifest.v1",
            "canonical": CONTRACT["canonical"],
            "tensors": entries,
        }
        digest = _sha256_uri(_canonical_bytes(manifest))
        if digest != CONTRACT["artifact_digest"]:
            raise RuntimeError(
                "artifact manifest digest mismatch:\n"
                f"expected: {CONTRACT['artifact_digest']}\n"
                f"actual:   {digest}"
            )
        self._manifest = manifest
        return manifest

    def tensor(self, name):
        if name not in self._bound:
            raise RuntimeError(f"tensor is not bound: {name}")
        return self._bound[name]

    def assert_trace(self, trace_ops):
        trace_ops = list(trace_ops)
        expected = CONTRACT["lowering"]["trace_ops"]
        if trace_ops != expected:
            raise RuntimeError(f"trace mismatch: expected {expected}, got {trace_ops}")
        return trace_ops

    def seal_witness(self, metrics, trace_ops, output):
        trace_ops = self.assert_trace(trace_ops)
        witness = {
            "schema": "ent.runtime-witness.v1",
            "training": CONTRACT["training"]["name"],
            "artifact": CONTRACT["artifact"],
            "lowering": CONTRACT["lowering"]["name"],
            "executor": CONTRACT["executor"]["name"],
            "observed": {
                "dataset_digest": CONTRACT["artifact_digest"],
                "trace_ops": trace_ops,
                "optimizer": CONTRACT["training"]["optimizer"],
                "learning_rate": CONTRACT["training"]["learning_rate"],
                "steps": CONTRACT["training"]["steps"],
                "batch": CONTRACT["training"]["batch"],
                "device": CONTRACT["executor"]["device"],
                "network_access": CONTRACT["executor"]["network_access"],
                "seed": CONTRACT["executor"]["seed"],
            },
            "metrics": dict(metrics),
        }
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(witness, sort_keys=True, indent=2) + "\n")
        return witness


def open_contract():
    return ContractSession()
"#,
    );
    Ok(module)
}

fn find_training<'a>(cert: &'a Certificate, name: &str) -> Result<&'a TrainingContract> {
    cert.trainings
        .iter()
        .find(|training| training.name == name)
        .ok_or_else(|| TensorRuntimeError::MissingTraining.into())
}

fn find_model<'a>(cert: &'a Certificate, name: &str) -> Result<&'a ModelContract> {
    cert.models
        .iter()
        .find(|model| model.name == name)
        .ok_or_else(|| TensorRuntimeError::MissingModel(name.to_owned()).into())
}

fn find_artifact<'a>(cert: &'a Certificate, name: &str) -> Result<&'a ArtifactContract> {
    cert.artifacts
        .iter()
        .find(|artifact| artifact.name == name)
        .ok_or_else(|| TensorRuntimeError::MissingArtifact.into())
}

fn find_lowering<'a>(cert: &'a Certificate, name: &str) -> Result<&'a LoweringContract> {
    cert.lowerings
        .iter()
        .find(|lowering| lowering.name == name)
        .ok_or_else(|| TensorRuntimeError::MissingLowering.into())
}

fn find_executor<'a>(cert: &'a Certificate, name: &str) -> Result<&'a ExecutorContract> {
    cert.executors
        .iter()
        .find(|executor| executor.name == name)
        .ok_or_else(|| TensorRuntimeError::MissingExecutor.into())
}

fn resolve_ent_relative(ent_path: &Path, relative: &str) -> PathBuf {
    ent_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(relative)
}

fn concrete_shape(tensor: &TensorContract) -> Result<Vec<usize>> {
    tensor
        .shape
        .iter()
        .map(|dim| {
            dim.parse::<usize>()
                .map_err(|_| TensorRuntimeError::SymbolicRuntimeShape(tensor.name.clone()).into())
        })
        .collect()
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&value)?)
}

fn require_equal(field: &'static str, expected: &str, actual: &str) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(TensorRuntimeError::WitnessMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        }
        .into())
    }
}

fn canonical_f64(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.1}")
    } else {
        value.to_string()
    }
}

fn evaluate_requirement(requirement: &str, metrics: &BTreeMap<String, f64>) -> Result<bool> {
    let (metric, op, expected) = parse_requirement(requirement)
        .ok_or_else(|| TensorRuntimeError::MalformedRequirement(requirement.to_owned()))?;
    let actual = metrics
        .get(metric)
        .ok_or_else(|| TensorRuntimeError::WitnessRequirementFailed(requirement.to_owned()))?;
    Ok(match op {
        "<=" => *actual <= expected,
        "<" => *actual < expected,
        ">=" => *actual >= expected,
        ">" => *actual > expected,
        "==" => (*actual - expected).abs() <= f64::EPSILON,
        _ => false,
    })
}

fn parse_requirement(requirement: &str) -> Option<(&str, &str, f64)> {
    for op in ["<=", ">=", "==", "<", ">"] {
        if let Some((metric, value)) = requirement.split_once(op) {
            let metric = metric.trim();
            let value = value.trim().parse::<f64>().ok()?;
            if metric
                .split('.')
                .all(|part| !part.is_empty() && valid_binding_name(part))
                && value.is_finite()
            {
                return Some((metric, op, value));
            }
        }
    }
    None
}

fn valid_binding_name(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch == '-' || ch.is_ascii_alphanumeric())
}

fn valid_sha256_uri(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit())
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
