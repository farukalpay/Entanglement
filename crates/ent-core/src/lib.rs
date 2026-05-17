pub use ent_proof::{ProofCertificate, ProofScript, Proposition, PropositionKind};
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const CERTIFICATE_SCHEMA_VERSION: u32 = 6;
pub const MIN_CERTIFICATE_SCHEMA_VERSION: u32 = 3;
pub const MAX_MODAL_DIMENSIONS: usize = 12;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorldId(pub String);

pub type StateId = WorldId;

impl From<&str> for WorldId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for WorldId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for WorldId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramState {
    pub name: String,
    pub sort: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Label {
    pub members: Vec<String>,
}

impl Label {
    pub fn new<I, S>(members: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut set = IndexSet::new();
        for member in members {
            set.insert(member.into());
        }
        let mut members: Vec<_> = set.into_iter().collect();
        members.sort();
        Self { members }
    }

    pub fn empty() -> Self {
        Self { members: vec![] }
    }

    pub fn grand(dimensions: &[String]) -> Self {
        Self::new(dimensions.iter().cloned())
    }

    pub fn powerset(dimensions: &[String]) -> Vec<Self> {
        let mut dims = dimensions.to_vec();
        dims.sort();
        dims.dedup();
        let count = 1usize << dims.len();
        let mut labels = Vec::with_capacity(count);
        for mask in 0..count {
            let members = dims
                .iter()
                .enumerate()
                .filter(|(idx, _)| (mask & (1usize << idx)) != 0)
                .map(|(_, dim)| dim.clone())
                .collect::<Vec<_>>();
            labels.push(Self { members });
        }
        labels.sort();
        labels
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.members
            .iter()
            .all(|member| other.members.contains(member))
    }

    pub fn union(&self, other: &Self) -> Self {
        Self::new(self.members.iter().chain(other.members.iter()).cloned())
    }

    pub fn complement(&self, dimensions: &[String]) -> Self {
        Self::new(
            dimensions
                .iter()
                .filter(|dimension| !self.members.contains(dimension))
                .cloned(),
        )
    }

    pub fn display_name(&self) -> String {
        if self.members.is_empty() {
            "empty".to_owned()
        } else {
            self.members.join("+")
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KernelFormula {
    Atom(String),
    Not(Box<KernelFormula>),
    And(Box<KernelFormula>, Box<KernelFormula>),
    Box(Label, Box<KernelFormula>),
    Diamond(Label, Box<KernelFormula>),
}

impl KernelFormula {
    pub fn atom(value: impl Into<String>) -> Self {
        Self::Atom(value.into())
    }
}

impl fmt::Display for KernelFormula {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelFormula::Atom(atom) => f.write_str(atom),
            KernelFormula::Not(inner) => write!(f, "!({inner})"),
            KernelFormula::And(left, right) => write!(f, "({left} & {right})"),
            KernelFormula::Box(label, body) => write!(f, "[{}]{body}", label.display_name()),
            KernelFormula::Diamond(label, body) => write!(f, "<{}>{body}", label.display_name()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationTable {
    pub label: Label,
    pub pairs: Vec<(StateId, StateId)>,
}

impl RelationTable {
    pub fn new(label: Label, pairs: Vec<(StateId, StateId)>) -> Self {
        Self { label, pairs }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactorWitness {
    pub left: Label,
    pub right: Label,
    pub from: StateId,
    pub midpoint: StateId,
    pub to: StateId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiamondWitness {
    pub state: StateId,
    pub label: Label,
    pub body: KernelFormula,
    pub target: StateId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvariantContract {
    pub name: String,
    pub before: f64,
    pub after: f64,
    pub tolerance: f64,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceAccess {
    Read,
    Write,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceContract {
    pub name: String,
    pub state: StateId,
    pub access: ResourceAccess,
    pub owner: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalContract {
    pub name: String,
    pub interface: String,
    pub state: StateId,
    pub resource: String,
    pub access: ResourceAccess,
    pub admissible: bool,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceContract {
    pub name: String,
    pub boundary: String,
    pub access: ResourceAccess,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserContract {
    pub name: String,
    pub language: String,
    pub adapter: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionContract {
    pub name: String,
    pub predicate: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformTarget {
    Selection(String),
    File(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextReplacement {
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformContract {
    pub name: String,
    pub operation: String,
    pub target: TransformTarget,
    pub destination: Option<String>,
    pub predicate: Option<String>,
    pub replacement: Option<TextReplacement>,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorContract {
    pub name: String,
    pub argv: Vec<String>,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphicContract {
    pub name: String,
    pub entry: String,
    pub source_digest: String,
    pub imports: Vec<String>,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderTargetContract {
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderPipelineContract {
    pub name: String,
    pub graphics: String,
    pub target: String,
    pub entry: String,
    pub mode: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkContract {
    pub name: String,
    pub graphics: String,
    pub entry: String,
    pub warmup: u32,
    pub iterations: u32,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorContract {
    pub name: String,
    pub shape: Vec<String>,
    pub dtype: String,
    pub gradient: String,
    pub layout: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceleratorContract {
    pub name: String,
    pub kind: String,
    pub memory: String,
    pub precision: String,
    pub supports: Vec<String>,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetContract {
    pub name: String,
    pub tensors: Vec<String>,
    pub source: String,
    pub source_digest: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelContract {
    pub name: String,
    pub entry: String,
    pub inputs: Vec<String>,
    pub parameters: Vec<String>,
    pub outputs: Vec<String>,
    pub ops: Vec<String>,
    pub loss: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrainingContract {
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
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbabilityContract {
    pub name: String,
    pub state: StateId,
    pub weights: Vec<(String, f64)>,
    pub tolerance: f64,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdContract {
    pub primal: String,
    pub tangent: String,
    pub adjoint: String,
    pub law: String,
    pub evidence: String,
}

impl AdContract {
    pub fn identity(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            primal: name.clone(),
            tangent: format!("d_{name}"),
            adjoint: format!("adj_{name}"),
            law: "identity".to_owned(),
            evidence: "identity-ad-contract".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    Cpu,
    Metal,
    PrivateAne,
    Capability(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendContract {
    pub node: String,
    pub backend: BackendKind,
    pub admissible: bool,
    pub evidence: String,
}

impl BackendContract {
    pub fn cpu(node: impl Into<String>) -> Self {
        Self {
            node: node.into(),
            backend: BackendKind::Cpu,
            admissible: true,
            evidence: "cpu-executable".to_owned(),
        }
    }

    pub fn metal(node: impl Into<String>) -> Self {
        Self {
            node: node.into(),
            backend: BackendKind::Metal,
            admissible: true,
            evidence: "metal-shader-emittable".to_owned(),
        }
    }

    pub fn private_ane(
        node: impl Into<String>,
        admissible: bool,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            node: node.into(),
            backend: BackendKind::PrivateAne,
            admissible,
            evidence: evidence.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MachineMemoryModel {
    Sequential,
    RiscvRvwmo,
    RiscvTso,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineContract {
    pub id: String,
    pub isa: String,
    pub profile: String,
    pub word_bits: u32,
    pub endianness: Endianness,
    pub memory_model: MachineMemoryModel,
    pub semantic_source: String,
    pub source_digest: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryPermission {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub permissions: Vec<MemoryPermission>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryContract {
    pub name: String,
    pub machine: String,
    pub address_bits: u32,
    pub ordering: MachineMemoryModel,
    pub regions: Vec<MemoryRegion>,
    pub frame_conditions: Vec<String>,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionContract {
    pub name: String,
    pub machine: String,
    pub mnemonic: String,
    pub encoding: String,
    pub semantics: String,
    pub effects: Vec<String>,
    pub proof_artifact: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiContract {
    pub name: String,
    pub machine: String,
    pub target_triple: String,
    pub object_format: String,
    pub calling_convention: String,
    pub external_policy: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProverKind {
    Rocq,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub name: String,
    pub prover: ProverKind,
    pub module: String,
    pub digest: String,
    pub obligations: Vec<String>,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Certificate {
    pub version: u32,
    pub world: String,
    pub dimensions: Vec<String>,
    pub program_states: Vec<ProgramState>,
    pub modal_worlds: Vec<StateId>,
    pub root_world: StateId,
    pub formula: KernelFormula,
    pub closure: Vec<KernelFormula>,
    pub types: Vec<(StateId, Vec<KernelFormula>)>,
    pub relation_names: Vec<String>,
    pub relations: Vec<RelationTable>,
    pub factors: Vec<FactorWitness>,
    pub diamonds: Vec<DiamondWitness>,
    pub invariants: Vec<InvariantContract>,
    pub resources: Vec<ResourceContract>,
    pub probabilities: Vec<ProbabilityContract>,
    pub ad: Vec<AdContract>,
    pub backends: Vec<BackendContract>,
    #[serde(default)]
    pub external_capabilities: Vec<ExternalContract>,
    #[serde(default)]
    pub workspaces: Vec<WorkspaceContract>,
    #[serde(default)]
    pub parsers: Vec<ParserContract>,
    #[serde(default)]
    pub selections: Vec<SelectionContract>,
    #[serde(default)]
    pub transforms: Vec<TransformContract>,
    #[serde(default)]
    pub validators: Vec<ValidatorContract>,
    #[serde(default)]
    pub graphics: Vec<GraphicContract>,
    #[serde(default)]
    pub render_targets: Vec<RenderTargetContract>,
    #[serde(default)]
    pub render_pipelines: Vec<RenderPipelineContract>,
    #[serde(default)]
    pub benchmarks: Vec<BenchmarkContract>,
    #[serde(default)]
    pub tensors: Vec<TensorContract>,
    #[serde(default)]
    pub accelerators: Vec<AcceleratorContract>,
    #[serde(default)]
    pub datasets: Vec<DatasetContract>,
    #[serde(default)]
    pub models: Vec<ModelContract>,
    #[serde(default)]
    pub trainings: Vec<TrainingContract>,
    #[serde(default)]
    pub machines: Vec<MachineContract>,
    #[serde(default)]
    pub memory: Vec<MemoryContract>,
    #[serde(default)]
    pub instructions: Vec<InstructionContract>,
    #[serde(default)]
    pub abis: Vec<AbiContract>,
    #[serde(default)]
    pub proof_artifacts: Vec<ProofArtifact>,
    pub proofs: Vec<ProofCertificate>,
    pub require_coordinate_separation: bool,
    pub public_survivors: Option<Vec<StateId>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckedRows {
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
    pub graphics: usize,
    pub render_targets: usize,
    pub render_pipelines: usize,
    pub benchmarks: usize,
    pub tensors: usize,
    pub accelerators: usize,
    pub datasets: usize,
    pub models: usize,
    pub trainings: usize,
    pub machines: usize,
    pub memory: usize,
    pub instructions: usize,
    pub abis: usize,
    pub proof_artifacts: usize,
    pub proofs: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstabilityKind {
    UnsupportedVersion,
    EvidenceMissing,
    BadRelation,
    MissingMidpoint,
    ModalTruthMismatch,
    DiamondWitnessInvalid,
    FactorClosureFailure,
    CoordinateSeparationFailure,
    InvariantDrift,
    ResourceConflict,
    ProbabilityDrift,
    AdContractViolation,
    BackendInadmissible,
    ExternalInadmissible,
    WorkspaceInadmissible,
    ParserInadmissible,
    SelectionInadmissible,
    TransformInadmissible,
    ValidatorInadmissible,
    GraphicsInadmissible,
    RenderTargetInadmissible,
    RenderPipelineInadmissible,
    BenchmarkInadmissible,
    TensorInadmissible,
    AcceleratorInadmissible,
    DatasetInadmissible,
    ModelInadmissible,
    TrainingInadmissible,
    MachineInadmissible,
    MemoryInadmissible,
    InstructionInadmissible,
    AbiInadmissible,
    ProofArtifactInadmissible,
    ProofGap,
    RootFormulaMissing,
    UnknownReference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instability {
    pub kind: InstabilityKind,
    pub message: String,
    pub evidence: Vec<String>,
}

impl Instability {
    pub fn new(kind: InstabilityKind, message: impl Into<String>, evidence: Vec<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            evidence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub world: String,
    pub checked_rows: CheckedRows,
    pub instabilities: Vec<Instability>,
}
