use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PropositionKind {
    DevFrame,
    ResourceLinear,
    ProbabilityNormalizes,
    InvariantPreserved,
    BackendAdmissible,
    ExternalAdmissible,
    MachineAdmissible,
    MemoryAdmissible,
    InstructionRefines,
    AbiAdmissible,
    ProofArtifactChecked,
    ParserAdmissible,
    SelectionAdmissible,
    TransformAdmissible,
    ValidatorAdmissible,
    ObjectiveAdmissible,
    MilestoneAdmissible,
    TaskAdmissible,
    GateAdmissible,
    DecisionAdmissible,
    NoteAdmissible,
    LaneAdmissible,
    ClaimAdmissible,
    HandoffAdmissible,
    SyncAdmissible,
    CheckpointAdmissible,
    RuntimeLedgerAdmissible,
    RuntimePolicyAdmissible,
    RuntimeSessionAdmissible,
    RuntimeToolAdmissible,
    RuntimeTurnAdmissible,
    RuntimeHookAdmissible,
    RuntimeBridgeAdmissible,
    GraphicsAdmissible,
    RenderTargetAdmissible,
    RenderPipelineAdmissible,
    BenchmarkAdmissible,
    TensorAdmissible,
    AcceleratorAdmissible,
    DatasetAdmissible,
    ModelAdmissible,
    TrainingAdmissible,
    CanonicalAdmissible,
    ArtifactBound,
    LoweringAdmissible,
    ExecutorConfined,
    WitnessSatisfies,
    TraceEquivalent,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Proposition {
    pub kind: PropositionKind,
    pub subject: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RowKind {
    Relation,
    Resource,
    Probability,
    Invariant,
    Backend,
    External,
    Machine,
    Memory,
    Instruction,
    Abi,
    ProofArtifact,
    Parser,
    Selection,
    Transform,
    Validator,
    Objective,
    Milestone,
    Task,
    Gate,
    Decision,
    Note,
    Lane,
    Claim,
    Handoff,
    Sync,
    Checkpoint,
    RuntimeLedger,
    RuntimePolicy,
    RuntimeSession,
    RuntimeTool,
    RuntimeTurn,
    RuntimeHook,
    RuntimeBridge,
    Graphics,
    RenderTarget,
    RenderPipeline,
    Benchmark,
    Tensor,
    Accelerator,
    Dataset,
    Model,
    Training,
    Canonical,
    Artifact,
    Lowering,
    Executor,
    Witness,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrimitiveRule {
    DevFrameFromRelation,
    ResourceLinearFromResource,
    ProbabilityNormalizesFromProbability,
    InvariantPreservedFromInvariant,
    BackendAdmissibleFromBackend,
    ExternalAdmissibleFromExternal,
    MachineAdmissibleFromMachine,
    MemoryAdmissibleFromMemory,
    InstructionRefinesFromInstruction,
    AbiAdmissibleFromAbi,
    ProofArtifactCheckedFromArtifact,
    ParserAdmissibleFromParser,
    SelectionAdmissibleFromSelection,
    TransformAdmissibleFromTransform,
    ValidatorAdmissibleFromValidator,
    ObjectiveAdmissibleFromObjective,
    MilestoneAdmissibleFromMilestone,
    TaskAdmissibleFromTask,
    GateAdmissibleFromGate,
    DecisionAdmissibleFromDecision,
    NoteAdmissibleFromNote,
    LaneAdmissibleFromLane,
    ClaimAdmissibleFromClaim,
    HandoffAdmissibleFromHandoff,
    SyncAdmissibleFromSync,
    CheckpointAdmissibleFromCheckpoint,
    RuntimeLedgerAdmissibleFromRuntimeLedger,
    RuntimePolicyAdmissibleFromRuntimePolicy,
    RuntimeSessionAdmissibleFromRuntimeSession,
    RuntimeToolAdmissibleFromRuntimeTool,
    RuntimeTurnAdmissibleFromRuntimeTurn,
    RuntimeHookAdmissibleFromRuntimeHook,
    RuntimeBridgeAdmissibleFromRuntimeBridge,
    GraphicsAdmissibleFromGraphics,
    RenderTargetAdmissibleFromRenderTarget,
    RenderPipelineAdmissibleFromRenderPipeline,
    BenchmarkAdmissibleFromBenchmark,
    TensorAdmissibleFromTensor,
    AcceleratorAdmissibleFromAccelerator,
    DatasetAdmissibleFromDataset,
    ModelAdmissibleFromModel,
    TrainingAdmissibleFromTraining,
    CanonicalAdmissibleFromCanonical,
    ArtifactBoundFromArtifact,
    LoweringAdmissibleFromLowering,
    ExecutorConfinedFromExecutor,
    WitnessSatisfiesContract,
    TraceEquivalent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofStatement {
    BindRow {
        name: String,
        kind: RowKind,
        subject: String,
    },
    ApplyRule {
        name: String,
        rule: PrimitiveRule,
        args: Vec<String>,
    },
    UseRocq {
        module: String,
    },
    Qed {
        value: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofScript {
    pub theorem: String,
    pub statements: Vec<ProofStatement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCertificate {
    pub name: String,
    pub proposition: Proposition,
    pub script: ProofScript,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofParseError {
    #[error("malformed proposition: {0}")]
    MalformedProposition(String),
    #[error("unknown proposition operator: {0}")]
    UnknownProposition(String),
    #[error("malformed proof statement: {0}")]
    MalformedStatement(String),
    #[error("unknown row kind: {0}")]
    UnknownRowKind(String),
    #[error("unknown primitive rule: {0}")]
    UnknownRule(String),
}

pub fn parse_proposition(input: &str) -> Result<Proposition, ProofParseError> {
    let open = input
        .find('(')
        .ok_or_else(|| ProofParseError::MalformedProposition(input.to_owned()))?;
    let close = input
        .rfind(')')
        .ok_or_else(|| ProofParseError::MalformedProposition(input.to_owned()))?;
    if close <= open || !input[close + 1..].trim().is_empty() {
        return Err(ProofParseError::MalformedProposition(input.to_owned()));
    }
    let operator = input[..open].trim();
    let subject = input[open + 1..close].trim();
    if subject.is_empty() {
        return Err(ProofParseError::MalformedProposition(input.to_owned()));
    }
    let kind = match operator {
        "dev_frame" => PropositionKind::DevFrame,
        "resource_linear" => PropositionKind::ResourceLinear,
        "probability_normalizes" => PropositionKind::ProbabilityNormalizes,
        "invariant_preserved" => PropositionKind::InvariantPreserved,
        "backend_admissible" => PropositionKind::BackendAdmissible,
        "external_admissible" => PropositionKind::ExternalAdmissible,
        "machine_admissible" => PropositionKind::MachineAdmissible,
        "memory_admissible" => PropositionKind::MemoryAdmissible,
        "instruction_refines" => PropositionKind::InstructionRefines,
        "abi_admissible" => PropositionKind::AbiAdmissible,
        "proof_artifact_checked" => PropositionKind::ProofArtifactChecked,
        "parser_admissible" => PropositionKind::ParserAdmissible,
        "selection_admissible" => PropositionKind::SelectionAdmissible,
        "transform_admissible" => PropositionKind::TransformAdmissible,
        "validator_admissible" => PropositionKind::ValidatorAdmissible,
        "objective_admissible" => PropositionKind::ObjectiveAdmissible,
        "milestone_admissible" => PropositionKind::MilestoneAdmissible,
        "task_admissible" => PropositionKind::TaskAdmissible,
        "gate_admissible" => PropositionKind::GateAdmissible,
        "decision_admissible" => PropositionKind::DecisionAdmissible,
        "note_admissible" => PropositionKind::NoteAdmissible,
        "lane_admissible" => PropositionKind::LaneAdmissible,
        "claim_admissible" => PropositionKind::ClaimAdmissible,
        "handoff_admissible" => PropositionKind::HandoffAdmissible,
        "sync_admissible" => PropositionKind::SyncAdmissible,
        "checkpoint_admissible" => PropositionKind::CheckpointAdmissible,
        "runtime_ledger_admissible" => PropositionKind::RuntimeLedgerAdmissible,
        "runtime_policy_admissible" => PropositionKind::RuntimePolicyAdmissible,
        "runtime_session_admissible" => PropositionKind::RuntimeSessionAdmissible,
        "runtime_tool_admissible" => PropositionKind::RuntimeToolAdmissible,
        "runtime_turn_admissible" => PropositionKind::RuntimeTurnAdmissible,
        "runtime_hook_admissible" => PropositionKind::RuntimeHookAdmissible,
        "runtime_bridge_admissible" => PropositionKind::RuntimeBridgeAdmissible,
        "graphics_admissible" => PropositionKind::GraphicsAdmissible,
        "render_target_admissible" => PropositionKind::RenderTargetAdmissible,
        "render_pipeline_admissible" => PropositionKind::RenderPipelineAdmissible,
        "benchmark_admissible" => PropositionKind::BenchmarkAdmissible,
        "tensor_admissible" => PropositionKind::TensorAdmissible,
        "accelerator_admissible" => PropositionKind::AcceleratorAdmissible,
        "dataset_admissible" => PropositionKind::DatasetAdmissible,
        "model_admissible" => PropositionKind::ModelAdmissible,
        "training_admissible" => PropositionKind::TrainingAdmissible,
        "canonical_admissible" => PropositionKind::CanonicalAdmissible,
        "artifact_bound" => PropositionKind::ArtifactBound,
        "lowering_admissible" => PropositionKind::LoweringAdmissible,
        "executor_confined" => PropositionKind::ExecutorConfined,
        "witness_satisfies" => PropositionKind::WitnessSatisfies,
        "trace_equivalent" => PropositionKind::TraceEquivalent,
        _ => return Err(ProofParseError::UnknownProposition(operator.to_owned())),
    };
    Ok(Proposition {
        kind,
        subject: subject.to_owned(),
    })
}

pub fn parse_script(theorem: &str, body: &str) -> Result<ProofScript, ProofParseError> {
    let mut statements = Vec::new();
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        statements.push(parse_statement(line)?);
    }
    Ok(ProofScript {
        theorem: theorem.to_owned(),
        statements,
    })
}

fn parse_statement(line: &str) -> Result<ProofStatement, ProofParseError> {
    if let Some(module) = line.strip_prefix("rocq module ") {
        return Ok(ProofStatement::UseRocq {
            module: parse_quoted(module.trim())
                .ok_or_else(|| ProofParseError::MalformedStatement(line.to_owned()))?,
        });
    }

    if let Some(value) = line.strip_prefix("qed ") {
        let value = value.trim();
        if value.is_empty() || value.split_whitespace().count() != 1 {
            return Err(ProofParseError::MalformedStatement(line.to_owned()));
        }
        return Ok(ProofStatement::Qed {
            value: value.to_owned(),
        });
    }

    let Some(rest) = line.strip_prefix("let ") else {
        return Err(ProofParseError::MalformedStatement(line.to_owned()));
    };
    let (name, expr) = rest
        .split_once(" = ")
        .ok_or_else(|| ProofParseError::MalformedStatement(line.to_owned()))?;
    let name = name.trim();
    if name.is_empty() || name.split_whitespace().count() != 1 {
        return Err(ProofParseError::MalformedStatement(line.to_owned()));
    }

    if let Some(row) = expr.strip_prefix("row ") {
        let mut words = row.split_whitespace();
        let kind = words
            .next()
            .ok_or_else(|| ProofParseError::MalformedStatement(line.to_owned()))
            .and_then(parse_row_kind)?;
        let subject = words
            .next()
            .ok_or_else(|| ProofParseError::MalformedStatement(line.to_owned()))?;
        if words.next().is_some() {
            return Err(ProofParseError::MalformedStatement(line.to_owned()));
        }
        return Ok(ProofStatement::BindRow {
            name: name.to_owned(),
            kind,
            subject: subject.to_owned(),
        });
    }

    if let Some(rule) = expr.strip_prefix("rule ") {
        let open = rule
            .find('(')
            .ok_or_else(|| ProofParseError::MalformedStatement(line.to_owned()))?;
        let close = rule
            .rfind(')')
            .ok_or_else(|| ProofParseError::MalformedStatement(line.to_owned()))?;
        if close <= open || !rule[close + 1..].trim().is_empty() {
            return Err(ProofParseError::MalformedStatement(line.to_owned()));
        }
        let rule_name = rule[..open].trim();
        let args = rule[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|arg| !arg.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        return Ok(ProofStatement::ApplyRule {
            name: name.to_owned(),
            rule: parse_rule(rule_name)?,
            args,
        });
    }

    Err(ProofParseError::MalformedStatement(line.to_owned()))
}

fn parse_row_kind(input: &str) -> Result<RowKind, ProofParseError> {
    match input {
        "relation" => Ok(RowKind::Relation),
        "resource" => Ok(RowKind::Resource),
        "probability" => Ok(RowKind::Probability),
        "invariant" => Ok(RowKind::Invariant),
        "backend" => Ok(RowKind::Backend),
        "external" => Ok(RowKind::External),
        "machine" => Ok(RowKind::Machine),
        "memory" => Ok(RowKind::Memory),
        "instruction" => Ok(RowKind::Instruction),
        "abi" => Ok(RowKind::Abi),
        "proof-artifact" => Ok(RowKind::ProofArtifact),
        "parser" => Ok(RowKind::Parser),
        "selection" => Ok(RowKind::Selection),
        "transform" => Ok(RowKind::Transform),
        "validator" => Ok(RowKind::Validator),
        "objective" => Ok(RowKind::Objective),
        "milestone" => Ok(RowKind::Milestone),
        "task" => Ok(RowKind::Task),
        "gate" => Ok(RowKind::Gate),
        "decision" => Ok(RowKind::Decision),
        "note" => Ok(RowKind::Note),
        "lane" => Ok(RowKind::Lane),
        "claim" => Ok(RowKind::Claim),
        "handoff" => Ok(RowKind::Handoff),
        "sync" => Ok(RowKind::Sync),
        "checkpoint" => Ok(RowKind::Checkpoint),
        "runtime-ledger" => Ok(RowKind::RuntimeLedger),
        "runtime-policy" => Ok(RowKind::RuntimePolicy),
        "runtime-session" => Ok(RowKind::RuntimeSession),
        "runtime-tool" => Ok(RowKind::RuntimeTool),
        "runtime-turn" => Ok(RowKind::RuntimeTurn),
        "runtime-hook" => Ok(RowKind::RuntimeHook),
        "runtime-bridge" => Ok(RowKind::RuntimeBridge),
        "graphics" => Ok(RowKind::Graphics),
        "render-target" => Ok(RowKind::RenderTarget),
        "render-pipeline" => Ok(RowKind::RenderPipeline),
        "benchmark" => Ok(RowKind::Benchmark),
        "tensor" => Ok(RowKind::Tensor),
        "accelerator" => Ok(RowKind::Accelerator),
        "dataset" => Ok(RowKind::Dataset),
        "model" => Ok(RowKind::Model),
        "training" => Ok(RowKind::Training),
        "canonical" => Ok(RowKind::Canonical),
        "artifact" => Ok(RowKind::Artifact),
        "lowering" => Ok(RowKind::Lowering),
        "executor" => Ok(RowKind::Executor),
        "witness" => Ok(RowKind::Witness),
        _ => Err(ProofParseError::UnknownRowKind(input.to_owned())),
    }
}

fn parse_rule(input: &str) -> Result<PrimitiveRule, ProofParseError> {
    match input {
        "dev_frame_from_relation" => Ok(PrimitiveRule::DevFrameFromRelation),
        "resource_linear_from_resource" => Ok(PrimitiveRule::ResourceLinearFromResource),
        "probability_normalizes_from_probability" => {
            Ok(PrimitiveRule::ProbabilityNormalizesFromProbability)
        }
        "invariant_preserved_from_invariant" => Ok(PrimitiveRule::InvariantPreservedFromInvariant),
        "backend_admissible_from_backend" => Ok(PrimitiveRule::BackendAdmissibleFromBackend),
        "external_admissible_from_external" => Ok(PrimitiveRule::ExternalAdmissibleFromExternal),
        "machine_admissible_from_machine" => Ok(PrimitiveRule::MachineAdmissibleFromMachine),
        "memory_admissible_from_memory" => Ok(PrimitiveRule::MemoryAdmissibleFromMemory),
        "instruction_refines_from_instruction" => {
            Ok(PrimitiveRule::InstructionRefinesFromInstruction)
        }
        "abi_admissible_from_abi" => Ok(PrimitiveRule::AbiAdmissibleFromAbi),
        "proof_artifact_checked_from_artifact" => {
            Ok(PrimitiveRule::ProofArtifactCheckedFromArtifact)
        }
        "parser_admissible_from_parser" => Ok(PrimitiveRule::ParserAdmissibleFromParser),
        "selection_admissible_from_selection" => {
            Ok(PrimitiveRule::SelectionAdmissibleFromSelection)
        }
        "transform_admissible_from_transform" => {
            Ok(PrimitiveRule::TransformAdmissibleFromTransform)
        }
        "validator_admissible_from_validator" => {
            Ok(PrimitiveRule::ValidatorAdmissibleFromValidator)
        }
        "objective_admissible_from_objective" => {
            Ok(PrimitiveRule::ObjectiveAdmissibleFromObjective)
        }
        "milestone_admissible_from_milestone" => {
            Ok(PrimitiveRule::MilestoneAdmissibleFromMilestone)
        }
        "task_admissible_from_task" => Ok(PrimitiveRule::TaskAdmissibleFromTask),
        "gate_admissible_from_gate" => Ok(PrimitiveRule::GateAdmissibleFromGate),
        "decision_admissible_from_decision" => Ok(PrimitiveRule::DecisionAdmissibleFromDecision),
        "note_admissible_from_note" => Ok(PrimitiveRule::NoteAdmissibleFromNote),
        "lane_admissible_from_lane" => Ok(PrimitiveRule::LaneAdmissibleFromLane),
        "claim_admissible_from_claim" => Ok(PrimitiveRule::ClaimAdmissibleFromClaim),
        "handoff_admissible_from_handoff" => Ok(PrimitiveRule::HandoffAdmissibleFromHandoff),
        "sync_admissible_from_sync" => Ok(PrimitiveRule::SyncAdmissibleFromSync),
        "checkpoint_admissible_from_checkpoint" => {
            Ok(PrimitiveRule::CheckpointAdmissibleFromCheckpoint)
        }
        "runtime_ledger_admissible_from_runtime_ledger" => {
            Ok(PrimitiveRule::RuntimeLedgerAdmissibleFromRuntimeLedger)
        }
        "runtime_policy_admissible_from_runtime_policy" => {
            Ok(PrimitiveRule::RuntimePolicyAdmissibleFromRuntimePolicy)
        }
        "runtime_session_admissible_from_runtime_session" => {
            Ok(PrimitiveRule::RuntimeSessionAdmissibleFromRuntimeSession)
        }
        "runtime_tool_admissible_from_runtime_tool" => {
            Ok(PrimitiveRule::RuntimeToolAdmissibleFromRuntimeTool)
        }
        "runtime_turn_admissible_from_runtime_turn" => {
            Ok(PrimitiveRule::RuntimeTurnAdmissibleFromRuntimeTurn)
        }
        "runtime_hook_admissible_from_runtime_hook" => {
            Ok(PrimitiveRule::RuntimeHookAdmissibleFromRuntimeHook)
        }
        "runtime_bridge_admissible_from_runtime_bridge" => {
            Ok(PrimitiveRule::RuntimeBridgeAdmissibleFromRuntimeBridge)
        }
        "graphics_admissible_from_graphics" => Ok(PrimitiveRule::GraphicsAdmissibleFromGraphics),
        "render_target_admissible_from_render_target" => {
            Ok(PrimitiveRule::RenderTargetAdmissibleFromRenderTarget)
        }
        "render_pipeline_admissible_from_render_pipeline" => {
            Ok(PrimitiveRule::RenderPipelineAdmissibleFromRenderPipeline)
        }
        "benchmark_admissible_from_benchmark" => {
            Ok(PrimitiveRule::BenchmarkAdmissibleFromBenchmark)
        }
        "tensor_admissible_from_tensor" => Ok(PrimitiveRule::TensorAdmissibleFromTensor),
        "accelerator_admissible_from_accelerator" => {
            Ok(PrimitiveRule::AcceleratorAdmissibleFromAccelerator)
        }
        "dataset_admissible_from_dataset" => Ok(PrimitiveRule::DatasetAdmissibleFromDataset),
        "model_admissible_from_model" => Ok(PrimitiveRule::ModelAdmissibleFromModel),
        "training_admissible_from_training" => Ok(PrimitiveRule::TrainingAdmissibleFromTraining),
        "canonical_admissible_from_canonical" => {
            Ok(PrimitiveRule::CanonicalAdmissibleFromCanonical)
        }
        "artifact_bound_from_artifact" => Ok(PrimitiveRule::ArtifactBoundFromArtifact),
        "lowering_admissible_from_lowering" => Ok(PrimitiveRule::LoweringAdmissibleFromLowering),
        "executor_confined_from_executor" => Ok(PrimitiveRule::ExecutorConfinedFromExecutor),
        "witness_satisfies_contract" => Ok(PrimitiveRule::WitnessSatisfiesContract),
        "trace_equivalent" => Ok(PrimitiveRule::TraceEquivalent),
        _ => Err(ProofParseError::UnknownRule(input.to_owned())),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProofValue {
    Row { kind: RowKind, subject: String },
    Fact(Proposition),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofCheckError {
    #[error("proof script targets theorem {script_theorem}, expected {expected_theorem}")]
    TheoremMismatch {
        expected_theorem: String,
        script_theorem: String,
    },
    #[error("proof script has no final qed")]
    MissingQed,
    #[error("qed must be the final proof statement")]
    TrailingStatement,
    #[error("proof binding is duplicated: {0}")]
    DuplicateBinding(String),
    #[error("proof variable is unknown: {0}")]
    UnknownVariable(String),
    #[error("certificate row is unavailable: {kind:?} {subject}")]
    UnknownRow { kind: RowKind, subject: String },
    #[error("rule {rule:?} received the wrong number of row arguments")]
    InvalidRuleArity { rule: PrimitiveRule },
    #[error("rule {rule:?} cannot consume {kind:?}")]
    WrongRowKind { rule: PrimitiveRule, kind: RowKind },
    #[error("rule {rule:?} relation is not supported by the certificate rows")]
    RuleRelationRejected { rule: PrimitiveRule },
    #[error("qed value is not a fact: {0}")]
    QedNotFact(String),
    #[error("proved proposition does not match theorem")]
    PropositionMismatch {
        expected: Proposition,
        actual: Proposition,
    },
}

pub trait ProofEnvironment {
    fn has_row(&self, kind: &RowKind, subject: &str) -> bool;

    fn validates_rule(&self, _rule: &PrimitiveRule, _rows: &[(RowKind, String)]) -> bool {
        true
    }

    fn has_rocq_artifact(&self, _module: &str, _proposition: &Proposition) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofCheckReport {
    pub checked_steps: usize,
}

pub fn check_proof(
    theorem: &str,
    proposition: &Proposition,
    script: &ProofScript,
    environment: &impl ProofEnvironment,
) -> Result<ProofCheckReport, ProofCheckError> {
    if script.theorem != theorem {
        return Err(ProofCheckError::TheoremMismatch {
            expected_theorem: theorem.to_owned(),
            script_theorem: script.theorem.clone(),
        });
    }

    let mut values = BTreeMap::new();
    let mut checked_steps = 0;
    let mut qed_value = None;

    for (idx, statement) in script.statements.iter().enumerate() {
        checked_steps += 1;
        match statement {
            ProofStatement::BindRow {
                name,
                kind,
                subject,
            } => {
                if qed_value.is_some() {
                    return Err(ProofCheckError::TrailingStatement);
                }
                if !environment.has_row(kind, subject) {
                    return Err(ProofCheckError::UnknownRow {
                        kind: kind.clone(),
                        subject: subject.clone(),
                    });
                }
                insert_binding(
                    &mut values,
                    name,
                    ProofValue::Row {
                        kind: kind.clone(),
                        subject: subject.clone(),
                    },
                )?;
            }
            ProofStatement::ApplyRule { name, rule, args } => {
                if qed_value.is_some() {
                    return Err(ProofCheckError::TrailingStatement);
                }
                let fact = apply_rule(environment, rule, args, &values)?;
                insert_binding(&mut values, name, ProofValue::Fact(fact))?;
            }
            ProofStatement::UseRocq { module } => {
                if qed_value.is_some() {
                    return Err(ProofCheckError::TrailingStatement);
                }
                if !environment.has_rocq_artifact(module, proposition) {
                    return Err(ProofCheckError::UnknownRow {
                        kind: RowKind::ProofArtifact,
                        subject: module.clone(),
                    });
                }
                insert_binding(
                    &mut values,
                    "checked",
                    ProofValue::Fact(proposition.clone()),
                )?;
            }
            ProofStatement::Qed { value } => {
                if idx + 1 != script.statements.len() {
                    return Err(ProofCheckError::TrailingStatement);
                }
                qed_value = Some(value.clone());
            }
        }
    }

    let qed_value = qed_value.ok_or(ProofCheckError::MissingQed)?;
    let actual = match values.get(&qed_value) {
        Some(ProofValue::Fact(fact)) => fact.clone(),
        Some(ProofValue::Row { .. }) => return Err(ProofCheckError::QedNotFact(qed_value)),
        None => return Err(ProofCheckError::UnknownVariable(qed_value)),
    };
    if &actual != proposition {
        return Err(ProofCheckError::PropositionMismatch {
            expected: proposition.clone(),
            actual,
        });
    }

    Ok(ProofCheckReport { checked_steps })
}

fn insert_binding(
    values: &mut BTreeMap<String, ProofValue>,
    name: &str,
    value: ProofValue,
) -> Result<(), ProofCheckError> {
    if values.insert(name.to_owned(), value).is_some() {
        return Err(ProofCheckError::DuplicateBinding(name.to_owned()));
    }
    Ok(())
}

fn apply_rule(
    environment: &impl ProofEnvironment,
    rule: &PrimitiveRule,
    args: &[String],
    values: &BTreeMap<String, ProofValue>,
) -> Result<Proposition, ProofCheckError> {
    let contract = rule_contract(rule);
    if args.len() != contract.rows.len() {
        return Err(ProofCheckError::InvalidRuleArity { rule: rule.clone() });
    }
    let mut rows = Vec::with_capacity(args.len());
    for (arg, expected_kind) in args.iter().zip(contract.rows.iter()) {
        let Some(ProofValue::Row { kind, subject }) = values.get(arg) else {
            return Err(ProofCheckError::UnknownVariable(arg.clone()));
        };
        if kind != expected_kind {
            return Err(ProofCheckError::WrongRowKind {
                rule: rule.clone(),
                kind: kind.clone(),
            });
        }
        rows.push((kind.clone(), subject.clone()));
    }
    if !environment.validates_rule(rule, &rows) {
        return Err(ProofCheckError::RuleRelationRejected { rule: rule.clone() });
    }
    Ok(Proposition {
        kind: contract.proposition,
        subject: rows[contract.subject_index].1.clone(),
    })
}

struct RuleContract {
    rows: Vec<RowKind>,
    proposition: PropositionKind,
    subject_index: usize,
}

fn unary_rule(row: RowKind, proposition: PropositionKind) -> RuleContract {
    RuleContract {
        rows: vec![row],
        proposition,
        subject_index: 0,
    }
}

fn rule_contract(rule: &PrimitiveRule) -> RuleContract {
    match rule {
        PrimitiveRule::DevFrameFromRelation => {
            unary_rule(RowKind::Relation, PropositionKind::DevFrame)
        }
        PrimitiveRule::ResourceLinearFromResource => {
            unary_rule(RowKind::Resource, PropositionKind::ResourceLinear)
        }
        PrimitiveRule::ProbabilityNormalizesFromProbability => {
            unary_rule(RowKind::Probability, PropositionKind::ProbabilityNormalizes)
        }
        PrimitiveRule::InvariantPreservedFromInvariant => {
            unary_rule(RowKind::Invariant, PropositionKind::InvariantPreserved)
        }
        PrimitiveRule::BackendAdmissibleFromBackend => {
            unary_rule(RowKind::Backend, PropositionKind::BackendAdmissible)
        }
        PrimitiveRule::ExternalAdmissibleFromExternal => {
            unary_rule(RowKind::External, PropositionKind::ExternalAdmissible)
        }
        PrimitiveRule::MachineAdmissibleFromMachine => {
            unary_rule(RowKind::Machine, PropositionKind::MachineAdmissible)
        }
        PrimitiveRule::MemoryAdmissibleFromMemory => {
            unary_rule(RowKind::Memory, PropositionKind::MemoryAdmissible)
        }
        PrimitiveRule::InstructionRefinesFromInstruction => {
            unary_rule(RowKind::Instruction, PropositionKind::InstructionRefines)
        }
        PrimitiveRule::AbiAdmissibleFromAbi => {
            unary_rule(RowKind::Abi, PropositionKind::AbiAdmissible)
        }
        PrimitiveRule::ProofArtifactCheckedFromArtifact => unary_rule(
            RowKind::ProofArtifact,
            PropositionKind::ProofArtifactChecked,
        ),
        PrimitiveRule::ParserAdmissibleFromParser => {
            unary_rule(RowKind::Parser, PropositionKind::ParserAdmissible)
        }
        PrimitiveRule::SelectionAdmissibleFromSelection => {
            unary_rule(RowKind::Selection, PropositionKind::SelectionAdmissible)
        }
        PrimitiveRule::TransformAdmissibleFromTransform => {
            unary_rule(RowKind::Transform, PropositionKind::TransformAdmissible)
        }
        PrimitiveRule::ValidatorAdmissibleFromValidator => {
            unary_rule(RowKind::Validator, PropositionKind::ValidatorAdmissible)
        }
        PrimitiveRule::ObjectiveAdmissibleFromObjective => {
            unary_rule(RowKind::Objective, PropositionKind::ObjectiveAdmissible)
        }
        PrimitiveRule::MilestoneAdmissibleFromMilestone => {
            unary_rule(RowKind::Milestone, PropositionKind::MilestoneAdmissible)
        }
        PrimitiveRule::TaskAdmissibleFromTask => {
            unary_rule(RowKind::Task, PropositionKind::TaskAdmissible)
        }
        PrimitiveRule::GateAdmissibleFromGate => {
            unary_rule(RowKind::Gate, PropositionKind::GateAdmissible)
        }
        PrimitiveRule::DecisionAdmissibleFromDecision => {
            unary_rule(RowKind::Decision, PropositionKind::DecisionAdmissible)
        }
        PrimitiveRule::NoteAdmissibleFromNote => {
            unary_rule(RowKind::Note, PropositionKind::NoteAdmissible)
        }
        PrimitiveRule::LaneAdmissibleFromLane => {
            unary_rule(RowKind::Lane, PropositionKind::LaneAdmissible)
        }
        PrimitiveRule::ClaimAdmissibleFromClaim => {
            unary_rule(RowKind::Claim, PropositionKind::ClaimAdmissible)
        }
        PrimitiveRule::HandoffAdmissibleFromHandoff => {
            unary_rule(RowKind::Handoff, PropositionKind::HandoffAdmissible)
        }
        PrimitiveRule::SyncAdmissibleFromSync => {
            unary_rule(RowKind::Sync, PropositionKind::SyncAdmissible)
        }
        PrimitiveRule::CheckpointAdmissibleFromCheckpoint => {
            unary_rule(RowKind::Checkpoint, PropositionKind::CheckpointAdmissible)
        }
        PrimitiveRule::RuntimeLedgerAdmissibleFromRuntimeLedger => unary_rule(
            RowKind::RuntimeLedger,
            PropositionKind::RuntimeLedgerAdmissible,
        ),
        PrimitiveRule::RuntimePolicyAdmissibleFromRuntimePolicy => unary_rule(
            RowKind::RuntimePolicy,
            PropositionKind::RuntimePolicyAdmissible,
        ),
        PrimitiveRule::RuntimeSessionAdmissibleFromRuntimeSession => unary_rule(
            RowKind::RuntimeSession,
            PropositionKind::RuntimeSessionAdmissible,
        ),
        PrimitiveRule::RuntimeToolAdmissibleFromRuntimeTool => {
            unary_rule(RowKind::RuntimeTool, PropositionKind::RuntimeToolAdmissible)
        }
        PrimitiveRule::RuntimeTurnAdmissibleFromRuntimeTurn => {
            unary_rule(RowKind::RuntimeTurn, PropositionKind::RuntimeTurnAdmissible)
        }
        PrimitiveRule::RuntimeHookAdmissibleFromRuntimeHook => {
            unary_rule(RowKind::RuntimeHook, PropositionKind::RuntimeHookAdmissible)
        }
        PrimitiveRule::RuntimeBridgeAdmissibleFromRuntimeBridge => unary_rule(
            RowKind::RuntimeBridge,
            PropositionKind::RuntimeBridgeAdmissible,
        ),
        PrimitiveRule::GraphicsAdmissibleFromGraphics => {
            unary_rule(RowKind::Graphics, PropositionKind::GraphicsAdmissible)
        }
        PrimitiveRule::RenderTargetAdmissibleFromRenderTarget => unary_rule(
            RowKind::RenderTarget,
            PropositionKind::RenderTargetAdmissible,
        ),
        PrimitiveRule::RenderPipelineAdmissibleFromRenderPipeline => unary_rule(
            RowKind::RenderPipeline,
            PropositionKind::RenderPipelineAdmissible,
        ),
        PrimitiveRule::BenchmarkAdmissibleFromBenchmark => {
            unary_rule(RowKind::Benchmark, PropositionKind::BenchmarkAdmissible)
        }
        PrimitiveRule::TensorAdmissibleFromTensor => {
            unary_rule(RowKind::Tensor, PropositionKind::TensorAdmissible)
        }
        PrimitiveRule::AcceleratorAdmissibleFromAccelerator => {
            unary_rule(RowKind::Accelerator, PropositionKind::AcceleratorAdmissible)
        }
        PrimitiveRule::DatasetAdmissibleFromDataset => {
            unary_rule(RowKind::Dataset, PropositionKind::DatasetAdmissible)
        }
        PrimitiveRule::ModelAdmissibleFromModel => {
            unary_rule(RowKind::Model, PropositionKind::ModelAdmissible)
        }
        PrimitiveRule::TrainingAdmissibleFromTraining => {
            unary_rule(RowKind::Training, PropositionKind::TrainingAdmissible)
        }
        PrimitiveRule::CanonicalAdmissibleFromCanonical => {
            unary_rule(RowKind::Canonical, PropositionKind::CanonicalAdmissible)
        }
        PrimitiveRule::ArtifactBoundFromArtifact => {
            unary_rule(RowKind::Artifact, PropositionKind::ArtifactBound)
        }
        PrimitiveRule::LoweringAdmissibleFromLowering => {
            unary_rule(RowKind::Lowering, PropositionKind::LoweringAdmissible)
        }
        PrimitiveRule::ExecutorConfinedFromExecutor => {
            unary_rule(RowKind::Executor, PropositionKind::ExecutorConfined)
        }
        PrimitiveRule::WitnessSatisfiesContract => RuleContract {
            rows: vec![
                RowKind::Witness,
                RowKind::Training,
                RowKind::Artifact,
                RowKind::Executor,
            ],
            proposition: PropositionKind::WitnessSatisfies,
            subject_index: 0,
        },
        PrimitiveRule::TraceEquivalent => RuleContract {
            rows: vec![RowKind::Witness, RowKind::Model, RowKind::Lowering],
            proposition: PropositionKind::TraceEquivalent,
            subject_index: 0,
        },
    }
}

fn parse_quoted(input: &str) -> Option<String> {
    let body = input.strip_prefix('"')?.strip_suffix('"')?;
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
    Some(output)
}
