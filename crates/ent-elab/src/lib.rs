use ent_core::{
    AbiContract, AcceleratorContract, AdContract, ArtifactContract, BackendContract,
    BenchmarkContract, CanonicalContract, Certificate, DatasetContract, Endianness,
    ExecutorContract, ExternalContract, GraphicContract, InstructionContract, InvariantContract,
    KernelFormula, Label, LoweringContract, MachineContract, MachineMemoryModel, MemoryContract,
    MemoryPermission, MemoryRegion, ModelContract, ParserContract, ProbabilityContract,
    ProgramState, ProofArtifact, ProofCertificate, ProverKind, RelationTable,
    RenderPipelineContract, RenderTargetContract, ResourceAccess, ResourceContract,
    SelectionContract, StateId, TensorContract, TextReplacement, TrainingContract,
    TransformContract, TransformTarget, ValidatorContract, WitnessContract, WorkspaceContract,
    CERTIFICATE_SCHEMA_VERSION, MAX_MODAL_DIMENSIONS,
};
use ent_parser::{
    parse_world_diagnostic, DimensionKind, EffectAccess, ParseDiagnostic, ParseError,
    TransformTargetDecl, WorldAst,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ElabError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    ParseDiagnostic(#[from] ParseDiagnostic),
    #[error("world must declare at least one dimension")]
    EmptyDimensionSet,
    #[error("proof references undeclared theorem: {0}")]
    UnknownProofTarget(String),
    #[error("theorem lacks proof block: {0}")]
    MissingProof(String),
    #[error("duplicate proof block for theorem: {0}")]
    DuplicateProof(String),
    #[error("unsupported backend: {0}")]
    UnsupportedBackend(String),
    #[error("unsupported endianness: {0}")]
    UnsupportedEndianness(String),
    #[error("unsupported memory model: {0}")]
    UnsupportedMemoryModel(String),
    #[error("unsupported memory permission: {0}")]
    UnsupportedMemoryPermission(String),
    #[error("unsupported prover: {0}")]
    UnsupportedProver(String),
    #[error("world declares {actual} modal dimensions, maximum is {max}")]
    TooManyDimensions { actual: usize, max: usize },
    #[error("missing explicit evidence for {kind}: {name}")]
    MissingEvidence { kind: &'static str, name: String },
    #[error("differentiable evolve lacks explicit AD contract: {0}")]
    MissingAdContract(String),
}

pub fn elaborate_source(source: &str) -> Result<Certificate, ElabError> {
    let ast = parse_world_diagnostic(source)?;
    elaborate_ast(&ast)
}

pub fn elaborate_ast(ast: &WorldAst) -> Result<Certificate, ElabError> {
    let dimensions = explicit_dimensions(ast)?;
    if dimensions.is_empty() {
        return Err(ElabError::EmptyDimensionSet);
    }
    if dimensions.len() > MAX_MODAL_DIMENSIONS {
        return Err(ElabError::TooManyDimensions {
            actual: dimensions.len(),
            max: MAX_MODAL_DIMENSIONS,
        });
    }

    let modal_worlds = product_worlds(&dimensions);
    let root_world = modal_worlds[0].clone();
    let relations = product_relations(&dimensions, &modal_worlds);
    let atom = KernelFormula::Atom("verified".to_owned());
    let closure = vec![
        atom.clone(),
        KernelFormula::Box(Label::empty(), Box::new(atom.clone())),
        KernelFormula::Diamond(Label::empty(), Box::new(atom.clone())),
    ];
    let types = modal_worlds
        .iter()
        .cloned()
        .map(|state| (state, closure.clone()))
        .collect::<Vec<_>>();
    let invariants = explicit_invariants(ast)?;
    let resources = explicit_resources(ast, &root_world)?;
    let external_capabilities = explicit_external_capabilities(ast, &root_world)?;
    let probabilities = explicit_probabilities(ast, &root_world)?;
    let ad = explicit_ad(ast)?;
    for evolve in ast.evolves.iter().filter(|evolve| evolve.differentiable) {
        if !ad.iter().any(|contract| contract.primal == evolve.name) {
            return Err(ElabError::MissingAdContract(evolve.name.clone()));
        }
    }
    let backends = ast
        .evolves
        .iter()
        .map(|evolve| match evolve.backend.as_str() {
            _ if evolve.evidence.trim().is_empty() => Err(ElabError::MissingEvidence {
                kind: "backend",
                name: evolve.name.clone(),
            }),
            "cpu" => Ok(BackendContract {
                node: evolve.name.clone(),
                backend: ent_core::BackendKind::Cpu,
                admissible: true,
                evidence: evolve.evidence.clone(),
            }),
            "metal" => Ok(BackendContract {
                node: evolve.name.clone(),
                backend: ent_core::BackendKind::Metal,
                admissible: true,
                evidence: evolve.evidence.clone(),
            }),
            "private-ane" => Ok(BackendContract::private_ane(
                &evolve.name,
                true,
                evolve.evidence.clone(),
            )),
            backend if backend.starts_with("capability:") => Ok(BackendContract {
                node: evolve.name.clone(),
                backend: ent_core::BackendKind::Capability(
                    backend.trim_start_matches("capability:").to_owned(),
                ),
                admissible: true,
                evidence: evolve.evidence.clone(),
            }),
            other => Err(ElabError::UnsupportedBackend(other.to_owned())),
        })
        .collect::<Result<Vec<_>, ElabError>>()?;
    let proofs = proofs(ast)?;

    Ok(Certificate {
        version: CERTIFICATE_SCHEMA_VERSION,
        program_states: ast
            .states
            .iter()
            .map(|state| ProgramState {
                name: state.name.clone(),
                sort: state.ty.clone(),
            })
            .collect(),
        world: ast.name.clone(),
        dimensions,
        modal_worlds: modal_worlds.clone(),
        root_world: root_world.clone(),
        formula: atom,
        closure,
        types,
        relation_names: ast
            .relations
            .iter()
            .map(|relation| relation.name.clone())
            .collect(),
        relations,
        factors: vec![],
        diamonds: vec![],
        invariants,
        resources,
        probabilities,
        ad,
        backends,
        external_capabilities,
        workspaces: explicit_workspaces(ast)?,
        parsers: explicit_parsers(ast)?,
        selections: explicit_selections(ast)?,
        transforms: explicit_transforms(ast)?,
        validators: explicit_validators(ast)?,
        graphics: explicit_graphics(ast)?,
        render_targets: explicit_render_targets(ast)?,
        render_pipelines: explicit_render_pipelines(ast)?,
        benchmarks: explicit_benchmarks(ast)?,
        tensors: explicit_tensors(ast)?,
        accelerators: explicit_accelerators(ast)?,
        datasets: explicit_datasets(ast)?,
        models: explicit_models(ast)?,
        trainings: explicit_trainings(ast)?,
        canonicals: explicit_canonicals(ast)?,
        artifacts: explicit_artifacts(ast)?,
        lowerings: explicit_lowerings(ast)?,
        executors: explicit_executors(ast)?,
        witnesses: explicit_witnesses(ast)?,
        machines: explicit_machines(ast)?,
        memory: explicit_memory(ast)?,
        instructions: explicit_instructions(ast)?,
        abis: explicit_abis(ast)?,
        proof_artifacts: explicit_proof_artifacts(ast)?,
        proofs,
        require_coordinate_separation: true,
        public_survivors: None,
    })
}

fn explicit_invariants(ast: &WorldAst) -> Result<Vec<InvariantContract>, ElabError> {
    ast.invariants
        .iter()
        .map(|decl| {
            require_evidence("invariant", &decl.name, &decl.evidence)?;
            Ok(InvariantContract {
                name: decl.name.clone(),
                before: decl.before,
                after: decl.after,
                tolerance: decl.tolerance,
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_resources(ast: &WorldAst, root: &StateId) -> Result<Vec<ResourceContract>, ElabError> {
    ast.effects
        .iter()
        .map(|effect| {
            require_evidence("resource", &effect.resource, &effect.evidence)?;
            Ok(ResourceContract {
                name: effect.resource.clone(),
                state: root.clone(),
                access: match effect.access {
                    EffectAccess::Read => ResourceAccess::Read,
                    EffectAccess::Write => ResourceAccess::Write,
                },
                owner: effect.name.clone(),
                evidence: effect.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_external_capabilities(
    ast: &WorldAst,
    root: &StateId,
) -> Result<Vec<ExternalContract>, ElabError> {
    ast.externals
        .iter()
        .map(|external| {
            require_evidence("external", &external.name, &external.evidence)?;
            Ok(ExternalContract {
                name: external.name.clone(),
                interface: external.interface.clone(),
                state: root.clone(),
                resource: external.resource.clone(),
                access: match external.access {
                    EffectAccess::Read => ResourceAccess::Read,
                    EffectAccess::Write => ResourceAccess::Write,
                },
                admissible: true,
                evidence: external.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_workspaces(ast: &WorldAst) -> Result<Vec<WorkspaceContract>, ElabError> {
    ast.workspaces
        .iter()
        .map(|decl| {
            require_evidence("workspace", &decl.name, &decl.evidence)?;
            Ok(WorkspaceContract {
                name: decl.name.clone(),
                boundary: decl.boundary.clone(),
                access: match decl.access {
                    EffectAccess::Read => ResourceAccess::Read,
                    EffectAccess::Write => ResourceAccess::Write,
                },
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_parsers(ast: &WorldAst) -> Result<Vec<ParserContract>, ElabError> {
    let mut parsers = ast
        .parsers
        .iter()
        .map(|decl| {
            require_evidence("parser", &decl.name, &decl.evidence)?;
            Ok(ParserContract {
                name: decl.name.clone(),
                language: decl.language.clone(),
                adapter: decl.adapter.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect::<Result<Vec<_>, ElabError>>()?;

    for document in &ast.documents {
        require_evidence("document", &document.name, &document.evidence)?;
        parsers.push(ParserContract {
            name: document.name.clone(),
            language: document.name.clone(),
            adapter: document.adapter.clone(),
            evidence: document.evidence.clone(),
        });
    }

    Ok(parsers)
}

fn explicit_selections(ast: &WorldAst) -> Result<Vec<SelectionContract>, ElabError> {
    ast.selections
        .iter()
        .map(|decl| {
            require_evidence("selection", &decl.name, &decl.evidence)?;
            Ok(SelectionContract {
                name: decl.name.clone(),
                predicate: decl.predicate.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_transforms(ast: &WorldAst) -> Result<Vec<TransformContract>, ElabError> {
    ast.transforms
        .iter()
        .map(|decl| {
            require_evidence("transform", &decl.name, &decl.evidence)?;
            Ok(TransformContract {
                name: decl.name.clone(),
                operation: decl.operation.clone(),
                target: match &decl.target {
                    TransformTargetDecl::Selection(name) => {
                        TransformTarget::Selection(name.clone())
                    }
                    TransformTargetDecl::File(path) => TransformTarget::File(path.clone()),
                },
                destination: decl.destination.clone(),
                predicate: decl.predicate.clone(),
                replacement: decl
                    .replacement
                    .as_ref()
                    .map(|replacement| TextReplacement {
                        from: replacement.from.clone(),
                        to: replacement.to.clone(),
                    }),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_validators(ast: &WorldAst) -> Result<Vec<ValidatorContract>, ElabError> {
    ast.validators
        .iter()
        .map(|decl| {
            require_evidence("validator", &decl.name, &decl.evidence)?;
            Ok(ValidatorContract {
                name: decl.name.clone(),
                argv: decl.argv.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_graphics(ast: &WorldAst) -> Result<Vec<GraphicContract>, ElabError> {
    ast.graphics
        .iter()
        .map(|decl| {
            require_evidence("graphics", &decl.name, &decl.evidence)?;
            Ok(GraphicContract {
                name: decl.name.clone(),
                entry: decl.entry.clone(),
                source_digest: format!("sha256:{}", sha256_hex(decl.body.as_bytes())),
                imports: decl.imports.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_render_targets(ast: &WorldAst) -> Result<Vec<RenderTargetContract>, ElabError> {
    ast.render_targets
        .iter()
        .map(|decl| {
            require_evidence("render-target", &decl.name, &decl.evidence)?;
            Ok(RenderTargetContract {
                name: decl.name.clone(),
                width: decl.width,
                height: decl.height,
                format: decl.format.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_render_pipelines(ast: &WorldAst) -> Result<Vec<RenderPipelineContract>, ElabError> {
    ast.render_pipelines
        .iter()
        .map(|decl| {
            require_evidence("render-pipeline", &decl.name, &decl.evidence)?;
            Ok(RenderPipelineContract {
                name: decl.name.clone(),
                graphics: decl.graphics.clone(),
                target: decl.target.clone(),
                entry: decl.entry.clone(),
                mode: decl.mode.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_benchmarks(ast: &WorldAst) -> Result<Vec<BenchmarkContract>, ElabError> {
    ast.benchmarks
        .iter()
        .map(|decl| {
            require_evidence("benchmark", &decl.name, &decl.evidence)?;
            Ok(BenchmarkContract {
                name: decl.name.clone(),
                graphics: decl.graphics.clone(),
                entry: decl.entry.clone(),
                warmup: decl.warmup,
                iterations: decl.iterations,
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_tensors(ast: &WorldAst) -> Result<Vec<TensorContract>, ElabError> {
    ast.tensors
        .iter()
        .map(|decl| {
            require_evidence("tensor", &decl.name, &decl.evidence)?;
            Ok(TensorContract {
                name: decl.name.clone(),
                shape: decl.shape.clone(),
                dtype: decl.dtype.clone(),
                gradient: decl.gradient.clone(),
                layout: decl.layout.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_accelerators(ast: &WorldAst) -> Result<Vec<AcceleratorContract>, ElabError> {
    ast.accelerators
        .iter()
        .map(|decl| {
            require_evidence("accelerator", &decl.name, &decl.evidence)?;
            Ok(AcceleratorContract {
                name: decl.name.clone(),
                kind: decl.kind.clone(),
                memory: decl.memory.clone(),
                precision: decl.precision.clone(),
                supports: decl.supports.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_datasets(ast: &WorldAst) -> Result<Vec<DatasetContract>, ElabError> {
    ast.datasets
        .iter()
        .map(|decl| {
            require_evidence("dataset", &decl.name, &decl.evidence)?;
            Ok(DatasetContract {
                name: decl.name.clone(),
                tensors: decl.tensors.clone(),
                source: decl.source.clone(),
                source_digest: decl.source_digest.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_models(ast: &WorldAst) -> Result<Vec<ModelContract>, ElabError> {
    ast.models
        .iter()
        .map(|decl| {
            require_evidence("model", &decl.name, &decl.evidence)?;
            Ok(ModelContract {
                name: decl.name.clone(),
                entry: decl.entry.clone(),
                inputs: decl.inputs.clone(),
                parameters: decl.parameters.clone(),
                outputs: decl.outputs.clone(),
                ops: decl.ops.clone(),
                loss: decl.loss.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_trainings(ast: &WorldAst) -> Result<Vec<TrainingContract>, ElabError> {
    ast.trainings
        .iter()
        .map(|decl| {
            require_evidence("training", &decl.name, &decl.evidence)?;
            Ok(TrainingContract {
                name: decl.name.clone(),
                model: decl.model.clone(),
                dataset: decl.dataset.clone(),
                artifact: decl.artifact.clone(),
                accelerator: decl.accelerator.clone(),
                optimizer: decl.optimizer.clone(),
                learning_rate: decl.learning_rate,
                steps: decl.steps,
                batch: decl.batch,
                objective: decl.objective.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_canonicals(ast: &WorldAst) -> Result<Vec<CanonicalContract>, ElabError> {
    ast.canonicals
        .iter()
        .map(|decl| {
            require_evidence("canonical", &decl.name, &decl.evidence)?;
            Ok(CanonicalContract {
                name: decl.name.clone(),
                format: decl.format.clone(),
                fields: decl.fields.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_artifacts(ast: &WorldAst) -> Result<Vec<ArtifactContract>, ElabError> {
    ast.artifacts
        .iter()
        .map(|decl| {
            require_evidence("artifact", &decl.name, &decl.evidence)?;
            Ok(ArtifactContract {
                name: decl.name.clone(),
                kind: decl.kind.clone(),
                tensors: decl.tensors.clone(),
                manifest: decl.manifest.clone(),
                digest: decl.digest.clone(),
                canonical: decl.canonical.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_lowerings(ast: &WorldAst) -> Result<Vec<LoweringContract>, ElabError> {
    ast.lowerings
        .iter()
        .map(|decl| {
            require_evidence("lowering", &decl.name, &decl.evidence)?;
            Ok(LoweringContract {
                name: decl.name.clone(),
                model: decl.model.clone(),
                framework: decl.framework.clone(),
                mappings: decl.mappings.clone(),
                tolerance: decl.tolerance,
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_executors(ast: &WorldAst) -> Result<Vec<ExecutorContract>, ElabError> {
    ast.executors
        .iter()
        .map(|decl| {
            require_evidence("executor", &decl.name, &decl.evidence)?;
            Ok(ExecutorContract {
                name: decl.name.clone(),
                framework: decl.framework.clone(),
                module: decl.module.clone(),
                function: decl.function.clone(),
                device: decl.device.clone(),
                network: decl.network.clone(),
                seed: decl.seed,
                deterministic: decl.deterministic,
                read_artifacts: decl.read_artifacts.clone(),
                write_paths: decl.write_paths.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_witnesses(ast: &WorldAst) -> Result<Vec<WitnessContract>, ElabError> {
    ast.witnesses
        .iter()
        .map(|decl| {
            require_evidence("witness", &decl.name, &decl.evidence)?;
            Ok(WitnessContract {
                name: decl.name.clone(),
                training: decl.training.clone(),
                artifact: decl.artifact.clone(),
                lowering: decl.lowering.clone(),
                executor: decl.executor.clone(),
                manifest: decl.manifest.clone(),
                requirements: decl.requirements.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_machines(ast: &WorldAst) -> Result<Vec<MachineContract>, ElabError> {
    ast.machines
        .iter()
        .map(|decl| {
            require_evidence("machine", &decl.id, &decl.evidence)?;
            Ok(MachineContract {
                id: decl.id.clone(),
                isa: decl.isa.clone(),
                profile: decl.profile.clone(),
                word_bits: decl.word_bits,
                endianness: parse_endianness(&decl.endianness)?,
                memory_model: parse_memory_model(&decl.memory_model)?,
                semantic_source: decl.semantic_source.clone(),
                source_digest: decl.source_digest.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_memory(ast: &WorldAst) -> Result<Vec<MemoryContract>, ElabError> {
    ast.memories
        .iter()
        .map(|decl| {
            require_evidence("memory", &decl.name, &decl.evidence)?;
            Ok(MemoryContract {
                name: decl.name.clone(),
                machine: decl.machine.clone(),
                address_bits: decl.address_bits,
                ordering: parse_memory_model(&decl.ordering)?,
                regions: decl
                    .regions
                    .iter()
                    .map(|region| {
                        Ok(MemoryRegion {
                            name: region.name.clone(),
                            base: region.base,
                            size: region.size,
                            permissions: region
                                .permissions
                                .iter()
                                .map(|permission| parse_memory_permission(permission))
                                .collect::<Result<Vec<_>, ElabError>>()?,
                        })
                    })
                    .collect::<Result<Vec<_>, ElabError>>()?,
                frame_conditions: decl.frame_conditions.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_instructions(ast: &WorldAst) -> Result<Vec<InstructionContract>, ElabError> {
    ast.instructions
        .iter()
        .map(|decl| {
            require_evidence("instruction", &decl.name, &decl.evidence)?;
            Ok(InstructionContract {
                name: decl.name.clone(),
                machine: decl.machine.clone(),
                mnemonic: decl.mnemonic.clone(),
                encoding: decl.encoding.clone(),
                semantics: decl.semantics.clone(),
                effects: decl.effects.clone(),
                proof_artifact: decl.proof_artifact.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_abis(ast: &WorldAst) -> Result<Vec<AbiContract>, ElabError> {
    ast.abis
        .iter()
        .map(|decl| {
            require_evidence("abi", &decl.name, &decl.evidence)?;
            Ok(AbiContract {
                name: decl.name.clone(),
                machine: decl.machine.clone(),
                target_triple: decl.target_triple.clone(),
                object_format: decl.object_format.clone(),
                calling_convention: decl.calling_convention.clone(),
                external_policy: decl.external_policy.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_proof_artifacts(ast: &WorldAst) -> Result<Vec<ProofArtifact>, ElabError> {
    ast.proof_artifacts
        .iter()
        .map(|decl| {
            require_evidence("proof-artifact", &decl.name, &decl.evidence)?;
            Ok(ProofArtifact {
                name: decl.name.clone(),
                prover: parse_prover(&decl.prover)?,
                module: decl.module.clone(),
                digest: decl.digest.clone(),
                obligations: decl.obligations.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_probabilities(
    ast: &WorldAst,
    root: &StateId,
) -> Result<Vec<ProbabilityContract>, ElabError> {
    ast.measures
        .iter()
        .map(|measure| {
            require_evidence("probability", &measure.name, &measure.evidence)?;
            Ok(ProbabilityContract {
                name: measure.name.clone(),
                state: root.clone(),
                weights: measure.weights.clone(),
                tolerance: measure.tolerance,
                evidence: measure.evidence.clone(),
            })
        })
        .collect()
}

fn explicit_ad(ast: &WorldAst) -> Result<Vec<AdContract>, ElabError> {
    ast.ad
        .iter()
        .map(|decl| {
            require_evidence("ad", &decl.primal, &decl.evidence)?;
            Ok(AdContract {
                primal: decl.primal.clone(),
                tangent: decl.tangent.clone(),
                adjoint: decl.adjoint.clone(),
                law: decl.law.clone(),
                evidence: decl.evidence.clone(),
            })
        })
        .collect()
}

fn parse_endianness(value: &str) -> Result<Endianness, ElabError> {
    match value {
        "little" => Ok(Endianness::Little),
        "big" => Ok(Endianness::Big),
        other => Err(ElabError::UnsupportedEndianness(other.to_owned())),
    }
}

fn parse_memory_model(value: &str) -> Result<MachineMemoryModel, ElabError> {
    match value {
        "sequential" => Ok(MachineMemoryModel::Sequential),
        "rvwmo" | "riscv-rvwmo" => Ok(MachineMemoryModel::RiscvRvwmo),
        "ztso" | "riscv-tso" => Ok(MachineMemoryModel::RiscvTso),
        other => Err(ElabError::UnsupportedMemoryModel(other.to_owned())),
    }
}

fn parse_memory_permission(value: &str) -> Result<MemoryPermission, ElabError> {
    match value {
        "read" => Ok(MemoryPermission::Read),
        "write" => Ok(MemoryPermission::Write),
        "execute" => Ok(MemoryPermission::Execute),
        other => Err(ElabError::UnsupportedMemoryPermission(other.to_owned())),
    }
}

fn parse_prover(value: &str) -> Result<ProverKind, ElabError> {
    match value {
        "rocq" | "coq" => Ok(ProverKind::Rocq),
        other => Err(ElabError::UnsupportedProver(other.to_owned())),
    }
}

fn require_evidence(kind: &'static str, name: &str, evidence: &str) -> Result<(), ElabError> {
    if evidence.trim().is_empty() {
        return Err(ElabError::MissingEvidence {
            kind,
            name: name.to_owned(),
        });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn proofs(ast: &WorldAst) -> Result<Vec<ProofCertificate>, ElabError> {
    let mut scripts = BTreeMap::new();
    for proof in &ast.proofs {
        if !ast
            .theorems
            .iter()
            .any(|theorem| theorem.name == proof.theorem)
        {
            return Err(ElabError::UnknownProofTarget(proof.theorem.clone()));
        }
        if scripts
            .insert(proof.theorem.clone(), proof.script.clone())
            .is_some()
        {
            return Err(ElabError::DuplicateProof(proof.theorem.clone()));
        }
    }

    ast.theorems
        .iter()
        .map(|theorem| {
            let script = scripts
                .remove(&theorem.name)
                .ok_or_else(|| ElabError::MissingProof(theorem.name.clone()))?;
            Ok(ProofCertificate {
                name: theorem.name.clone(),
                proposition: theorem.proposition.clone(),
                script,
            })
        })
        .collect()
}

fn explicit_dimensions(ast: &WorldAst) -> Result<Vec<String>, ElabError> {
    let mut dimensions = ast
        .dimensions
        .iter()
        .map(|dimension| match dimension.kind {
            DimensionKind::Agent => format!("agent:{}", dimension.name),
            DimensionKind::Space => format!("space:{}", dimension.name),
            DimensionKind::Other(_) => dimension.name.clone(),
        })
        .collect::<Vec<_>>();
    dimensions.sort();
    dimensions.dedup();
    Ok(dimensions)
}

fn product_worlds(dimensions: &[String]) -> Vec<StateId> {
    let count = 1usize << dimensions.len();
    (0..count)
        .map(|mask| StateId::from(format!("s{mask:0width$b}", width = dimensions.len())))
        .collect()
}

fn product_relations(dimensions: &[String], states: &[StateId]) -> Vec<RelationTable> {
    Label::powerset(dimensions)
        .into_iter()
        .map(|label| {
            let pairs = states
                .iter()
                .enumerate()
                .flat_map(|(left_idx, left)| {
                    states.iter().enumerate().filter_map({
                        let label = label.clone();
                        move |(right_idx, right)| {
                            compatible_product_edge(dimensions, &label, left_idx, right_idx)
                                .then(|| (left.clone(), right.clone()))
                        }
                    })
                })
                .collect();
            RelationTable::new(label, pairs)
        })
        .collect()
}

fn compatible_product_edge(
    dimensions: &[String],
    label: &Label,
    left_idx: usize,
    right_idx: usize,
) -> bool {
    dimensions.iter().enumerate().all(|(idx, dimension)| {
        label.members.contains(dimension)
            || ((left_idx >> idx) & 1usize) == ((right_idx >> idx) & 1usize)
    })
}
