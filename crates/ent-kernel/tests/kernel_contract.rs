use ent_core::{
    AbiContract, AdContract, BackendContract, BenchmarkContract, Certificate, Endianness,
    GraphicContract, InstabilityKind, InstructionContract, KernelFormula, Label, MachineContract,
    MachineMemoryModel, MemoryContract, MemoryPermission, MemoryRegion, ParserContract,
    ProgramState, ProofArtifact, ProofCertificate, ProverKind, RelationTable,
    RenderPipelineContract, RenderTargetContract, ResourceAccess, SelectionContract, StateId,
    TransformContract, TransformTarget, ValidatorContract, WorkspaceContract,
    CERTIFICATE_SCHEMA_VERSION,
};
use ent_kernel::{verify, KernelError};
use ent_proof::{
    PrimitiveRule, ProofScript, ProofStatement, Proposition, PropositionKind, RowKind,
};

fn accepting_certificate() -> Certificate {
    let agents = vec!["one".into(), "two".into()];
    let states = vec![StateId::from("s0")];
    let labels = Label::powerset(&agents);
    let identity = vec![(StateId::from("s0"), StateId::from("s0"))];
    let relations = labels
        .iter()
        .map(|label| RelationTable::new(label.clone(), identity.clone()))
        .collect();

    Certificate {
        version: CERTIFICATE_SCHEMA_VERSION,
        world: "Audit".into(),
        dimensions: agents,
        program_states: vec![ProgramState {
            name: "heap".into(),
            sort: "Resource".into(),
        }],
        modal_worlds: states.clone(),
        root_world: StateId::from("s0"),
        closure: vec![
            KernelFormula::Atom("p".into()),
            KernelFormula::Box(Label::empty(), Box::new(KernelFormula::Atom("p".into()))),
            KernelFormula::Diamond(Label::empty(), Box::new(KernelFormula::Atom("p".into()))),
        ],
        types: vec![(
            StateId::from("s0"),
            vec![
                KernelFormula::Atom("p".into()),
                KernelFormula::Box(Label::empty(), Box::new(KernelFormula::Atom("p".into()))),
                KernelFormula::Diamond(Label::empty(), Box::new(KernelFormula::Atom("p".into()))),
            ],
        )],
        relation_names: vec!["audit".into()],
        relations,
        factors: vec![],
        diamonds: vec![],
        invariants: vec![],
        resources: vec![],
        probabilities: vec![],
        ad: vec![AdContract::identity("realization")],
        backends: vec![BackendContract::metal("compile")],
        external_capabilities: vec![],
        workspaces: vec![],
        parsers: vec![],
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
        memory: vec![],
        instructions: vec![],
        abis: vec![],
        proof_artifacts: vec![],
        proofs: vec![],
        require_coordinate_separation: false,
        public_survivors: None,
        formula: KernelFormula::Atom("p".into()),
    }
}

fn proof(
    name: &str,
    proposition_kind: PropositionKind,
    subject: &str,
    row_kind: RowKind,
    rule: PrimitiveRule,
) -> ProofCertificate {
    ProofCertificate {
        name: name.to_owned(),
        proposition: Proposition {
            kind: proposition_kind,
            subject: subject.to_owned(),
        },
        script: ProofScript {
            theorem: name.to_owned(),
            statements: vec![
                ProofStatement::BindRow {
                    name: "row".to_owned(),
                    kind: row_kind,
                    subject: subject.to_owned(),
                },
                ProofStatement::ApplyRule {
                    name: "fact".to_owned(),
                    rule,
                    args: vec!["row".to_owned()],
                },
                ProofStatement::Qed {
                    value: "fact".to_owned(),
                },
            ],
        },
    }
}

fn rocq_proof(name: &str, proposition_kind: PropositionKind, subject: &str) -> ProofCertificate {
    ProofCertificate {
        name: name.to_owned(),
        proposition: Proposition {
            kind: proposition_kind,
            subject: subject.to_owned(),
        },
        script: ProofScript {
            theorem: name.to_owned(),
            statements: vec![
                ProofStatement::UseRocq {
                    module: "proofs/rocq/EntanglementRiscV.v".into(),
                },
                ProofStatement::Qed {
                    value: "checked".into(),
                },
            ],
        },
    }
}

#[test]
fn accepts_finite_dev_certificate_with_generic_labels() {
    let report = verify(&accepting_certificate()).expect("certificate should verify");
    assert_eq!(report.instabilities.len(), 0);
    assert!(report.checked_rows.union_composition > 0);
}

#[test]
fn accepts_native_proof_scripts() {
    let mut cert = accepting_certificate();
    cert.proofs.push(proof(
        "causal_step",
        PropositionKind::DevFrame,
        "audit",
        RowKind::Relation,
        PrimitiveRule::DevFrameFromRelation,
    ));
    cert.proofs.push(proof(
        "backend_checked",
        PropositionKind::BackendAdmissible,
        "compile",
        RowKind::Backend,
        PrimitiveRule::BackendAdmissibleFromBackend,
    ));

    let report = verify(&cert).expect("native proof scripts should verify");
    assert_eq!(report.checked_rows.proofs, 2);
}

#[test]
fn accepts_riscv_machine_contracts_with_rocq_artifact_obligations() {
    let mut cert = accepting_certificate();
    cert.proof_artifacts.push(ProofArtifact {
        name: "rv64_rocq".into(),
        prover: ProverKind::Rocq,
        module: "proofs/rocq/EntanglementRiscV.v".into(),
        digest: "sha256:d9c118f713688605f18c50cbc090181dd74d3bbc530566473a9c860b2ba5405d".into(),
        obligations: vec![
            "rv64_rocq".into(),
            "rv64".into(),
            "host".into(),
            "add".into(),
            "windows_x64".into(),
        ],
        evidence: "coqc_checked".into(),
    });
    cert.machines.push(MachineContract {
        id: "rv64".into(),
        isa: "riscv".into(),
        profile: "rv64imac".into(),
        word_bits: 64,
        endianness: Endianness::Little,
        memory_model: MachineMemoryModel::RiscvRvwmo,
        semantic_source: "sail:riscv/sail-riscv@adopted-formal-model".into(),
        source_digest: "sha256:8168545f5b6539e656716b970aa2b101a557ef1e37f45cbf42ad73c6b4b37670"
            .into(),
        evidence: "rv64_sail_source".into(),
    });
    cert.memory.push(MemoryContract {
        name: "host".into(),
        machine: "rv64".into(),
        address_bits: 64,
        ordering: MachineMemoryModel::RiscvRvwmo,
        regions: vec![MemoryRegion {
            name: "ram".into(),
            base: 0,
            size: 4096,
            permissions: vec![MemoryPermission::Read, MemoryPermission::Write],
        }],
        frame_conditions: vec!["x-registers".into(), "pc".into()],
        evidence: "host_memory_frame".into(),
    });
    cert.instructions.push(InstructionContract {
        name: "add".into(),
        machine: "rv64".into(),
        mnemonic: "ADD".into(),
        encoding: "rv64-r-type-add".into(),
        semantics: "sail(\"ADD\")".into(),
        effects: vec!["read:rs1".into(), "read:rs2".into(), "write:rd".into()],
        proof_artifact: "rv64_rocq".into(),
        evidence: "add_sail_semantics".into(),
    });
    cert.abis.push(AbiContract {
        name: "windows_x64".into(),
        machine: "rv64".into(),
        target_triple: "x86_64-pc-windows-msvc".into(),
        object_format: "pe-coff".into(),
        calling_convention: "win64".into(),
        external_policy: "explicit".into(),
        evidence: "windows_x64_boundary".into(),
    });
    cert.proofs.push(proof(
        "artifact_checked",
        PropositionKind::ProofArtifactChecked,
        "rv64_rocq",
        RowKind::ProofArtifact,
        PrimitiveRule::ProofArtifactCheckedFromArtifact,
    ));
    cert.proofs.push(rocq_proof(
        "rv64_checked",
        PropositionKind::MachineAdmissible,
        "rv64",
    ));
    cert.proofs.push(rocq_proof(
        "host_memory_checked",
        PropositionKind::MemoryAdmissible,
        "host",
    ));
    cert.proofs.push(rocq_proof(
        "add_refines",
        PropositionKind::InstructionRefines,
        "add",
    ));
    cert.proofs.push(rocq_proof(
        "windows_boundary_checked",
        PropositionKind::AbiAdmissible,
        "windows_x64",
    ));

    let report = verify(&cert).expect("RISC-V machine contract should verify");

    assert_eq!(report.checked_rows.machines, 1);
    assert_eq!(report.checked_rows.instructions, 1);
    assert_eq!(report.checked_rows.proof_artifacts, 1);
    assert_eq!(report.checked_rows.proofs, 5);
}

#[test]
fn accepts_proved_workspace_transform_contracts() {
    let mut cert = accepting_certificate();
    cert.workspaces.push(WorkspaceContract {
        name: "repo".into(),
        boundary: "filesystem".into(),
        access: ResourceAccess::Write,
        evidence: "repo_boundary".into(),
    });
    cert.parsers.push(ParserContract {
        name: "rust".into(),
        language: "rust".into(),
        adapter: "tree-sitter".into(),
        evidence: "rust_parser_contract".into(),
    });
    cert.selections.push(SelectionContract {
        name: "code".into(),
        predicate: "parsed_by(rust)".into(),
        evidence: "parser_coverage".into(),
    });
    cert.transforms.push(TransformContract {
        name: "strip_comments".into(),
        operation: "remove_comments".into(),
        target: TransformTarget::Selection("code".into()),
        destination: None,
        predicate: None,
        replacement: None,
        evidence: "comment_ranges".into(),
    });
    cert.validators.push(ValidatorContract {
        name: "build".into(),
        argv: vec!["cargo".into(), "test".into()],
        evidence: "build_still_passes".into(),
    });
    cert.proofs.push(proof(
        "rust_parser",
        PropositionKind::ParserAdmissible,
        "rust",
        RowKind::Parser,
        PrimitiveRule::ParserAdmissibleFromParser,
    ));
    cert.proofs.push(proof(
        "code_selection",
        PropositionKind::SelectionAdmissible,
        "code",
        RowKind::Selection,
        PrimitiveRule::SelectionAdmissibleFromSelection,
    ));
    cert.proofs.push(proof(
        "comments_safe",
        PropositionKind::TransformAdmissible,
        "strip_comments",
        RowKind::Transform,
        PrimitiveRule::TransformAdmissibleFromTransform,
    ));
    cert.proofs.push(proof(
        "build_safe",
        PropositionKind::ValidatorAdmissible,
        "build",
        RowKind::Validator,
        PrimitiveRule::ValidatorAdmissibleFromValidator,
    ));

    let report = verify(&cert).expect("proved workspace transforms should verify");
    assert_eq!(report.checked_rows.transforms, 1);
    assert_eq!(report.checked_rows.validators, 1);
    assert_eq!(report.checked_rows.proofs, 4);
}

#[test]
fn accepts_proved_graphics_contracts() {
    let mut cert = accepting_certificate();
    cert.graphics.push(GraphicContract {
        name: "scene".into(),
        entry: "main".into(),
        source_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .into(),
        imports: vec!["graphics.raster".into()],
        evidence: "scene_trace".into(),
    });
    cert.render_targets.push(RenderTargetContract {
        name: "frame".into(),
        width: 640,
        height: 360,
        format: "rgba8".into(),
        evidence: "target_trace".into(),
    });
    cert.render_pipelines.push(RenderPipelineContract {
        name: "pipe".into(),
        graphics: "scene".into(),
        target: "frame".into(),
        entry: "main".into(),
        mode: "native".into(),
        evidence: "pipe_trace".into(),
    });
    cert.benchmarks.push(BenchmarkContract {
        name: "bench".into(),
        graphics: "scene".into(),
        entry: "main".into(),
        warmup: 1,
        iterations: 2,
        evidence: "bench_trace".into(),
    });
    cert.proofs.push(proof(
        "scene_ok",
        PropositionKind::GraphicsAdmissible,
        "scene",
        RowKind::Graphics,
        PrimitiveRule::GraphicsAdmissibleFromGraphics,
    ));
    cert.proofs.push(proof(
        "target_ok",
        PropositionKind::RenderTargetAdmissible,
        "frame",
        RowKind::RenderTarget,
        PrimitiveRule::RenderTargetAdmissibleFromRenderTarget,
    ));
    cert.proofs.push(proof(
        "pipeline_ok",
        PropositionKind::RenderPipelineAdmissible,
        "pipe",
        RowKind::RenderPipeline,
        PrimitiveRule::RenderPipelineAdmissibleFromRenderPipeline,
    ));
    cert.proofs.push(proof(
        "bench_ok",
        PropositionKind::BenchmarkAdmissible,
        "bench",
        RowKind::Benchmark,
        PrimitiveRule::BenchmarkAdmissibleFromBenchmark,
    ));

    let report = verify(&cert).expect("graphics contracts verify");
    assert_eq!(report.checked_rows.graphics, 1);
    assert_eq!(report.checked_rows.render_targets, 1);
    assert_eq!(report.checked_rows.render_pipelines, 1);
    assert_eq!(report.checked_rows.benchmarks, 1);
}

#[test]
fn rejects_graphics_contract_without_proof() {
    let mut cert = accepting_certificate();
    cert.graphics.push(GraphicContract {
        name: "scene".into(),
        entry: "main".into(),
        source_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .into(),
        imports: vec![],
        evidence: "scene_trace".into(),
    });

    let err = verify(&cert).expect_err("graphics rows require proof");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::ProofGap,
            ..
        }
    ));
}

#[test]
fn rejects_workspace_transform_without_proof() {
    let mut cert = accepting_certificate();
    cert.parsers.push(ParserContract {
        name: "rust".into(),
        language: "rust".into(),
        adapter: "tree-sitter".into(),
        evidence: "rust_parser_contract".into(),
    });

    let err = verify(&cert).expect_err("parser rows require proof obligations");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::ProofGap,
            ..
        }
    ));
}

#[test]
fn rejects_unknown_parser_adapter() {
    let mut cert = accepting_certificate();
    cert.parsers.push(ParserContract {
        name: "python".into(),
        language: "python".into(),
        adapter: "tree-sitter".into(),
        evidence: "python_parser_contract".into(),
    });

    let err = verify(&cert).expect_err("adapter registry must fail closed");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::ParserInadmissible,
            ..
        }
    ));
}

#[test]
fn accepts_c_cpp_and_rust_tree_sitter_parser_rows() {
    let mut cert = accepting_certificate();
    for name in ["rust", "c", "cpp"] {
        cert.parsers.push(ParserContract {
            name: name.into(),
            language: name.into(),
            adapter: "tree-sitter".into(),
            evidence: format!("{name}_parser_contract"),
        });
        cert.proofs.push(proof(
            &format!("{name}_parser"),
            PropositionKind::ParserAdmissible,
            name,
            RowKind::Parser,
            PrimitiveRule::ParserAdmissibleFromParser,
        ));
    }

    let report = verify(&cert).expect("registered parser rows should verify");
    assert_eq!(report.checked_rows.parsers, 3);
    assert_eq!(report.checked_rows.proofs, 3);
}

#[test]
fn rejects_missing_explicit_evidence_rows() {
    let mut cert = accepting_certificate();
    cert.program_states = vec![ProgramState {
        name: "heap".into(),
        sort: "Resource".into(),
    }];
    cert.invariants.push(ent_core::InvariantContract {
        name: "auth_preserved".into(),
        before: 1.0,
        after: 1.0,
        tolerance: 0.0,
        evidence: String::new(),
    });

    let err = verify(&cert).expect_err("kernel must reject evidence-free invariant rows");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::EvidenceMissing,
            ..
        }
    ));
}

#[test]
fn rejects_invalid_proof_script_as_proof_gap() {
    let mut cert = accepting_certificate();
    cert.proofs.push(ProofCertificate {
        name: "bad_proof".into(),
        proposition: Proposition {
            kind: PropositionKind::DevFrame,
            subject: "audit".into(),
        },
        script: ProofScript {
            theorem: "bad_proof".into(),
            statements: vec![
                ProofStatement::BindRow {
                    name: "row".into(),
                    kind: RowKind::Relation,
                    subject: "audit".into(),
                },
                ProofStatement::ApplyRule {
                    name: "fact".into(),
                    rule: PrimitiveRule::DevFrameFromRelation,
                    args: vec!["row".into()],
                },
            ],
        },
    });

    let err = verify(&cert).expect_err("proof scripts without qed must not verify");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::ProofGap,
            ..
        }
    ));
}

#[test]
fn rejects_bad_union_composition_as_missing_midpoint_instability() {
    let mut cert = accepting_certificate();
    cert.modal_worlds.push(StateId::from("s1"));
    cert.root_world = StateId::from("s0");
    cert.types.push((StateId::from("s1"), vec![]));
    for rel in &mut cert.relations {
        rel.pairs = vec![
            (StateId::from("s0"), StateId::from("s0")),
            (StateId::from("s1"), StateId::from("s1")),
        ];
        if rel.label == Label::grand(&cert.dimensions) {
            rel.pairs.push((StateId::from("s0"), StateId::from("s1")));
            rel.pairs.push((StateId::from("s1"), StateId::from("s0")));
        }
    }

    let err = verify(&cert).expect_err("grand edge without singleton midpoint must reject");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::MissingMidpoint,
            ..
        }
    ));
}

#[test]
fn rejects_modal_truth_mismatch_and_reports_state() {
    let mut cert = accepting_certificate();
    cert.types[0]
        .1
        .retain(|formula| !matches!(formula, KernelFormula::Diamond(_, _)));

    let err = verify(&cert).expect_err("missing positive diamond truth row must reject");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::ModalTruthMismatch,
            ..
        }
    ));
    assert!(err.to_string().contains("s0"));
}

#[test]
fn rejects_probability_mass_that_does_not_normalize() {
    let mut cert = accepting_certificate();
    cert.probabilities.push(ent_core::ProbabilityContract {
        name: "branch_prob".into(),
        state: StateId::from("s0"),
        weights: vec![("left".into(), 0.75), ("right".into(), 0.10)],
        tolerance: 0.0001,
        evidence: "bad-mass-fixture".into(),
    });

    let err = verify(&cert).expect_err("probability mass must be checked by kernel");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::ProbabilityDrift,
            ..
        }
    ));
}

#[test]
fn rejects_public_restriction_that_deletes_required_factor_midpoint() {
    let agents = vec!["one".into(), "two".into()];
    let states = vec![
        StateId::from("s00"),
        StateId::from("s10"),
        StateId::from("s01"),
        StateId::from("s11"),
    ];
    let labels = Label::powerset(&agents);
    let relations = labels
        .iter()
        .map(|label| {
            let dimensions = agents.clone();
            let pairs = states
                .iter()
                .enumerate()
                .flat_map(|(left_idx, left)| {
                    states.iter().enumerate().filter_map({
                        let label = label.clone();
                        let dimensions = dimensions.clone();
                        move |(right_idx, right)| {
                            dimensions
                                .iter()
                                .enumerate()
                                .all(|(idx, agent)| {
                                    label.members.contains(agent)
                                        || ((left_idx >> idx) & 1usize)
                                            == ((right_idx >> idx) & 1usize)
                                })
                                .then(|| (left.clone(), right.clone()))
                        }
                    })
                })
                .collect();
            RelationTable::new(label.clone(), pairs)
        })
        .collect();

    let mut cert = Certificate {
        version: CERTIFICATE_SCHEMA_VERSION,
        world: "UnsafeRestriction".into(),
        dimensions: agents,
        program_states: vec![ProgramState {
            name: "artifact".into(),
            sort: "Resource".into(),
        }],
        modal_worlds: states.clone(),
        root_world: StateId::from("s00"),
        closure: vec![KernelFormula::Atom("p".into())],
        types: states
            .iter()
            .cloned()
            .map(|state| (state, vec![KernelFormula::Atom("p".into())]))
            .collect(),
        relation_names: vec!["restrict".into()],
        relations,
        factors: vec![],
        diamonds: vec![],
        invariants: vec![],
        resources: vec![],
        probabilities: vec![],
        ad: vec![],
        backends: vec![],
        external_capabilities: vec![],
        workspaces: vec![],
        parsers: vec![],
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
        memory: vec![],
        instructions: vec![],
        abis: vec![],
        proof_artifacts: vec![],
        proofs: vec![],
        require_coordinate_separation: true,
        public_survivors: Some(vec![StateId::from("s00"), StateId::from("s11")]),
        formula: KernelFormula::Atom("p".into()),
    };
    let err = verify(&cert).expect_err("survivors delete both mixed-corner midpoints");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::FactorClosureFailure,
            ..
        }
    ));

    cert.public_survivors = Some(vec![
        StateId::from("s00"),
        StateId::from("s10"),
        StateId::from("s01"),
        StateId::from("s11"),
    ]);
    verify(&cert).expect("full public image preserves factor closure");
}
