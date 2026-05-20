use ent_core::{
    AdContract, BackendContract, Certificate, ExternalContract, InstabilityKind, KernelFormula,
    Label, ProgramState, ProofCertificate, RelationTable, ResourceAccess, StateId,
    CERTIFICATE_SCHEMA_VERSION,
};
use ent_kernel::{verify, KernelError};
use ent_proof::{
    PrimitiveRule, ProofScript, ProofStatement, Proposition, PropositionKind, RowKind,
};

fn base_certificate() -> Certificate {
    let dimensions = vec!["agent:Client".into()];
    let states = vec![StateId::from("s0"), StateId::from("s1")];
    let relations = Label::powerset(&dimensions)
        .into_iter()
        .map(|label| {
            let pairs = if label.is_empty() {
                vec![
                    (StateId::from("s0"), StateId::from("s0")),
                    (StateId::from("s1"), StateId::from("s1")),
                ]
            } else {
                states
                    .iter()
                    .flat_map(|left| {
                        states
                            .iter()
                            .map(move |right| (left.clone(), right.clone()))
                    })
                    .collect()
            };
            RelationTable::new(label, pairs)
        })
        .collect();
    let formula = KernelFormula::Atom("p".into());
    let closure = vec![
        formula.clone(),
        KernelFormula::Box(Label::empty(), Box::new(formula.clone())),
        KernelFormula::Diamond(Label::empty(), Box::new(formula.clone())),
    ];
    let types = states
        .iter()
        .cloned()
        .map(|state| (state, closure.clone()))
        .collect();

    Certificate {
        version: CERTIFICATE_SCHEMA_VERSION,
        world: "ExternalAudit".into(),
        dimensions,
        program_states: vec![ProgramState {
            name: "heap".into(),
            sort: "Resource".into(),
        }],
        modal_worlds: states.clone(),
        root_world: StateId::from("s0"),
        formula,
        closure,
        types,
        relation_names: vec!["step".into()],
        relations,
        factors: vec![],
        diamonds: vec![],
        invariants: vec![],
        resources: vec![],
        probabilities: vec![],
        ad: vec![AdContract::identity("realization")],
        backends: vec![BackendContract::cpu("realization")],
        external_capabilities: vec![],
        workspaces: vec![],
        parsers: vec![],
        selections: vec![],
        transforms: vec![],
        validators: vec![],
        objectives: vec![],
        milestones: vec![],
        tasks: vec![],
        gates: vec![],
        decisions: vec![],
        notes: vec![],
        graphics: vec![],
        render_targets: vec![],
        render_pipelines: vec![],
        benchmarks: vec![],
        tensors: vec![],
        accelerators: vec![],
        datasets: vec![],
        models: vec![],
        trainings: vec![],
        canonicals: vec![],
        artifacts: vec![],
        lowerings: vec![],
        executors: vec![],
        witnesses: vec![],
        machines: vec![],
        memory: vec![],
        instructions: vec![],
        abis: vec![],
        proof_artifacts: vec![],
        proofs: vec![],
        require_coordinate_separation: true,
        public_survivors: None,
    }
}

#[test]
fn accepts_kernel_reducible_external_capability_obligation() {
    let mut cert = base_certificate();
    cert.external_capabilities.push(ExternalContract {
        name: "ffi".into(),
        interface: "runtime_call".into(),
        state: StateId::from("s0"),
        resource: "heap".into(),
        access: ResourceAccess::Read,
        admissible: true,
        evidence: "ffi_manifest_trace".into(),
    });
    cert.proofs.push(ProofCertificate {
        name: "ffi_boundary".into(),
        proposition: Proposition {
            kind: PropositionKind::ExternalAdmissible,
            subject: "ffi".into(),
        },
        script: ProofScript {
            theorem: "ffi_boundary".into(),
            statements: vec![
                ProofStatement::BindRow {
                    name: "row".into(),
                    kind: RowKind::External,
                    subject: "ffi".into(),
                },
                ProofStatement::ApplyRule {
                    name: "fact".into(),
                    rule: PrimitiveRule::ExternalAdmissibleFromExternal,
                    args: vec!["row".into()],
                },
                ProofStatement::Qed {
                    value: "fact".into(),
                },
            ],
        },
    });

    let report = verify(&cert).expect("explicit external capability should verify");
    assert_eq!(report.checked_rows.external_capabilities, 1);
    assert_eq!(report.checked_rows.proofs, 1);
}

#[test]
fn rejects_external_capability_without_evidence() {
    let mut cert = base_certificate();
    cert.external_capabilities.push(ExternalContract {
        name: "ffi".into(),
        interface: "runtime_call".into(),
        state: StateId::from("s0"),
        resource: "heap".into(),
        access: ResourceAccess::Read,
        admissible: true,
        evidence: String::new(),
    });

    let err = verify(&cert).expect_err("external rows must carry explicit evidence");
    assert!(matches!(
        err,
        KernelError::Instability {
            kind: InstabilityKind::EvidenceMissing,
            ..
        }
    ));
}
