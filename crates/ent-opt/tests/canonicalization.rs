use ent_core::{
    Certificate, ExternalContract, KernelFormula, Label, ProgramState, RelationTable,
    ResourceAccess, StateId, CERTIFICATE_SCHEMA_VERSION,
};
use ent_opt::canonicalize_certificate;

fn unsorted_certificate() -> Certificate {
    let dimensions = vec!["b".to_owned(), "a".to_owned()];
    let states = vec![StateId::from("s0")];
    let identity = vec![(StateId::from("s0"), StateId::from("s0"))];
    let relations = Label::powerset(&dimensions)
        .into_iter()
        .rev()
        .map(|label| RelationTable::new(label, identity.clone()))
        .collect();

    Certificate {
        version: CERTIFICATE_SCHEMA_VERSION,
        world: "Canonical".into(),
        dimensions,
        program_states: vec![
            ProgramState {
                name: "z".into(),
                sort: "Resource".into(),
            },
            ProgramState {
                name: "a".into(),
                sort: "Semantic".into(),
            },
        ],
        modal_worlds: states.clone(),
        root_world: StateId::from("s0"),
        formula: KernelFormula::Atom("p".into()),
        closure: vec![KernelFormula::Atom("p".into())],
        types: vec![(StateId::from("s0"), vec![KernelFormula::Atom("p".into())])],
        relation_names: vec!["z_rel".into(), "a_rel".into()],
        relations,
        factors: vec![],
        diamonds: vec![],
        invariants: vec![],
        resources: vec![],
        probabilities: vec![],
        ad: vec![],
        backends: vec![],
        external_capabilities: vec![
            ExternalContract {
                name: "z_ffi".into(),
                interface: "runtime_call".into(),
                state: StateId::from("s0"),
                resource: "z".into(),
                access: ResourceAccess::Read,
                admissible: true,
                evidence: "z_ffi_trace".into(),
            },
            ExternalContract {
                name: "a_ffi".into(),
                interface: "runtime_call".into(),
                state: StateId::from("s0"),
                resource: "a".into(),
                access: ResourceAccess::Read,
                admissible: true,
                evidence: "a_ffi_trace".into(),
            },
        ],
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
        require_coordinate_separation: false,
        public_survivors: None,
    }
}

#[test]
fn canonicalization_reorders_non_semantic_rows_and_replays_kernel_check() {
    let rewrite = canonicalize_certificate(&unsorted_certificate())
        .expect("canonicalization should preserve kernel validity");

    assert_eq!(rewrite.name, "canonicalize-certificate-v7");
    assert_eq!(rewrite.after.dimensions, vec!["a", "b"]);
    assert_eq!(rewrite.after.program_states[0].name, "a");
    assert_eq!(rewrite.after.relation_names, vec!["a_rel", "z_rel"]);
    assert_eq!(rewrite.after.external_capabilities[0].name, "a_ffi");
    assert!(rewrite.verification.checked_rows.union_composition > 0);
}
