use ent_core::{
    Certificate, KernelFormula, Label, ProgramState, RelationTable, StateId,
    CERTIFICATE_SCHEMA_VERSION,
};
use ent_proof::{ProofCertificate, ProofScript, Proposition, PropositionKind};

#[test]
fn certificate_v4_roundtrips_with_native_and_machine_contract_fields() {
    let cert = minimal_certificate();
    assert_eq!(cert.version, CERTIFICATE_SCHEMA_VERSION);

    let json = serde_json::to_value(&cert).expect("serialize certificate");
    assert_eq!(json["version"], CERTIFICATE_SCHEMA_VERSION);
    assert!(json.get("program_states").is_some());
    assert!(json.get("modal_worlds").is_some());
    assert!(json.get("root_world").is_some());
    assert!(json.get("states").is_none());
    assert!(json.get("root").is_none());
    assert!(json.get("external_capabilities").is_some());
    assert!(json.get("machines").is_some());
    assert!(json.get("proof_artifacts").is_some());
    assert!(json.get("proofs").is_some());
    assert!(json.get("proof_obligations").is_none());
    assert_eq!(json["program_states"][0]["name"], "truth");

    let roundtrip: Certificate = serde_json::from_value(json).expect("deserialize certificate");
    assert_eq!(roundtrip, cert);
}

fn minimal_certificate() -> Certificate {
    let dimensions = vec!["agent:A".to_owned()];
    let worlds = vec![StateId::from("s0")];
    let labels = Label::powerset(&dimensions);
    let identity = vec![(StateId::from("s0"), StateId::from("s0"))];
    let relations = labels
        .iter()
        .map(|label| RelationTable::new(label.clone(), identity.clone()))
        .collect();

    Certificate {
        version: CERTIFICATE_SCHEMA_VERSION,
        world: "Schema".into(),
        dimensions,
        program_states: vec![ProgramState {
            name: "truth".into(),
            sort: "Semantic".into(),
        }],
        modal_worlds: worlds.clone(),
        root_world: StateId::from("s0"),
        formula: KernelFormula::Atom("p".into()),
        closure: vec![KernelFormula::Atom("p".into())],
        types: vec![(StateId::from("s0"), vec![KernelFormula::Atom("p".into())])],
        relation_names: vec!["step".into()],
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
        machines: vec![],
        memory: vec![],
        instructions: vec![],
        abis: vec![],
        proof_artifacts: vec![],
        proofs: vec![ProofCertificate {
            name: "causal_step".into(),
            proposition: Proposition {
                kind: PropositionKind::DevFrame,
                subject: "step".into(),
            },
            script: ProofScript {
                theorem: "causal_step".into(),
                statements: vec![],
            },
        }],
        require_coordinate_separation: false,
        public_survivors: None,
    }
}
