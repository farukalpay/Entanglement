use ent_proof::{
    check_proof, PrimitiveRule, ProofCheckError, ProofEnvironment, ProofScript, ProofStatement,
    Proposition, PropositionKind, RowKind,
};
use std::collections::BTreeSet;

#[derive(Default)]
struct Env {
    rows: BTreeSet<(RowKind, String)>,
    rocq: BTreeSet<(String, Proposition)>,
}

impl Env {
    fn with(mut self, kind: RowKind, subject: &str) -> Self {
        self.rows.insert((kind, subject.to_owned()));
        self
    }

    fn with_rocq(mut self, module: &str, proposition: Proposition) -> Self {
        self.rocq.insert((module.to_owned(), proposition));
        self
    }
}

impl ProofEnvironment for Env {
    fn has_row(&self, kind: &RowKind, subject: &str) -> bool {
        self.rows.contains(&(kind.clone(), subject.to_owned()))
    }

    fn has_rocq_artifact(&self, module: &str, proposition: &Proposition) -> bool {
        self.rocq
            .contains(&(module.to_owned(), proposition.clone()))
    }
}

#[test]
fn accepts_matching_primitive_rule_script() {
    let env = Env::default().with(RowKind::Relation, "step");
    let proposition = Proposition {
        kind: PropositionKind::DevFrame,
        subject: "step".into(),
    };
    let script = script(
        "causal_step",
        RowKind::Relation,
        "step",
        PrimitiveRule::DevFrameFromRelation,
    );

    let report =
        check_proof("causal_step", &proposition, &script, &env).expect("proof should check");

    assert_eq!(report.checked_steps, 3);
}

#[test]
fn rejects_unknown_certificate_row() {
    let env = Env::default();
    let proposition = Proposition {
        kind: PropositionKind::DevFrame,
        subject: "step".into(),
    };
    let script = script(
        "causal_step",
        RowKind::Relation,
        "step",
        PrimitiveRule::DevFrameFromRelation,
    );

    let err = check_proof("causal_step", &proposition, &script, &env)
        .expect_err("unknown rows must reject");

    assert!(matches!(err, ProofCheckError::UnknownRow { .. }));
}

#[test]
fn rejects_wrong_row_kind_for_rule() {
    let env = Env::default().with(RowKind::Backend, "step");
    let proposition = Proposition {
        kind: PropositionKind::DevFrame,
        subject: "step".into(),
    };
    let script = script(
        "causal_step",
        RowKind::Backend,
        "step",
        PrimitiveRule::DevFrameFromRelation,
    );

    let err = check_proof("causal_step", &proposition, &script, &env)
        .expect_err("wrong row kind must reject");

    assert!(matches!(err, ProofCheckError::WrongRowKind { .. }));
}

#[test]
fn rejects_qed_that_does_not_match_theorem() {
    let env = Env::default().with(RowKind::Backend, "compile");
    let proposition = Proposition {
        kind: PropositionKind::DevFrame,
        subject: "step".into(),
    };
    let script = script(
        "causal_step",
        RowKind::Backend,
        "compile",
        PrimitiveRule::BackendAdmissibleFromBackend,
    );

    let err = check_proof("causal_step", &proposition, &script, &env)
        .expect_err("mismatched proposition must reject");

    assert!(matches!(err, ProofCheckError::PropositionMismatch { .. }));
}

#[test]
fn rejects_missing_qed() {
    let env = Env::default().with(RowKind::Relation, "step");
    let proposition = Proposition {
        kind: PropositionKind::DevFrame,
        subject: "step".into(),
    };
    let mut script = script(
        "causal_step",
        RowKind::Relation,
        "step",
        PrimitiveRule::DevFrameFromRelation,
    );
    script.statements.pop();

    let err = check_proof("causal_step", &proposition, &script, &env)
        .expect_err("missing qed must reject");

    assert_eq!(err, ProofCheckError::MissingQed);
}

#[test]
fn accepts_rocq_checked_proof_artifact_binding() {
    let proposition = Proposition {
        kind: PropositionKind::InstructionRefines,
        subject: "add".into(),
    };
    let env = Env::default().with_rocq("proofs/rocq/EntanglementRiscV.v", proposition.clone());
    let script = ProofScript {
        theorem: "add_refines".into(),
        statements: vec![
            ProofStatement::UseRocq {
                module: "proofs/rocq/EntanglementRiscV.v".into(),
            },
            ProofStatement::Qed {
                value: "checked".into(),
            },
        ],
    };

    let report =
        check_proof("add_refines", &proposition, &script, &env).expect("Rocq proof should check");

    assert_eq!(report.checked_steps, 2);
}

fn script(theorem: &str, kind: RowKind, subject: &str, rule: PrimitiveRule) -> ProofScript {
    ProofScript {
        theorem: theorem.to_owned(),
        statements: vec![
            ProofStatement::BindRow {
                name: "row".into(),
                kind,
                subject: subject.into(),
            },
            ProofStatement::ApplyRule {
                name: "fact".into(),
                rule,
                args: vec!["row".into()],
            },
            ProofStatement::Qed {
                value: "fact".into(),
            },
        ],
    }
}
