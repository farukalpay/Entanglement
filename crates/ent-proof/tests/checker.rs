use ent_proof::{
    check_proof, PrimitiveRule, ProofCheckError, ProofEnvironment, ProofScript, ProofStatement,
    Proposition, PropositionKind, RowKind,
};
use std::collections::BTreeSet;

#[derive(Default)]
struct Env {
    rows: BTreeSet<(RowKind, String)>,
    rocq: BTreeSet<(String, Proposition)>,
    valid_rules: BTreeSet<(PrimitiveRule, Vec<String>)>,
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

    fn with_rule(mut self, rule: PrimitiveRule, subjects: &[&str]) -> Self {
        self.valid_rules.insert((
            rule,
            subjects.iter().map(|subject| subject.to_string()).collect(),
        ));
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

    fn validates_rule(&self, rule: &PrimitiveRule, rows: &[(RowKind, String)]) -> bool {
        if !matches!(
            rule,
            PrimitiveRule::TraceEquivalent | PrimitiveRule::WitnessSatisfiesContract
        ) {
            return true;
        }
        self.valid_rules.contains(&(
            rule.clone(),
            rows.iter().map(|(_, subject)| subject.clone()).collect(),
        ))
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

#[test]
fn accepts_structural_runtime_boundary_rules() {
    let env = Env::default()
        .with(RowKind::Witness, "xor_run")
        .with(RowKind::Model, "xor_mlp")
        .with(RowKind::Lowering, "xor_pytorch")
        .with_rule(
            PrimitiveRule::TraceEquivalent,
            &["xor_run", "xor_mlp", "xor_pytorch"],
        );
    let proposition = Proposition {
        kind: PropositionKind::TraceEquivalent,
        subject: "xor_run".into(),
    };
    let script = ProofScript {
        theorem: "xor_trace_ok".into(),
        statements: vec![
            ProofStatement::BindRow {
                name: "witness".into(),
                kind: RowKind::Witness,
                subject: "xor_run".into(),
            },
            ProofStatement::BindRow {
                name: "model".into(),
                kind: RowKind::Model,
                subject: "xor_mlp".into(),
            },
            ProofStatement::BindRow {
                name: "lowering".into(),
                kind: RowKind::Lowering,
                subject: "xor_pytorch".into(),
            },
            ProofStatement::ApplyRule {
                name: "fact".into(),
                rule: PrimitiveRule::TraceEquivalent,
                args: vec!["witness".into(), "model".into(), "lowering".into()],
            },
            ProofStatement::Qed {
                value: "fact".into(),
            },
        ],
    };

    let report =
        check_proof("xor_trace_ok", &proposition, &script, &env).expect("proof should check");

    assert_eq!(report.checked_steps, 5);
}

#[test]
fn rejects_structural_runtime_rule_when_rows_are_unrelated() {
    let env = Env::default()
        .with(RowKind::Witness, "xor_run")
        .with(RowKind::Model, "other_model")
        .with(RowKind::Lowering, "xor_pytorch");
    let proposition = Proposition {
        kind: PropositionKind::TraceEquivalent,
        subject: "xor_run".into(),
    };
    let script = ProofScript {
        theorem: "xor_trace_ok".into(),
        statements: vec![
            ProofStatement::BindRow {
                name: "witness".into(),
                kind: RowKind::Witness,
                subject: "xor_run".into(),
            },
            ProofStatement::BindRow {
                name: "model".into(),
                kind: RowKind::Model,
                subject: "other_model".into(),
            },
            ProofStatement::BindRow {
                name: "lowering".into(),
                kind: RowKind::Lowering,
                subject: "xor_pytorch".into(),
            },
            ProofStatement::ApplyRule {
                name: "fact".into(),
                rule: PrimitiveRule::TraceEquivalent,
                args: vec!["witness".into(), "model".into(), "lowering".into()],
            },
            ProofStatement::Qed {
                value: "fact".into(),
            },
        ],
    };

    let err = check_proof("xor_trace_ok", &proposition, &script, &env)
        .expect_err("unrelated rows must reject");

    assert!(matches!(err, ProofCheckError::RuleRelationRejected { .. }));
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
