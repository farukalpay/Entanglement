use ent_parser::parse_world;
use ent_proof::{PrimitiveRule, ProofStatement, PropositionKind, RowKind};

#[test]
fn parser_accepts_structured_proof_blocks() {
    let source = r#"
world ProofBlock(agent Client) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<Client>] preserves truth changes heap[c]
  theorem causal_step : dev_frame(step)
  proof causal_step {
    let rel = row relation step
    let fact = rule dev_frame_from_relation(rel)
    qed fact
  }
}
"#;

    let ast = parse_world(source).expect("structured proof block should parse");

    assert_eq!(ast.theorems[0].name, "causal_step");
    assert_eq!(ast.theorems[0].proposition.kind, PropositionKind::DevFrame);
    assert_eq!(ast.theorems[0].proposition.subject, "step");
    assert_eq!(ast.proofs[0].theorem, "causal_step");
    assert_eq!(
        ast.proofs[0].script.statements,
        vec![
            ProofStatement::BindRow {
                name: "rel".to_owned(),
                kind: RowKind::Relation,
                subject: "step".to_owned(),
            },
            ProofStatement::ApplyRule {
                name: "fact".to_owned(),
                rule: PrimitiveRule::DevFrameFromRelation,
                args: vec!["rel".to_owned()],
            },
            ProofStatement::Qed {
                value: "fact".to_owned(),
            },
        ]
    );
}

#[test]
fn parser_accepts_machine_rows_and_rocq_proof_blocks() {
    let source = r#"
world RiscVCore(agent Verifier) {
  state machine_state : Semantic
  machine rv64 isa riscv profile rv64imac word 64 endian little memory rvwmo via sail source "riscv/sail-riscv@ref" digest "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" evidence rv64_source
  memory host for rv64 address 64 order rvwmo region "ram:0x0:0x1000:read-write" frame "x-registers,pc" evidence host_memory
  proof-artifact rv64_rocq prover rocq module "proofs/rocq/EntanglementRiscV.v" digest "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" obligations [rv64_rocq,rv64,host,add,windows_x64] evidence coqc_checked
  instruction add in rv64 mnemonic "ADD" encoding "rv64-r-type-add" semantics sail("ADD") effects "read:rs1,read:rs2,write:rd" proof rv64_rocq evidence add_sail
  abi windows_x64 for rv64 target "x86_64-pc-windows-msvc" object pe-coff calling win64 external explicit evidence windows_boundary
  theorem add_refines : instruction_refines(add)
  proof add_refines {
    rocq module "proofs/rocq/EntanglementRiscV.v"
    qed checked
  }
}
"#;

    let ast = parse_world(source).expect("machine rows should parse");

    assert_eq!(ast.machines[0].id, "rv64");
    assert_eq!(
        ast.memories[0].regions[0].permissions,
        vec!["read", "write"]
    );
    assert_eq!(ast.instructions[0].proof_artifact, "rv64_rocq");
    assert_eq!(ast.abis[0].object_format, "pe-coff");
    assert_eq!(ast.proof_artifacts[0].obligations[3], "add");
    assert_eq!(
        ast.proofs[0].script.statements,
        vec![
            ProofStatement::UseRocq {
                module: "proofs/rocq/EntanglementRiscV.v".to_owned(),
            },
            ProofStatement::Qed {
                value: "checked".to_owned(),
            },
        ]
    );
}

#[test]
fn parser_rejects_legacy_kernel_proof_method() {
    let source = r#"
world LegacyProof(agent Client) {
  state truth : Semantic
  relation step[c: Set<Client>] preserves truth changes truth[c]
  theorem causal_step : dev_frame(step)
  proof causal_step by kernel
}
"#;

    let err = parse_world(source).expect_err("legacy proof method is no longer accepted");
    assert!(err.to_string().contains("proof block"));
}
