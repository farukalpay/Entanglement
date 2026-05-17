use ent_core::CERTIFICATE_SCHEMA_VERSION;
use ent_elab::{elaborate_source, ElabError};
use ent_kernel::verify;
use ent_parser::parse_world;

const SOURCE: &str = r#"
world VerifiedStore(agent Client, agent Runtime) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<Client>] preserves truth changes heap[c]
  law step[c] ; step[d] == step[c union d]

  invariant auth_preserved(heap) before 1.0 after 1.0 tolerance 0.0 evidence auth_trace
  effect put uses heap write evidence heap_put_single_writer
  evolve put(dt: f32) by metal differentiable evidence metal_put_contract
  ad put tangent d_put adjoint adj_put law identity evidence put_ad_contract
  measure branch_prob weights allow=0.5, deny=0.5 tolerance 0.000001 evidence branch_mass_trace
  theorem causal_step : dev_frame(step)
  theorem linear_heap : resource_linear(heap)
  theorem mass_branch : probability_normalizes(branch_prob)
  theorem auth_ok : invariant_preserved(auth_preserved)
  theorem put_backend : backend_admissible(put)
  proof causal_step {
    let row = row relation step
    let fact = rule dev_frame_from_relation(row)
    qed fact
  }
  proof linear_heap {
    let row = row resource heap
    let fact = rule resource_linear_from_resource(row)
    qed fact
  }
  proof mass_branch {
    let row = row probability branch_prob
    let fact = rule probability_normalizes_from_probability(row)
    qed fact
  }
  proof auth_ok {
    let row = row invariant auth_preserved
    let fact = rule invariant_preserved_from_invariant(row)
    qed fact
  }
  proof put_backend {
    let row = row backend put
    let fact = rule backend_admissible_from_backend(row)
    qed fact
  }
}
"#;

#[test]
fn parses_declarative_world_without_instruction_sequence() {
    let ast = parse_world(SOURCE).expect("surface syntax should parse");
    assert_eq!(ast.name, "VerifiedStore");
    assert_eq!(ast.states.len(), 2);
    assert_eq!(ast.relations[0].name, "step");
    assert_eq!(ast.evolves[0].backend, "metal");
    assert_eq!(ast.effects[0].resource, "heap");
    assert_eq!(ast.effects[0].evidence, "heap_put_single_writer");
    assert_eq!(ast.theorems.len(), 5);
    assert_eq!(ast.proofs.len(), 5);
    assert!(ast.evolves[0].differentiable);
    assert_eq!(ast.ad.len(), 1);
}

#[test]
fn elaborates_source_into_kernel_verifiable_certificate() {
    let cert = elaborate_source(SOURCE).expect("elaboration should produce explicit certificate");
    assert_eq!(cert.world, "VerifiedStore");
    assert_eq!(cert.version, CERTIFICATE_SCHEMA_VERSION);
    assert!(
        cert.dimensions.len() >= 2,
        "dimension must be explicit after elaboration"
    );
    assert_eq!(cert.proofs.len(), 5);
    let report = verify(&cert).expect("elaborated certificate must be trusted-kernel valid");
    assert!(report.checked_rows.union_composition > 0);
    assert!(report.checked_rows.invariants > 0);
    assert!(report.checked_rows.backends > 0);
    assert_eq!(report.checked_rows.proofs, 5);
}

#[test]
fn rejects_unknown_backend_instead_of_guessing_a_runtime() {
    let source = r#"
world UnknownBackend(agent A) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<A>] preserves truth changes heap[c]
  law step[c] ; step[d] == step[c union d]
  evolve mystery(dt: f32) by quantum evidence unknown_backend_contract
}
"#;

    let err = elaborate_source(source).expect_err("unknown backend must be explicit");
    assert!(matches!(err, ElabError::UnsupportedBackend(name) if name == "quantum"));
}
