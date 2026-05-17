use ent_core::CERTIFICATE_SCHEMA_VERSION;
use ent_elab::{elaborate_source, ElabError};
use ent_kernel::verify;
use ent_parser::parse_world;

const EXPLICIT_SOURCE: &str = r#"
world VerifiedStore(agent Client, agent Runtime) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<Client>] preserves truth changes heap[c]
  law step[c] ; step[d] == step[c union d]

  invariant auth_preserved(heap) before 1.0 after 1.0 tolerance 0.0 evidence auth_trace
  effect put uses heap write evidence heap_put_single_writer
  evolve put(dt: f32) by metal differentiable evidence metal_put_contract
  ad put tangent d_put adjoint adj_put law identity evidence put_ad_contract
  evolve secure_eval(dt: f32) by private-ane evidence ane_secure_contract
  measure branch_prob weights allow=0.5, deny=0.5 tolerance 0.000001 evidence branch_mass_trace

  theorem causal_step : dev_frame(step)
  theorem linear_heap : resource_linear(heap)
  theorem mass_branch : probability_normalizes(branch_prob)
  theorem auth_ok : invariant_preserved(auth_preserved)
  theorem put_backend : backend_admissible(put)
  theorem secure_backend : backend_admissible(secure_eval)
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
  proof secure_backend {
    let row = row backend secure_eval
    let fact = rule backend_admissible_from_backend(row)
    qed fact
  }
}
"#;

#[test]
fn parser_preserves_source_spans_and_evidence_rows() {
    let ast = parse_world(EXPLICIT_SOURCE).expect("explicit evidence syntax should parse");

    assert_eq!(ast.name, "VerifiedStore");
    assert_eq!(ast.span.start, EXPLICIT_SOURCE.find("world ").unwrap());
    assert!(ast.span.end <= EXPLICIT_SOURCE.len());
    assert_eq!(ast.invariants[0].evidence, "auth_trace");
    assert!(ast.invariants[0].span.start < ast.invariants[0].span.end);
    assert_eq!(ast.effects[0].evidence, "heap_put_single_writer");
    assert_eq!(ast.evolves[0].evidence, "metal_put_contract");
    assert_eq!(ast.evolves[1].backend, "private-ane");
    assert_eq!(ast.ad[0].evidence, "put_ad_contract");
    assert_eq!(
        ast.measures[0].weights,
        vec![("allow".to_owned(), 0.5), ("deny".to_owned(), 0.5)]
    );
}

#[test]
fn elaborator_produces_current_certificate_without_synthetic_evidence() {
    let cert = elaborate_source(EXPLICIT_SOURCE).expect("explicit evidence should elaborate");

    assert_eq!(cert.version, CERTIFICATE_SCHEMA_VERSION);
    assert_eq!(cert.program_states[0].name, "truth");
    assert!(cert.modal_worlds.len() >= 2);
    assert!(cert.modal_worlds.contains(&cert.root_world));
    assert_eq!(cert.invariants[0].evidence, "auth_trace");
    assert_eq!(cert.resources[0].evidence, "heap_put_single_writer");
    assert_eq!(cert.probabilities[0].weights.len(), 2);
    assert_eq!(cert.probabilities[0].evidence, "branch_mass_trace");
    assert_eq!(cert.ad[0].evidence, "put_ad_contract");
    assert_eq!(cert.backends[1].evidence, "ane_secure_contract");

    let report = verify(&cert).expect("explicit certificate should verify");
    assert_eq!(report.checked_rows.proofs, 6);
}

#[test]
fn elaborator_lowers_external_capability_to_kernel_reducible_proof() {
    let source = r#"
world ExternalBoundary(agent Client, agent Runtime) {
  state truth : Semantic
  state heap : Resource
  relation step[c: Set<Client>] preserves truth changes heap[c]
  law step[c] ; step[d] == step[c union d]
  external ffi interface runtime_call uses heap read evidence ffi_manifest_trace
  theorem causal_step : dev_frame(step)
  theorem ffi_boundary : external_admissible(ffi)
  proof causal_step {
    let row = row relation step
    let fact = rule dev_frame_from_relation(row)
    qed fact
  }
  proof ffi_boundary {
    let row = row external ffi
    let fact = rule external_admissible_from_external(row)
    qed fact
  }
}
"#;

    let cert = elaborate_source(source).expect("external capability should elaborate");
    assert_eq!(cert.external_capabilities.len(), 1);
    assert_eq!(cert.external_capabilities[0].name, "ffi");
    assert_eq!(cert.external_capabilities[0].interface, "runtime_call");
    assert_eq!(cert.external_capabilities[0].evidence, "ffi_manifest_trace");

    let report = verify(&cert).expect("external capability proof should verify");
    assert_eq!(report.checked_rows.external_capabilities, 1);
    assert_eq!(report.checked_rows.proofs, 2);
}

#[test]
fn elaborator_rejects_declarations_that_need_evidence_instead_of_inventing_it() {
    let implicit = r#"
world Implicit(agent Client) {
  state heap : Resource
  relation step[c: Set<Client>] preserves heap changes heap[c]
  invariant auth_preserved(heap)
  evolve put(dt: f32) by metal differentiable
  measure branch_prob normalizes 1.0
}
"#;

    let err = elaborate_source(implicit).expect_err("elaborator must not synthesize evidence");
    assert!(matches!(err, ElabError::MissingEvidence { .. }));
}

#[test]
fn elaborator_preserves_parser_diagnostic_spans() {
    let source = r#"
world Bad(agent Client) {
  state heap : Resource
  relation step[c Set<Client>] preserves heap changes heap[c]
}
"#;

    let err = elaborate_source(source).expect_err("malformed syntax must fail");
    assert!(matches!(err, ElabError::ParseDiagnostic(_)));
    assert!(err.to_string().contains("malformed-declaration"));
    assert!(err.to_string().contains("relation step"));
    assert!(err.to_string().contains("bytes"));
}
