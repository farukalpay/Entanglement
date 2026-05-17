use ent_parser::{parse_world, EffectAccess};

#[test]
fn parser_accepts_explicit_external_capability_rows() {
    let source = r#"
world HostBoundary(agent Client) {
  state heap : Resource
  external ffi interface runtime_call uses heap read evidence ffi_manifest_trace
}
"#;

    let ast = parse_world(source).expect("external capability syntax should parse");
    assert_eq!(ast.externals.len(), 1);
    assert_eq!(ast.externals[0].name, "ffi");
    assert_eq!(ast.externals[0].interface, "runtime_call");
    assert_eq!(ast.externals[0].resource, "heap");
    assert_eq!(ast.externals[0].access, EffectAccess::Read);
    assert_eq!(ast.externals[0].evidence, "ffi_manifest_trace");
    assert!(ast.externals[0].span.start < ast.externals[0].span.end);
}
