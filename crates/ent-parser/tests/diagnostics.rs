use ent_parser::{parse_world_diagnostic, SourceSpan};

#[test]
fn malformed_relation_reports_span_for_the_declaration() {
    let source = r#"
world Bad(agent A) {
  state truth : Semantic
  relation step[c Set<A>] preserves truth changes truth[c]
}
"#;

    let diagnostic =
        parse_world_diagnostic(source).expect_err("malformed relation should return diagnostic");
    let expected_start = source.find("relation step").expect("relation line exists");
    let expected_end = source[expected_start..]
        .find('\n')
        .map(|idx| expected_start + idx)
        .unwrap();

    assert_eq!(
        diagnostic.span,
        SourceSpan {
            start: expected_start,
            end: expected_end
        }
    );
    assert_eq!(diagnostic.kind, "malformed-declaration");
    assert!(diagnostic.message.contains("relation step"));
}

#[test]
fn unsupported_item_reports_span_for_unknown_line() {
    let source = r#"
world Bad(agent A) {
  state truth : Semantic
  tactic intros
}
"#;

    let diagnostic =
        parse_world_diagnostic(source).expect_err("unsupported item should return diagnostic");
    let expected_start = source.find("tactic intros").expect("unknown line exists");

    assert_eq!(diagnostic.span.start, expected_start);
    assert_eq!(diagnostic.kind, "unsupported-item");
    assert_eq!(
        diagnostic.message,
        "unsupported top-level item: tactic intros"
    );
}
