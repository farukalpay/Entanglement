use ent_parser::{parse_world, TransformTargetDecl};

#[test]
fn parser_accepts_workspace_transform_declarations() {
    let source = r#"
world RepoCleanup(agent Operator, space Workspace) {
  state tree : Resource
  workspace repo uses filesystem write evidence repo_boundary
  parser rust language rust via tree-sitter evidence rust_parser_contract
  document markdown via pulldown_cmark evidence markdown_contract
  select code = files where parsed_by(rust) evidence parser_coverage
  transform strip_comments remove_comments on code evidence comment_ranges
  transform flatten flatten_modules on code into "flat" evidence rust_module_rewrite
  transform readme_lines delete_lines on file("README.md") where contains_word("legacy") evidence line_delete
  transform rename replace_word on file("README.md") from "old" to "new" evidence word_replace
  validator build argv ["cargo", "test"] evidence build_still_passes
}
"#;

    let ast = parse_world(source).expect("workspace transform syntax should parse");
    assert_eq!(ast.workspaces[0].name, "repo");
    assert_eq!(ast.parsers[0].language, "rust");
    assert_eq!(ast.documents[0].adapter, "pulldown_cmark");
    assert_eq!(ast.selections[0].predicate, "parsed_by(rust)");
    assert_eq!(ast.transforms[1].destination.as_deref(), Some("flat"));
    assert_eq!(
        ast.transforms[2].target,
        TransformTargetDecl::File("README.md".to_owned())
    );
    assert_eq!(ast.transforms[3].replacement.as_ref().unwrap().from, "old");
    assert_eq!(ast.validators[0].argv, vec!["cargo", "test"]);
}

#[test]
fn parser_accepts_protocol_declarations() {
    let source = r#"
world ProtocolFlow(role Maintainer, space Workspace) {
  state tree : Resource
  objective workspace_upgrade priority critical summary "Make checked workspace changes easier to stage and review" evidence roadmap_record
  milestone reviewable_changes objective workspace_upgrade state active due "2026-06-01" evidence schedule_record
  task dry_run_report milestone reviewable_changes kind implement state ready owner maintainer requires [] outputs ["apply-report"] title "Report changes before writing them" evidence task_record
  gate dry_run_checks task dry_run_report check "validator:cargo_test" expect "pass" evidence gate_record
  decision report_shape scope task:dry_run_report choose "reuse apply report" because "one report shape keeps review and write paths comparable" alternatives ["separate summary"] evidence decision_record
  note review_note scope gate:dry_run_checks text "Validators run against the staged tree before writes are materialized" tags [workspace,review] evidence note_record
}
"#;

    let ast = parse_world(source).expect("protocol syntax should parse");

    assert_eq!(ast.objectives[0].priority, "critical");
    assert_eq!(ast.milestones[0].objective, "workspace_upgrade");
    assert_eq!(ast.tasks[0].outputs, vec!["apply-report"]);
    assert_eq!(ast.gates[0].check, "validator:cargo_test");
    assert_eq!(ast.decisions[0].alternatives, vec!["separate summary"]);
    assert_eq!(ast.notes[0].tags, vec!["workspace", "review"]);
}
