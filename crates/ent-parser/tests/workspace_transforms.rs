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
