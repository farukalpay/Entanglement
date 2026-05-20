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

#[test]
fn parser_accepts_runtime_contract_declarations_with_endpoint_urls() {
    let source = r#"
world RuntimeContracts(agent Maintainer, space Repository) {
  runtime-ledger incident_ledger store jsonl retention "30d" fields [session,turn,tool,status] evidence incident_ledger_manifest
  runtime-policy quiet_guard approval on-request sandbox workspace-write network guarded allow [inspect_repo,local_tool_bus] deny [network_wildcard] evidence quiet_guard_policy
  runtime-session repair_studio owner maintainer mode autonomous state active ledger incident_ledger evidence repair_studio_session
  runtime-tool inspect_repo kind inspect risk low policy quiet_guard reads ["repo"] writes [] evidence inspect_repo_tool
  runtime-bridge local_tool_bus kind mcp policy quiet_guard endpoint "local://runtime/tools" exposes [inspect_repo] evidence local_tool_bridge
  runtime-hook append_outcome event post-tool-use target ledger:incident_ledger action "Append status after every call" evidence append_outcome_hook
  runtime-turn triage_loop session repair_studio policy quiet_guard tools [inspect_repo] budget 8 objective "Classify a failing command" evidence triage_turn_record
}
"#;

    let ast = parse_world(source).expect("runtime contract syntax should parse");
    assert_eq!(
        ast.runtime_ledgers[0].fields,
        vec!["session", "turn", "tool", "status"]
    );
    assert_eq!(ast.runtime_policies[0].approval, "on-request");
    assert_eq!(ast.runtime_sessions[0].ledger, "incident_ledger");
    assert_eq!(ast.runtime_tools[0].writes, Vec::<String>::new());
    assert_eq!(ast.runtime_bridges[0].endpoint, "local://runtime/tools");
    assert_eq!(ast.runtime_hooks[0].target, "ledger:incident_ledger");
    assert_eq!(ast.runtime_turns[0].budget, 8);
}

#[test]
fn parser_accepts_coordination_ledger_declarations() {
    let source = r#"
world CoordinationLedger(role Maintainer, space Repository) {
  lane core owner maintainer status active purpose "Protect central compiler work" capacity 2 evidence core_lane_record
  lane review owner maintainer status review purpose "Hold reviewed changes before release" capacity 2 evidence review_lane_record
  lane release owner maintainer status planned purpose "Prepare staged changes for publication" capacity 1 evidence release_lane_record
  claim parser_claim lane core scope file:"crates/ent-parser/src/lib.rs" mode write policy exclusive reason "Parser grammar update" evidence parser_claim_record
  handoff parser_to_kernel from core to review item claim:parser_claim state proposed summary "Parser rows ready for kernel validation" evidence parser_handoff_record
  sync kernel_merge source review target release strategy staged checks [record:coordination_checks] evidence kernel_sync_record
  checkpoint core_checkpoint lane core state green summary "Parser and kernel rows agree" blockers [] next [sync:kernel_merge] evidence core_checkpoint_record

  theorem core_lane_admissible : lane_admissible(core)
  theorem review_lane_admissible : lane_admissible(review)
  theorem release_lane_admissible : lane_admissible(release)
  theorem claim_admissible : claim_admissible(parser_claim)
  theorem handoff_admissible : handoff_admissible(parser_to_kernel)
  theorem sync_admissible : sync_admissible(kernel_merge)
  theorem checkpoint_admissible : checkpoint_admissible(core_checkpoint)

  proof core_lane_admissible {
    let row = row lane core
    let fact = rule lane_admissible_from_lane(row)
    qed fact
  }
  proof review_lane_admissible {
    let row = row lane review
    let fact = rule lane_admissible_from_lane(row)
    qed fact
  }
  proof release_lane_admissible {
    let row = row lane release
    let fact = rule lane_admissible_from_lane(row)
    qed fact
  }
  proof claim_admissible {
    let row = row claim parser_claim
    let fact = rule claim_admissible_from_claim(row)
    qed fact
  }
  proof handoff_admissible {
    let row = row handoff parser_to_kernel
    let fact = rule handoff_admissible_from_handoff(row)
    qed fact
  }
  proof sync_admissible {
    let row = row sync kernel_merge
    let fact = rule sync_admissible_from_sync(row)
    qed fact
  }
  proof checkpoint_admissible {
    let row = row checkpoint core_checkpoint
    let fact = rule checkpoint_admissible_from_checkpoint(row)
    qed fact
  }
}
"#;

    let ast = parse_world(source).expect("coordination ledger syntax should parse");
    assert_eq!(ast.lanes.len(), 3);
    assert_eq!(ast.lanes[0].capacity, 2);
    assert_eq!(ast.claims[0].scope, "file:\"crates/ent-parser/src/lib.rs\"");
    assert_eq!(ast.handoffs[0].item, "claim:parser_claim");
    assert_eq!(ast.syncs[0].checks, vec!["record:coordination_checks"]);
    assert_eq!(ast.checkpoints[0].next, vec!["sync:kernel_merge"]);
}
