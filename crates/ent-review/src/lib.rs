use anyhow::{Context, Result};
use ent_core::{
    Certificate, CheckedRows, DecisionContract, GateContract, MilestoneContract, NoteContract,
    ObjectiveContract, TaskContract, ValidatorContract, CERTIFICATE_SCHEMA_VERSION,
};
use ent_elab::elaborate_source;
use ent_inspect::{inspect_path, InspectOptions, InspectReport, ReadinessStatus};
use ent_kernel::verify;
use ent_transform::{
    preview_certificate, FileChange, PatchFile, TransformPreviewReport, ValidatorReport,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewOptions {
    pub include_hidden: bool,
    pub max_file_bytes: Option<u64>,
    pub include_patch: bool,
}

impl Default for ReviewOptions {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_file_bytes: Some(4 * 1024 * 1024),
            include_patch: false,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ReviewPacket {
    pub world: String,
    pub schema_version: u32,
    pub source: PathBuf,
    pub repo: PathBuf,
    pub inspection: InspectReport,
    pub plan: ReviewPlan,
    pub preview: ReviewPreview,
    pub gates: Vec<GateResult>,
    pub validators: Vec<ValidatorReport>,
    pub diagnostics: Vec<ReviewDiagnostic>,
    pub summary: ReviewSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<PatchArtifact>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReviewPlan {
    pub counts: PlanCounts,
    pub objectives: Vec<ObjectiveContract>,
    pub milestones: Vec<MilestoneContract>,
    pub tasks: Vec<TaskContract>,
    pub gates: Vec<GateContract>,
    pub decisions: Vec<DecisionContract>,
    pub notes: Vec<NoteContract>,
    pub tasks_by_state: BTreeMap<String, usize>,
    pub tasks_by_milestone: BTreeMap<String, Vec<String>>,
    pub gates_by_task: BTreeMap<String, Vec<String>>,
    pub dependency_edges: Vec<DependencyEdge>,
    pub checked_rows: CheckedRows,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PlanCounts {
    pub objectives: usize,
    pub milestones: usize,
    pub tasks: usize,
    pub gates: usize,
    pub decisions: usize,
    pub notes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReviewPreview {
    pub dry_run: bool,
    pub changed_files: Vec<FileChange>,
    pub patch_files: Vec<PatchFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GateResult {
    pub name: String,
    pub task: String,
    pub check: String,
    pub expect: String,
    pub observed: String,
    pub status: GateStatus,
    pub evidence: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateStatus {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PatchArtifact {
    pub file_count: usize,
    pub omitted_count: usize,
    pub byte_count: usize,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewDiagnostic {
    pub severity: ReviewSeverity,
    pub code: String,
    pub message: String,
    pub path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewSummary {
    pub status: ReviewStatus,
    pub score: u8,
    pub changed_file_count: usize,
    pub patch_file_count: usize,
    pub omitted_patch_count: usize,
    pub validator_count: usize,
    pub failed_validator_count: usize,
    pub gate_count: usize,
    pub failed_gate_count: usize,
    pub unknown_gate_count: usize,
    pub diagnostic_count: usize,
    pub blocker_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewStatus {
    Ready,
    NeedsAttention,
    Blocked,
}

pub fn build_review_packet(
    source: &Path,
    repo: &Path,
    options: ReviewOptions,
) -> Result<ReviewPacket> {
    let source_text = fs::read_to_string(source)
        .with_context(|| format!("failed to read source {}", source.display()))?;
    let cert = elaborate_source(&source_text).context("elaboration failed")?;
    let verification = verify(&cert).context("kernel verification failed")?;
    let inspection = inspect_path(
        repo,
        InspectOptions {
            recursive: true,
            include_hidden: options.include_hidden,
            follow_symlinks: false,
            max_file_bytes: options.max_file_bytes,
        },
    )
    .with_context(|| format!("failed to inspect {}", repo.display()))?;
    let mut transform_preview =
        preview_certificate(&cert, repo).context("failed to preview workspace changes")?;
    let patch = if options.include_patch {
        patch_artifact(&transform_preview)
    } else {
        for patch_file in &mut transform_preview.patch_files {
            patch_file.text = None;
        }
        transform_preview.patch = None;
        None
    };
    let plan = build_plan(&cert, verification.checked_rows.clone());
    let gates = evaluate_gates(&cert, &transform_preview.apply);
    let diagnostics = build_diagnostics(&inspection, &transform_preview, &gates);
    let summary = build_summary(&inspection, &transform_preview, &gates, &diagnostics);

    Ok(ReviewPacket {
        world: cert.world,
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        source: source.to_path_buf(),
        repo: repo.to_path_buf(),
        inspection,
        plan,
        preview: ReviewPreview {
            dry_run: transform_preview.apply.dry_run,
            changed_files: transform_preview.apply.changed_files,
            patch_files: transform_preview.patch_files,
        },
        gates,
        validators: transform_preview.apply.validators,
        diagnostics,
        summary,
        patch,
    })
}

pub fn render_review_markdown(packet: &ReviewPacket) -> String {
    let mut out = String::new();
    out.push_str("# Entanglement Review Packet\n\n");
    out.push_str(&format!("- World: `{}`\n", markdown_cell(&packet.world)));
    out.push_str(&format!(
        "- Status: {} (score {}/100)\n",
        review_status_label(packet.summary.status),
        packet.summary.score
    ));
    out.push_str(&format!(
        "- Changed files: {}\n",
        packet.summary.changed_file_count
    ));
    out.push_str(&format!(
        "- Gates: {} total, {} failed, {} unknown\n",
        packet.summary.gate_count,
        packet.summary.failed_gate_count,
        packet.summary.unknown_gate_count
    ));
    out.push_str(&format!(
        "- Validators: {} total, {} failed\n\n",
        packet.summary.validator_count, packet.summary.failed_validator_count
    ));

    out.push_str("## Readiness\n\n");
    out.push_str(&format!(
        "- Inspection: {} ({} errors, {} warnings)\n",
        readiness_label(packet.inspection.readiness.status),
        packet.inspection.summary.error_count,
        packet.inspection.summary.warning_count
    ));
    for reason in &packet.inspection.readiness.reasons {
        out.push_str(&format!("- {}\n", markdown_cell(reason)));
    }

    out.push_str("\n## Planned Work\n\n");
    out.push_str(&format!(
        "- Objectives: {}\n- Milestones: {}\n- Tasks: {}\n- Decisions: {}\n- Notes: {}\n",
        packet.plan.counts.objectives,
        packet.plan.counts.milestones,
        packet.plan.counts.tasks,
        packet.plan.counts.decisions,
        packet.plan.counts.notes
    ));
    if !packet.plan.tasks.is_empty() {
        out.push_str("\n| Task | State | Owner | Outputs |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for task in &packet.plan.tasks {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                markdown_cell(&task.name),
                markdown_cell(&task.state),
                markdown_cell(&task.owner),
                markdown_cell(&task.outputs.join(", "))
            ));
        }
    }

    out.push_str("\n## Gates\n\n");
    if packet.gates.is_empty() {
        out.push_str("No gates were declared.\n");
    } else {
        out.push_str("| Gate | Check | Expect | Observed | Status |\n");
        out.push_str("| --- | --- | --- | --- | --- |\n");
        for gate in &packet.gates {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} | {} |\n",
                markdown_cell(&gate.name),
                markdown_cell(&gate.check),
                markdown_cell(&gate.expect),
                markdown_cell(&gate.observed),
                gate_status_label(gate.status)
            ));
        }
    }

    out.push_str("\n## Validators\n\n");
    if packet.validators.is_empty() {
        out.push_str("No validators were declared.\n");
    } else {
        out.push_str("| Validator | Status | Command |\n");
        out.push_str("| --- | ---: | --- |\n");
        for validator in &packet.validators {
            out.push_str(&format!(
                "| `{}` | {} | `{}` |\n",
                markdown_cell(&validator.name),
                validator.status,
                markdown_cell(&validator.argv.join(" "))
            ));
        }
    }

    out.push_str("\n## Changed Files\n\n");
    if packet.preview.changed_files.is_empty() {
        out.push_str("No file changes were previewed.\n");
    } else {
        out.push_str("| File | Action | Before | After |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for change in &packet.preview.changed_files {
            out.push_str(&format!(
                "| `{}` | {} | `{}` | `{}` |\n",
                markdown_cell(&change.path),
                file_action_label(&change.action),
                markdown_cell(change.before_hash.as_deref().unwrap_or("-")),
                markdown_cell(change.after_hash.as_deref().unwrap_or("-"))
            ));
        }
    }

    out.push_str("\n## Patch\n\n");
    if let Some(patch) = &packet.patch {
        out.push_str(&format!(
            "Patch artifact: {} file(s), {} omitted, {} bytes.\n",
            patch.file_count, patch.omitted_count, patch.byte_count
        ));
    } else {
        out.push_str("Patch text was not requested for this packet.\n");
    }

    if !packet.diagnostics.is_empty() {
        out.push_str("\n## Diagnostics\n\n");
        out.push_str("| Severity | Code | Message |\n");
        out.push_str("| --- | --- | --- |\n");
        for diagnostic in &packet.diagnostics {
            out.push_str(&format!(
                "| {} | `{}` | {} |\n",
                severity_label(diagnostic.severity),
                markdown_cell(&diagnostic.code),
                markdown_cell(&diagnostic.message)
            ));
        }
    }

    out
}

pub fn emit_patch(packet: &ReviewPacket) -> Option<&str> {
    packet.patch.as_ref().map(|patch| patch.text.as_str())
}

fn build_plan(cert: &Certificate, checked_rows: CheckedRows) -> ReviewPlan {
    let mut tasks_by_state = BTreeMap::new();
    let mut tasks_by_milestone: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut gates_by_task: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for task in &cert.tasks {
        *tasks_by_state.entry(task.state.clone()).or_default() += 1;
        tasks_by_milestone
            .entry(task.milestone.clone())
            .or_default()
            .push(task.name.clone());
    }
    for gate in &cert.gates {
        gates_by_task
            .entry(gate.task.clone())
            .or_default()
            .push(gate.name.clone());
    }
    ReviewPlan {
        counts: PlanCounts {
            objectives: cert.objectives.len(),
            milestones: cert.milestones.len(),
            tasks: cert.tasks.len(),
            gates: cert.gates.len(),
            decisions: cert.decisions.len(),
            notes: cert.notes.len(),
        },
        objectives: cert.objectives.clone(),
        milestones: cert.milestones.clone(),
        tasks: cert.tasks.clone(),
        gates: cert.gates.clone(),
        decisions: cert.decisions.clone(),
        notes: cert.notes.clone(),
        tasks_by_state,
        tasks_by_milestone,
        gates_by_task,
        dependency_edges: cert
            .tasks
            .iter()
            .flat_map(|task| {
                task.requires.iter().map(|dependency| DependencyEdge {
                    from: dependency.clone(),
                    to: task.name.clone(),
                })
            })
            .collect(),
        checked_rows,
    }
}

fn evaluate_gates(cert: &Certificate, apply: &ent_transform::ApplyReport) -> Vec<GateResult> {
    cert.gates
        .iter()
        .map(|gate| evaluate_gate(gate, &cert.validators, &cert.transforms, apply))
        .collect()
}

fn evaluate_gate(
    gate: &GateContract,
    validators: &[ValidatorContract],
    transforms: &[ent_core::TransformContract],
    apply: &ent_transform::ApplyReport,
) -> GateResult {
    let (observed, status) = if let Some(name) = gate.check.strip_prefix("validator:") {
        if !validators.iter().any(|validator| validator.name == name) {
            ("missing".to_owned(), GateStatus::Fail)
        } else if let Some(report) = apply.validators.iter().find(|report| report.name == name) {
            let observed = if report.status == 0 { "pass" } else { "fail" };
            let status = if expectation_matches(&gate.expect, observed) {
                GateStatus::Pass
            } else {
                GateStatus::Fail
            };
            (observed.to_owned(), status)
        } else {
            ("not-run".to_owned(), GateStatus::Unknown)
        }
    } else if let Some(name) = gate.check.strip_prefix("transform:") {
        if !transforms.iter().any(|transform| transform.name == name) {
            ("missing".to_owned(), GateStatus::Fail)
        } else {
            let observed = if apply.changed_files.is_empty() {
                "unchanged"
            } else {
                "changed"
            };
            let status = if expectation_matches(&gate.expect, observed) {
                GateStatus::Pass
            } else {
                GateStatus::Fail
            };
            (observed.to_owned(), status)
        }
    } else {
        ("unsupported-check".to_owned(), GateStatus::Unknown)
    };

    GateResult {
        name: gate.name.clone(),
        task: gate.task.clone(),
        check: gate.check.clone(),
        expect: gate.expect.clone(),
        observed,
        status,
        evidence: gate.evidence.clone(),
    }
}

fn expectation_matches(expect: &str, observed: &str) -> bool {
    expect.trim().eq_ignore_ascii_case(observed)
}

fn build_diagnostics(
    inspection: &InspectReport,
    preview: &TransformPreviewReport,
    gates: &[GateResult],
) -> Vec<ReviewDiagnostic> {
    let mut diagnostics = Vec::new();
    if inspection.summary.error_count > 0 {
        diagnostics.push(ReviewDiagnostic {
            severity: ReviewSeverity::Error,
            code: "blocking-diagnostics".to_owned(),
            message: format!(
                "inspection found {} blocking diagnostic(s)",
                inspection.summary.error_count
            ),
            path: None,
        });
    }
    if inspection.summary.warning_count > 0 {
        diagnostics.push(ReviewDiagnostic {
            severity: ReviewSeverity::Warning,
            code: "inspection-warnings".to_owned(),
            message: format!(
                "inspection found {} warning diagnostic(s)",
                inspection.summary.warning_count
            ),
            path: None,
        });
    }
    for validator in &preview.apply.validators {
        if validator.status != 0 {
            diagnostics.push(ReviewDiagnostic {
                severity: ReviewSeverity::Error,
                code: "validator-failed".to_owned(),
                message: format!(
                    "validator {} exited with status {}",
                    validator.name, validator.status
                ),
                path: None,
            });
        }
    }
    for gate in gates {
        match gate.status {
            GateStatus::Pass => {}
            GateStatus::Fail => diagnostics.push(ReviewDiagnostic {
                severity: ReviewSeverity::Error,
                code: "gate-failed".to_owned(),
                message: format!(
                    "gate {} expected {} but observed {}",
                    gate.name, gate.expect, gate.observed
                ),
                path: None,
            }),
            GateStatus::Unknown => diagnostics.push(ReviewDiagnostic {
                severity: ReviewSeverity::Warning,
                code: "gate-unknown".to_owned(),
                message: format!("gate {} could not be evaluated", gate.name),
                path: None,
            }),
        }
    }
    for patch in &preview.patch_files {
        if let Some(reason) = &patch.omitted_reason {
            diagnostics.push(ReviewDiagnostic {
                severity: ReviewSeverity::Warning,
                code: "patch-omitted".to_owned(),
                message: format!("patch text omitted for {}: {reason}", patch.path),
                path: Some(PathBuf::from(&patch.path)),
            });
        }
    }
    if preview.apply.changed_files.is_empty() {
        diagnostics.push(ReviewDiagnostic {
            severity: ReviewSeverity::Info,
            code: "no-changes".to_owned(),
            message: "no file changes were previewed".to_owned(),
            path: None,
        });
    }
    diagnostics
}

fn build_summary(
    inspection: &InspectReport,
    preview: &TransformPreviewReport,
    gates: &[GateResult],
    diagnostics: &[ReviewDiagnostic],
) -> ReviewSummary {
    let failed_validator_count = preview
        .apply
        .validators
        .iter()
        .filter(|validator| validator.status != 0)
        .count();
    let failed_gate_count = gates
        .iter()
        .filter(|gate| gate.status == GateStatus::Fail)
        .count();
    let unknown_gate_count = gates
        .iter()
        .filter(|gate| gate.status == GateStatus::Unknown)
        .count();
    let omitted_patch_count = preview
        .patch_files
        .iter()
        .filter(|patch| patch.omitted_reason.is_some())
        .count();
    let blocker_count = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == ReviewSeverity::Error)
        .count();
    let mut score = inspection.readiness.score as i32;
    score -= (failed_validator_count as i32 * 20).min(60);
    score -= (failed_gate_count as i32 * 15).min(45);
    score -= (unknown_gate_count as i32 * 5).min(20);
    score -= (omitted_patch_count as i32 * 3).min(15);
    let score = score.clamp(0, 100) as u8;
    let has_warning = diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == ReviewSeverity::Warning);
    let status = if blocker_count > 0 || inspection.readiness.status == ReadinessStatus::Blocked {
        ReviewStatus::Blocked
    } else if has_warning || inspection.readiness.status == ReadinessStatus::NeedsAttention {
        ReviewStatus::NeedsAttention
    } else {
        ReviewStatus::Ready
    };

    ReviewSummary {
        status,
        score,
        changed_file_count: preview.apply.changed_files.len(),
        patch_file_count: preview
            .patch_files
            .iter()
            .filter(|patch| patch.text.is_some())
            .count(),
        omitted_patch_count,
        validator_count: preview.apply.validators.len(),
        failed_validator_count,
        gate_count: gates.len(),
        failed_gate_count,
        unknown_gate_count,
        diagnostic_count: diagnostics.len(),
        blocker_count,
    }
}

fn patch_artifact(preview: &TransformPreviewReport) -> Option<PatchArtifact> {
    let text = preview.patch.clone()?;
    Some(PatchArtifact {
        file_count: preview
            .patch_files
            .iter()
            .filter(|patch| patch.text.is_some())
            .count(),
        omitted_count: preview
            .patch_files
            .iter()
            .filter(|patch| patch.omitted_reason.is_some())
            .count(),
        byte_count: text.len(),
        text,
    })
}

fn review_status_label(status: ReviewStatus) -> &'static str {
    match status {
        ReviewStatus::Ready => "ready",
        ReviewStatus::NeedsAttention => "needs attention",
        ReviewStatus::Blocked => "blocked",
    }
}

fn readiness_label(status: ReadinessStatus) -> &'static str {
    match status {
        ReadinessStatus::Ready => "ready",
        ReadinessStatus::NeedsAttention => "needs attention",
        ReadinessStatus::Blocked => "blocked",
        ReadinessStatus::Empty => "empty",
    }
}

fn gate_status_label(status: GateStatus) -> &'static str {
    match status {
        GateStatus::Pass => "pass",
        GateStatus::Fail => "fail",
        GateStatus::Unknown => "unknown",
    }
}

fn severity_label(severity: ReviewSeverity) -> &'static str {
    match severity {
        ReviewSeverity::Info => "info",
        ReviewSeverity::Warning => "warning",
        ReviewSeverity::Error => "error",
    }
}

fn file_action_label(action: &ent_transform::FileAction) -> &'static str {
    match action {
        ent_transform::FileAction::Write => "write",
        ent_transform::FileAction::Delete => "delete",
    }
}

fn markdown_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "<br>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn builds_packet_with_plan_preview_gate_and_patch() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("README.md"), "old value\n").expect("readme");
        let source = temp.path().join("review.ent");
        fs::write(&source, review_source("pass")).expect("source");

        let packet = build_review_packet(
            &source,
            temp.path(),
            ReviewOptions {
                include_patch: true,
                ..ReviewOptions::default()
            },
        )
        .expect("packet");

        assert_eq!(packet.world, "ReviewPacket");
        assert_eq!(packet.plan.counts.tasks, 1);
        assert_eq!(packet.gates[0].status, GateStatus::Pass);
        assert_eq!(packet.summary.changed_file_count, 1);
        assert!(emit_patch(&packet).is_some_and(|patch| patch.contains("+new value")));
        assert_eq!(
            fs::read_to_string(temp.path().join("README.md")).expect("readme"),
            "old value\n"
        );
    }

    #[test]
    fn markdown_renderer_escapes_table_cells() {
        assert_eq!(markdown_cell("a|b\nc"), "a\\|b<br>c");
    }

    #[test]
    fn failing_validator_blocks_packet_without_losing_report() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("README.md"), "old value\n").expect("readme");
        let source = temp.path().join("review.ent");
        fs::write(&source, review_source("fail")).expect("source");

        let packet = build_review_packet(
            &source,
            temp.path(),
            ReviewOptions {
                include_patch: true,
                ..ReviewOptions::default()
            },
        )
        .expect("packet");

        assert_eq!(packet.summary.status, ReviewStatus::Blocked);
        assert_eq!(packet.summary.failed_validator_count, 1);
        assert!(packet
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "validator-failed"));
    }

    #[test]
    fn serializes_stable_top_level_shape() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("README.md"), "old value\n").expect("readme");
        let source = temp.path().join("review.ent");
        fs::write(&source, review_source("pass")).expect("source");
        let packet =
            build_review_packet(&source, temp.path(), ReviewOptions::default()).expect("packet");

        let value = serde_json::to_value(&packet).expect("json");
        assert!(value.get("inspection").is_some());
        assert!(value.get("plan").is_some());
        assert!(value.get("preview").is_some());
        assert!(value.get("summary").is_some());
        assert!(value.get("patch").is_none());
    }

    fn review_source(validator: &str) -> String {
        let validator_argv = if validator == "pass" {
            r#"["cargo", "--version"]"#
        } else {
            r#"["cargo", "--definitely-not-a-real-cargo-flag"]"#
        };
        format!(
            r#"
world ReviewPacket(role Maintainer, space Repository) {{
  state tree : Resource
  workspace repo uses filesystem write evidence repo_boundary
  document markdown via pulldown_cmark evidence markdown_contract
  select readme = files where file("README.md") evidence readme_scope
  transform rename replace_word on file("README.md") from "old" to "new" evidence word_replace
  validator cargo_version argv {validator_argv} evidence validator_record
  objective workspace_review priority high summary "Preview checked workspace changes" evidence objective_record
  milestone review_ready objective workspace_review state active due "unscheduled" evidence milestone_record
  task update_readme milestone review_ready kind document state ready owner maintainer requires [] outputs ["README.md"] title "Update README wording" evidence task_record
  gate cargo_gate task update_readme check "validator:cargo_version" expect "pass" evidence gate_record
  decision packet_shape scope task:update_readme choose "single packet" because "one report keeps preview and validation together" alternatives ["separate reports"] evidence decision_record
  note review_note scope gate:cargo_gate text "Validator output is recorded with the staged preview" tags [review,workspace] evidence note_record
  theorem markdown_parser_safe : parser_admissible(markdown)
  theorem readme_selection_safe : selection_admissible(readme)
  theorem rename_safe : transform_admissible(rename)
  theorem validator_safe : validator_admissible(cargo_version)
  theorem objective_safe : objective_admissible(workspace_review)
  theorem milestone_safe : milestone_admissible(review_ready)
  theorem task_safe : task_admissible(update_readme)
  theorem gate_safe : gate_admissible(cargo_gate)
  theorem decision_safe : decision_admissible(packet_shape)
  theorem note_safe : note_admissible(review_note)
  proof markdown_parser_safe {{
    let row = row parser markdown
    let fact = rule parser_admissible_from_parser(row)
    qed fact
  }}
  proof readme_selection_safe {{
    let row = row selection readme
    let fact = rule selection_admissible_from_selection(row)
    qed fact
  }}
  proof rename_safe {{
    let row = row transform rename
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }}
  proof validator_safe {{
    let row = row validator cargo_version
    let fact = rule validator_admissible_from_validator(row)
    qed fact
  }}
  proof objective_safe {{
    let row = row objective workspace_review
    let fact = rule objective_admissible_from_objective(row)
    qed fact
  }}
  proof milestone_safe {{
    let row = row milestone review_ready
    let fact = rule milestone_admissible_from_milestone(row)
    qed fact
  }}
  proof task_safe {{
    let row = row task update_readme
    let fact = rule task_admissible_from_task(row)
    qed fact
  }}
  proof gate_safe {{
    let row = row gate cargo_gate
    let fact = rule gate_admissible_from_gate(row)
    qed fact
  }}
  proof decision_safe {{
    let row = row decision packet_shape
    let fact = rule decision_admissible_from_decision(row)
    qed fact
  }}
  proof note_safe {{
    let row = row note review_note
    let fact = rule note_admissible_from_note(row)
    qed fact
  }}
}}
"#
        )
    }
}
