use ent_runtime_audit::{
    audit_runtime_path, has_blocking_findings, render_markdown, RuntimeAuditOptions,
    RuntimeComponentKind, RuntimeFindingSeverity, RuntimeReadinessStatus,
};
use std::fs;

#[test]
fn audits_runtime_topology() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(temp.path().join("crates/runtime-core/src/session")).expect("session dir");
    fs::write(
        temp.path().join("crates/runtime-core/Cargo.toml"),
        r#"[package]
name = "runtime-core"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1"
"#,
    )
    .expect("manifest");
    fs::write(
        temp.path().join("crates/runtime-core/src/lib.rs"),
        r#"
pub mod session;
pub mod tools;
pub mod exec_policy;
pub mod rollout;
"#,
    )
    .expect("lib");
    fs::write(
        temp.path().join("crates/runtime-core/src/session/mod.rs"),
        r#"
pub struct ThreadManager;
pub struct TurnContext;
pub struct RolloutRecorder;
"#,
    )
    .expect("session");
    fs::write(
        temp.path().join("crates/runtime-core/src/tools.rs"),
        r#"
pub struct ToolSpec;
pub struct ToolCall;
pub struct ToolExecutor;
"#,
    )
    .expect("tools");
    fs::write(
        temp.path().join("crates/runtime-core/src/exec_policy.rs"),
        r#"
pub enum ApprovalPolicy { Never, OnRequest }
pub struct SandboxPolicy;
"#,
    )
    .expect("policy");
    fs::write(
        temp.path().join("crates/runtime-core/src/rollout.rs"),
        r#"
pub struct EventPersistence;
pub fn append_thread_name() {}
"#,
    )
    .expect("rollout");

    let report =
        audit_runtime_path(temp.path(), RuntimeAuditOptions::default()).expect("audit succeeds");

    assert_eq!(report.schema_version, 1);
    assert_eq!(report.summary.crate_count, 1);
    assert!(report
        .components
        .iter()
        .any(|component| component.kind == RuntimeComponentKind::SessionRuntime));
    assert!(report
        .components
        .iter()
        .any(|component| component.kind == RuntimeComponentKind::ToolSurface));
    assert!(report
        .components
        .iter()
        .any(|component| component.kind == RuntimeComponentKind::ExecPolicy));
    assert!(report
        .components
        .iter()
        .any(|component| component.kind == RuntimeComponentKind::EventLedger));
    assert!(report
        .flows
        .iter()
        .any(|flow| flow.from == "runtime:session-runtime" && flow.to == "runtime:turn-scheduler"));
    assert_ne!(report.readiness.status, RuntimeReadinessStatus::Empty);
    assert!(!has_blocking_findings(&report));
}

#[test]
fn reports_missing_policy_for_tool_surface() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(temp.path().join("src")).expect("src");
    fs::write(
        temp.path().join("Cargo.toml"),
        r#"[package]
name = "tool-only"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("manifest");
    fs::write(
        temp.path().join("src/lib.rs"),
        r#"
pub struct ToolSpec;
pub struct ToolExecutor;
"#,
    )
    .expect("lib");

    let report =
        audit_runtime_path(temp.path(), RuntimeAuditOptions::default()).expect("audit succeeds");

    assert!(report.findings.iter().any(|finding| {
        finding.severity == RuntimeFindingSeverity::Warning
            && finding.code == "tool-surface-without-policy"
    }));
}

#[test]
fn markdown_is_runtime_owned_and_plain() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(
        temp.path().join("session.rs"),
        r#"
pub struct ThreadManager;
pub struct ToolSpec;
pub enum ApprovalPolicy { Never }
pub struct RolloutRecorder;
"#,
    )
    .expect("source");
    let report =
        audit_runtime_path(temp.path(), RuntimeAuditOptions::default()).expect("audit succeeds");
    let markdown = render_markdown(&report);

    assert!(markdown.contains("Entanglement Runtime Ledger"));
    assert!(markdown.contains("tool-surface"));
    assert!(markdown.contains("Owner: `entanglement`"));
    assert!(!markdown.contains("FarukAlpay"));
}
