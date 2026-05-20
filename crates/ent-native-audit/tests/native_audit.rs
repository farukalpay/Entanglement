use ent_native_audit::{
    audit_native_path, has_blocking_findings, render_markdown, AbiKind, BuildManifestKind,
    FindingSeverity, NativeAuditOptions, NativeReadinessStatus, SourceDialect, SymbolLinkage,
};
use std::fs;

#[test]
fn audits_mixed_native_workspace() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(temp.path().join("src")).expect("src");
    fs::create_dir_all(temp.path().join("include")).expect("include");
    fs::write(
        temp.path().join("Cargo.toml"),
        r#"[package]
name = "sample"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("cargo manifest");
    fs::write(
        temp.path().join("CMakeLists.txt"),
        "cmake_minimum_required(VERSION 3.20)\nproject(sample_native CXX)\n",
    )
    .expect("cmake");
    fs::write(
        temp.path().join("src/lib.rs"),
        r#"
use std::ffi::c_int;

#[no_mangle]
pub unsafe extern "C" fn ent_add(lhs: c_int, rhs: c_int) -> c_int {
    lhs + rhs
}

pub fn checked_add(lhs: i32, rhs: i32) -> i32 {
    unsafe { ent_add(lhs, rhs) }
}
"#,
    )
    .expect("rust source");
    fs::write(
        temp.path().join("include/engine.hpp"),
        r#"#pragma once
#include <stdint.h>

extern "C" int ent_step(int value);

class Runner {
public:
  void tick();
};
"#,
    )
    .expect("header");
    fs::write(
        temp.path().join("src/engine.cpp"),
        r#"#include "engine.hpp"
#include <cstring>

int ent_step(int value) {
  char dst[8];
  strcpy(dst, "x");
  return value + 1;
}

void Runner::tick() {
  ent_step(1);
}
"#,
    )
    .expect("cpp source");

    let report =
        audit_native_path(temp.path(), NativeAuditOptions::default()).expect("audit succeeds");

    assert_eq!(report.schema_version, 1);
    assert_eq!(report.summary.rust_file_count, 1);
    assert_eq!(report.summary.cpp_file_count, 2);
    assert_eq!(report.summary.build_manifest_count, 2);
    assert!(report
        .build
        .manifests
        .iter()
        .any(|manifest| manifest.kind == BuildManifestKind::Cargo));
    assert!(report
        .build
        .inferred_commands
        .iter()
        .any(|command| command == "cargo check --workspace"));
    assert!(report.surface.iter().any(|entry| entry.symbol == "ent_add"
        && entry.linkage == SymbolLinkage::Exported
        && entry.abi == AbiKind::C));
    assert!(report
        .surface
        .iter()
        .any(|entry| entry.symbol == "ent_step" && entry.abi == AbiKind::C));
    assert!(report
        .include_edges
        .iter()
        .any(|edge| edge.target == "engine.hpp"));
    assert!(report
        .call_edges
        .iter()
        .any(|edge| edge.target == "ent_step"));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "unchecked-buffer-call"));
    assert_eq!(
        report.readiness.status,
        NativeReadinessStatus::NeedsAttention
    );
}

#[test]
fn markdown_is_stable_and_plain() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(
        temp.path().join("lib.rs"),
        r#"
pub fn value() -> i32 {
    1
}
"#,
    )
    .expect("source");
    let report =
        audit_native_path(temp.path(), NativeAuditOptions::default()).expect("audit succeeds");
    let markdown = render_markdown(&report);

    assert!(markdown.contains("Entanglement Native Audit"));
    assert!(markdown.contains("Public Surface"));
    assert!(!markdown.contains("AI"));
    assert!(!markdown.to_ascii_lowercase().contains("agent"));
}

#[test]
fn options_can_skip_tests_and_large_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(temp.path().join("tests")).expect("tests");
    fs::write(
        temp.path().join("tests/native_test.cpp"),
        "int hidden_test_symbol() { return 1; }\n",
    )
    .expect("test source");
    fs::write(temp.path().join("big.c"), "int x = 0;\n").expect("big source");

    let report = audit_native_path(
        temp.path(),
        NativeAuditOptions {
            include_tests: false,
            max_file_bytes: Some(4),
            ..NativeAuditOptions::default()
        },
    )
    .expect("audit succeeds");

    assert_eq!(report.summary.source_file_count, 2);
    assert_eq!(report.summary.skipped_file_count, 2);
    assert_eq!(report.summary.audited_file_count, 0);
    assert!(report
        .findings
        .iter()
        .all(|finding| finding.severity == FindingSeverity::Info));
}

#[test]
fn blocking_findings_are_detected() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(temp.path().join("bad.c"), b"\xff\xfe\x00").expect("bad source");

    let report =
        audit_native_path(temp.path(), NativeAuditOptions::default()).expect("audit succeeds");

    assert!(has_blocking_findings(&report));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.severity == FindingSeverity::Error));
    assert!(report
        .files
        .iter()
        .any(|file| file.dialect == SourceDialect::C));
}
