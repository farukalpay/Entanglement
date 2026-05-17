use ent_elab::elaborate_source;
use ent_transform::{apply_certificate, TransformError};
use std::fs;
use std::process::Command;

#[test]
fn removes_rust_comments_and_flattens_modules_after_validator() {
    let repo = tempfile::tempdir().expect("repo");
    fs::create_dir_all(repo.path().join("src/nested")).expect("src");
    fs::write(
        repo.path().join("Cargo.toml"),
        r#"[package]
name = "fixture"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("cargo toml");
    fs::write(
        repo.path().join("src/lib.rs"),
        r#"
// root comment
pub mod nested;

pub fn value() -> i32 {
    nested::math::value()
}

#[cfg(test)]
mod tests {
    #[test]
    fn value_is_preserved() {
        assert_eq!(crate::value(), 2);
    }
}
"#,
    )
    .expect("lib");
    fs::write(
        repo.path().join("src/nested/mod.rs"),
        "pub mod math; // module comment\n",
    )
    .expect("mod");
    fs::write(
        repo.path().join("src/nested/math.rs"),
        r#"
pub fn value() -> i32 {
    let text = "not // a comment";
    let _ = text;
    1 /* block comment */ + 1
}
"#,
    )
    .expect("math");

    let cert = elaborate_source(RUST_PROGRAM).expect("program elaborates");
    let report = apply_certificate(&cert, repo.path()).expect("apply succeeds");

    assert!(report
        .changed_files
        .iter()
        .any(|change| change.path == "src/flat/nested.rs"));
    assert!(!repo.path().join("src/nested/math.rs").exists());
    let lib = fs::read_to_string(repo.path().join("src/lib.rs")).expect("lib");
    assert!(lib.contains("#[path = \"flat/nested.rs\"]"));
    assert!(!lib.contains("root comment"));
    let math = fs::read_to_string(repo.path().join("src/flat/nested__math.rs")).expect("math");
    assert!(math.contains("\"not // a comment\""));
    assert!(!math.contains("block comment"));

    let test = Command::new("cargo")
        .arg("test")
        .current_dir(repo.path())
        .output()
        .expect("cargo test");
    assert!(
        test.status.success(),
        "{}",
        String::from_utf8_lossy(&test.stderr)
    );
}

#[test]
fn removes_comments_from_mixed_rust_c_and_cpp_selection() {
    let repo = tempfile::tempdir().expect("repo");
    fs::create_dir_all(repo.path().join("src")).expect("src");
    fs::write(
        repo.path().join("src/lib.rs"),
        r#"
pub fn text() -> &'static str {
    "// not a Rust comment" // remove me
}
"#,
    )
    .expect("rust");
    fs::write(
        repo.path().join("calc.c"),
        r#"
#include <stdio.h>
const char *text = "// not a C comment";
int add(int a, int b) {
    return a + b; /* remove C block */
}
"#,
    )
    .expect("c");
    fs::write(
        repo.path().join("widget.cpp"),
        r#"
#include "widget.hpp"
#include <string>
std::string text() {
    return "/* not a C++ comment */"; // remove C++ line
}
"#,
    )
    .expect("cpp");
    fs::write(
        repo.path().join("widget.hpp"),
        "#pragma once\nint answer(); // remove header comment\n",
    )
    .expect("hpp");

    let cert = elaborate_source(MIXED_GRAMMAR_PROGRAM).expect("program elaborates");
    let report = apply_certificate(&cert, repo.path()).expect("apply succeeds");

    assert_eq!(report.changed_files.len(), 4);
    let rust = fs::read_to_string(repo.path().join("src/lib.rs")).expect("rust");
    assert!(rust.contains("\"// not a Rust comment\""));
    assert!(!rust.contains("remove me"));
    let c = fs::read_to_string(repo.path().join("calc.c")).expect("c");
    assert!(c.contains("\"// not a C comment\""));
    assert!(!c.contains("remove C block"));
    let cpp = fs::read_to_string(repo.path().join("widget.cpp")).expect("cpp");
    assert!(cpp.contains("\"/* not a C++ comment */\""));
    assert!(!cpp.contains("remove C++ line"));
    let hpp = fs::read_to_string(repo.path().join("widget.hpp")).expect("hpp");
    assert!(!hpp.contains("remove header comment"));
}

#[test]
fn ambiguous_c_cpp_header_fails_closed() {
    let repo = tempfile::tempdir().expect("repo");
    fs::write(repo.path().join("shared.h"), "int answer(); // ambiguous\n").expect("header");
    let cert = elaborate_source(AMBIGUOUS_HEADER_PROGRAM).expect("program elaborates");

    let err = apply_certificate(&cert, repo.path()).expect_err("ambiguous .h rejects");
    assert!(matches!(err, TransformError::AmbiguousParser { .. }));
    assert_eq!(
        fs::read_to_string(repo.path().join("shared.h")).expect("header"),
        "int answer(); // ambiguous\n"
    );
}

#[test]
fn applies_markdown_delete_line_delete_and_replace_contracts() {
    let repo = tempfile::tempdir().expect("repo");
    fs::write(
        repo.path().join("README.md"),
        "# Keep\nlegacy line\nold word\n",
    )
    .expect("readme");
    fs::write(repo.path().join("remove.md"), "# Remove Me\nbody\n").expect("remove");

    let cert = elaborate_source(MARKDOWN_PROGRAM).expect("program elaborates");
    let report = apply_certificate(&cert, repo.path()).expect("apply succeeds");

    assert!(report
        .changed_files
        .iter()
        .any(|change| change.path == "remove.md"));
    assert!(!repo.path().join("remove.md").exists());
    let readme = fs::read_to_string(repo.path().join("README.md")).expect("readme");
    assert_eq!(readme, "# Keep\nnew word\n");
}

#[test]
fn unsupported_files_fail_closed_without_target_writes() {
    let repo = tempfile::tempdir().expect("repo");
    fs::write(repo.path().join("tool.py"), "# comment\nprint('ok')\n").expect("python");
    let cert = elaborate_source(UNSUPPORTED_PROGRAM).expect("program elaborates");

    let err = apply_certificate(&cert, repo.path()).expect_err("unsupported file rejects");
    assert!(matches!(err, TransformError::UnsupportedFile { .. }));
    assert_eq!(
        fs::read_to_string(repo.path().join("tool.py")).expect("python"),
        "# comment\nprint('ok')\n"
    );
}

#[test]
fn validator_failure_rolls_back_target_writes() {
    let repo = tempfile::tempdir().expect("repo");
    fs::write(repo.path().join("README.md"), "keep\nlegacy\n").expect("readme");
    let cert = elaborate_source(FAILING_VALIDATOR_PROGRAM).expect("program elaborates");

    let err = apply_certificate(&cert, repo.path()).expect_err("validator rejects apply");
    assert!(matches!(err, TransformError::ValidatorFailed { .. }));
    assert_eq!(
        fs::read_to_string(repo.path().join("README.md")).expect("readme"),
        "keep\nlegacy\n"
    );
}

#[test]
fn stress_removes_comments_across_many_mixed_files() {
    let repo = tempfile::tempdir().expect("repo");
    fs::create_dir_all(repo.path().join("src")).expect("src");
    for idx in 0..30 {
        fs::write(
            repo.path().join(format!("src/unit_{idx}.rs")),
            format!("pub fn value_{idx}() -> &'static str {{ \"// keep {idx}\" }} // drop {idx}\n"),
        )
        .expect("rust");
        fs::write(
            repo.path().join(format!("unit_{idx}.c")),
            format!("const char *s_{idx} = \"/* keep {idx} */\"; /* drop {idx} */\n"),
        )
        .expect("c");
        fs::write(
            repo.path().join(format!("unit_{idx}.cpp")),
            format!("const char *s_{idx} = \"// keep {idx}\"; // drop {idx}\n"),
        )
        .expect("cpp");
    }

    let cert = elaborate_source(MIXED_GRAMMAR_PROGRAM).expect("program elaborates");
    let report = apply_certificate(&cert, repo.path()).expect("apply succeeds");

    assert_eq!(report.changed_files.len(), 90);
    for idx in [0, 17, 29] {
        let rust = fs::read_to_string(repo.path().join(format!("src/unit_{idx}.rs"))).unwrap();
        assert!(rust.contains(&format!("\"// keep {idx}\"")));
        assert!(!rust.contains(&format!("drop {idx}")));
        let c = fs::read_to_string(repo.path().join(format!("unit_{idx}.c"))).unwrap();
        assert!(c.contains(&format!("\"/* keep {idx} */\"")));
        assert!(!c.contains(&format!("drop {idx}")));
        let cpp = fs::read_to_string(repo.path().join(format!("unit_{idx}.cpp"))).unwrap();
        assert!(cpp.contains(&format!("\"// keep {idx}\"")));
        assert!(!cpp.contains(&format!("drop {idx}")));
    }
}

const RUST_PROGRAM: &str = r#"
world RustCleanup(agent Operator) {
  state tree : Resource
  workspace repo uses filesystem write evidence repo_boundary
  parser rust language rust via tree-sitter evidence rust_parser_contract
  select code = files where parsed_by(rust) evidence rust_parser_coverage
  transform strip_comments remove_comments on code evidence rust_comment_ranges
  transform flatten flatten_modules on code into "flat" evidence rust_module_rewrite
  validator build argv ["cargo", "test"] evidence build_still_passes
  theorem rust_parser : parser_admissible(rust)
  theorem code_selection : selection_admissible(code)
  theorem comments_safe : transform_admissible(strip_comments)
  theorem flatten_safe : transform_admissible(flatten)
  theorem build_safe : validator_admissible(build)
  proof rust_parser {
    let row = row parser rust
    let fact = rule parser_admissible_from_parser(row)
    qed fact
  }
  proof code_selection {
    let row = row selection code
    let fact = rule selection_admissible_from_selection(row)
    qed fact
  }
  proof comments_safe {
    let row = row transform strip_comments
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
  proof flatten_safe {
    let row = row transform flatten
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
  proof build_safe {
    let row = row validator build
    let fact = rule validator_admissible_from_validator(row)
    qed fact
  }
}
"#;

const MIXED_GRAMMAR_PROGRAM: &str = r#"
world MixedGrammarCleanup(agent Operator) {
  state tree : Resource
  workspace repo uses filesystem write evidence repo_boundary
  parser rust language rust via tree-sitter evidence rust_parser_contract
  parser c language c via tree-sitter evidence c_parser_contract
  parser cpp language cpp via tree-sitter evidence cpp_parser_contract
  select code = files where parsed_by(rust, c, cpp) evidence mixed_parser_coverage
  transform strip_comments remove_comments on code evidence grammar_comment_ranges
  theorem rust_parser : parser_admissible(rust)
  theorem c_parser : parser_admissible(c)
  theorem cpp_parser : parser_admissible(cpp)
  theorem code_selection : selection_admissible(code)
  theorem comments_safe : transform_admissible(strip_comments)
  proof rust_parser {
    let row = row parser rust
    let fact = rule parser_admissible_from_parser(row)
    qed fact
  }
  proof c_parser {
    let row = row parser c
    let fact = rule parser_admissible_from_parser(row)
    qed fact
  }
  proof cpp_parser {
    let row = row parser cpp
    let fact = rule parser_admissible_from_parser(row)
    qed fact
  }
  proof code_selection {
    let row = row selection code
    let fact = rule selection_admissible_from_selection(row)
    qed fact
  }
  proof comments_safe {
    let row = row transform strip_comments
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
}
"#;

const AMBIGUOUS_HEADER_PROGRAM: &str = r#"
world AmbiguousHeaderCleanup(agent Operator) {
  state tree : Resource
  workspace repo uses filesystem write evidence repo_boundary
  parser c language c via tree-sitter evidence c_parser_contract
  parser cpp language cpp via tree-sitter evidence cpp_parser_contract
  select code = files where parsed_by(c, cpp) evidence mixed_parser_coverage
  transform strip_comments remove_comments on code evidence grammar_comment_ranges
  theorem c_parser : parser_admissible(c)
  theorem cpp_parser : parser_admissible(cpp)
  theorem code_selection : selection_admissible(code)
  theorem comments_safe : transform_admissible(strip_comments)
  proof c_parser {
    let row = row parser c
    let fact = rule parser_admissible_from_parser(row)
    qed fact
  }
  proof cpp_parser {
    let row = row parser cpp
    let fact = rule parser_admissible_from_parser(row)
    qed fact
  }
  proof code_selection {
    let row = row selection code
    let fact = rule selection_admissible_from_selection(row)
    qed fact
  }
  proof comments_safe {
    let row = row transform strip_comments
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
}
"#;

const FAILING_VALIDATOR_PROGRAM: &str = r#"
world FailingValidatorCleanup(agent Operator) {
  state tree : Resource
  workspace repo uses filesystem write evidence repo_boundary
  select readme = files where file("README.md") evidence explicit_file
  transform cleanup delete_lines on file("README.md") where contains_word("legacy") evidence line_delete
  validator fail argv ["cargo", "--definitely-not-a-real-cargo-flag"] evidence failing_validator
  theorem readme_selection : selection_admissible(readme)
  theorem cleanup_safe : transform_admissible(cleanup)
  theorem validator_safe : validator_admissible(fail)
  proof readme_selection {
    let row = row selection readme
    let fact = rule selection_admissible_from_selection(row)
    qed fact
  }
  proof cleanup_safe {
    let row = row transform cleanup
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
  proof validator_safe {
    let row = row validator fail
    let fact = rule validator_admissible_from_validator(row)
    qed fact
  }
}
"#;

const MARKDOWN_PROGRAM: &str = r#"
world MarkdownCleanup(agent Operator) {
  state tree : Resource
  workspace repo uses filesystem write evidence repo_boundary
  document markdown via pulldown_cmark evidence markdown_contract
  select removable = files where markdown_heading("Remove Me") evidence heading_scope
  transform drop_docs delete_files on removable evidence doc_delete
  transform readme_lines delete_lines on file("README.md") where contains_word("legacy") evidence line_delete
  transform rename replace_word on file("README.md") from "old" to "new" evidence word_replace
  theorem markdown_parser : parser_admissible(markdown)
  theorem removable_selection : selection_admissible(removable)
  theorem drop_safe : transform_admissible(drop_docs)
  theorem line_safe : transform_admissible(readme_lines)
  theorem rename_safe : transform_admissible(rename)
  proof markdown_parser {
    let row = row parser markdown
    let fact = rule parser_admissible_from_parser(row)
    qed fact
  }
  proof removable_selection {
    let row = row selection removable
    let fact = rule selection_admissible_from_selection(row)
    qed fact
  }
  proof drop_safe {
    let row = row transform drop_docs
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
  proof line_safe {
    let row = row transform readme_lines
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
  proof rename_safe {
    let row = row transform rename
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
}
"#;

const UNSUPPORTED_PROGRAM: &str = r#"
world UnsupportedCleanup(agent Operator) {
  state tree : Resource
  workspace repo uses filesystem write evidence repo_boundary
  select scripts = files where extension(".py") evidence explicit_scope
  transform strip_comments remove_comments on scripts evidence comment_ranges
  theorem scripts_selection : selection_admissible(scripts)
  theorem comments_safe : transform_admissible(strip_comments)
  proof scripts_selection {
    let row = row selection scripts
    let fact = rule selection_admissible_from_selection(row)
    qed fact
  }
  proof comments_safe {
    let row = row transform strip_comments
    let fact = rule transform_admissible_from_transform(row)
    qed fact
  }
}
"#;
