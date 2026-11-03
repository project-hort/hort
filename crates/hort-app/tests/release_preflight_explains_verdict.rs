//! The release preflight reports why a dependency can remain absent after warming.

#[test]
fn release_preflight_names_terminal_rejection_and_recovery_paths() {
    let workflow = include_str!("../../../.github/workflows/release.yml");
    let preflight = workflow
        .split("- name: Vetted-index preflight")
        .nth(1)
        .expect("release preflight step")
        .split("      # The set and the order")
        .next()
        .expect("preflight body");
    let operator_errors: String = preflight
        .lines()
        .filter(|line| line.contains("echo \"::error::"))
        .collect();

    assert!(operator_errors.contains("Cold set:"), "{operator_errors}");
    assert!(
        operator_errors.contains("never ingested"),
        "{operator_errors}"
    );
    assert!(
        operator_errors.contains("quarantine window"),
        "{operator_errors}"
    );
    assert!(
        operator_errors.contains("terminally rejected"),
        "{operator_errors}"
    );
    assert!(operator_errors.contains("re-scan"), "{operator_errors}");
    assert!(
        operator_errors.contains("curator waiver"),
        "{operator_errors}"
    );
}
