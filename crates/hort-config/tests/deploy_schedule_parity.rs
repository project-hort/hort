//! Hold the Helm chart's scheduled-task CronJobs and the Ansible
//! `hort_timers` defaults against each other, so a task that ships on one
//! deployment flavour and not the other surfaces as a failing test rather
//! than as a silence.
//!
//! The gap this exists to catch was real and stood for as long as the
//! chart's `scan-row-retention-sweep` CronJob did: it was the only
//! default-on chart CronJob with no systemd counterpart, so on a non-k8s
//! deploy terminal `kind='scan'` rows were never reclaimed. Nothing about
//! the two files made that visible — they are prose-commented lists in
//! different languages under different roots, and neither mentions the
//! other.
//!
//! No database, no cluster, no `helm` binary — both sides are static
//! files in this repository, so this is a source scan in the same family
//! as the guards under `crates/*/tests/`, and `cargo test --workspace`
//! runs it by virtue of being a `tests/` target.
//!
//! # What is compared, and what is deliberately not
//!
//! **Membership only.** A task either has a scheduled trigger on both
//! flavours or it is a named, reasoned exception below.
//!
//! Three things are **not** compared, because they legitimately differ:
//!
//! - **Schedules.** Cron (`0 3 * * *`) and systemd `OnCalendar`
//!   (`*-*-* 03:00:00`) are different grammars. Comparing them would mean
//!   maintaining a translation table — a third source of truth, and the
//!   one most likely to be wrong. The per-entry `# (Helm: …)` comments in
//!   the Ansible defaults carry the intended pairing for a human.
//! - **`enabled` defaults.** They differ by design. The chart's
//!   admin-task CronJobs sit behind `scheduledTasks.adminTasksEnabled`,
//!   which is default-off because enabling it drags the
//!   `svc-token-bootstrap` Job chain in; the native deploy provisions the
//!   token as a file, so `hort_timers_admin_tasks_enabled` is default-on
//!   and the individual admin-task timers with it.
//! - **Execution path.** A task may be `dsn-direct` on one flavour and
//!   `admin-task` on the other without that being a defect; the two
//!   deployments have different least-privilege stories.
//!
//! # How a chart CronJob is paired with a timer
//!
//! The chart names a task by its template filename,
//! `templates/cronjob-<slug>.yaml`. The Ansible side names it twice: by
//! `kind` (which becomes the systemd unit name) and, for `dsn-direct`
//! entries, by `exec_subcommand` (the `hort-server` subcommand the unit
//! runs). The comparable identity is **the scheduled unit of work**, so:
//!
//! - `dsn-direct` → `exec_subcommand` with a leading `enqueue-` stripped.
//!   This is what makes `kind: config-scrub` pair with
//!   `templates/cronjob-scrub.yaml`: the `kind` is a unit-naming choice,
//!   the subcommand is the work.
//! - `admin-task` → `kind`, which is the task kind `hort-cli admin task
//!   invoke` is handed.
//!
//! That derivation is itself load-bearing — a wrong slug would pair
//! nothing and the parity assertions would fail loudly rather than
//! silently — and `every_dsn_direct_timer_names_a_real_subcommand` pins
//! its `dsn-direct` half against the `hort-server` CLI module set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Chart CronJobs with **no** systemd counterpart, each with the reason
/// it has none. This is not an allow-list of "known drift": an entry here
/// asserts a design decision, and the test fails if the entry goes stale
/// in either direction — if the slug stops being a chart CronJob, or if a
/// timer for it appears after all.
const CHART_ONLY: &[(&str, &str)] = &[(
    "noop",
    "Heartbeat for the k8s admin-task delivery chain specifically: it proves the \
     svc-token-bootstrap Job minted a usable PAT into a cluster Secret and that a \
     CronJob pod can reach the hort-server Service with it. None of that machinery \
     exists on the native deploy — the token is a file Ansible placed at \
     `hort_timers_token_file`, and any of the ten admin-task timers failing says the \
     same thing a failing noop would. A systemd noop.timer would assert nothing that \
     is not already asserted.",
)];

/// Systemd timers with **no** chart CronJob, each with its reason. Empty
/// today; the same staleness checks apply to any entry added here.
const TIMER_ONLY: &[(&str, &str)] = &[];

/// Collapse floors, **not** a census. The parity assertions below are
/// what catch a single task going missing; these catch the case parity
/// cannot see — both scans returning nothing, so two empty sets compare
/// equal. Deliberately far below the real counts (19 and 18 at the time
/// of writing) so that a genuinely missing task reaches the parity
/// assertion and its actionable message, rather than tripping a
/// census-shaped floor that says "vacuous" about a file that parsed fine.
const MIN_CHART_CRONJOBS: usize = 12;
const MIN_TIMERS: usize = 12;

/// A handful of slugs that must be found on both sides no matter how the
/// files are reorganised. Deliberately spans both execution paths and
/// both naming shapes: `scrub` only pairs if the `exec_subcommand`
/// derivation works (its `kind` is `config-scrub`), and
/// `scan-row-retention-sweep` is the one whose absence motivated this
/// test.
const MUST_BE_ON_BOTH_SIDES: &[&str] = &[
    "scrub",
    "quarantine-release-sweep",
    "scan-row-retention-sweep",
    "prefetch-row-retention-sweep",
    "jobs-row-retention-sweep",
    "staging-sweep",
];

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for this crate is `<root>/crates/hort-config`;
    // pop twice to reach the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root reachable from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

/// Every `templates/cronjob-<slug>.yaml` in the chart, by slug.
fn chart_cronjob_slugs() -> BTreeSet<String> {
    let dir = workspace_root().join("deploy/helm/hort-server/templates");
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("read chart templates dir") {
        let name = entry.expect("read chart template entry").file_name();
        let name = name.to_string_lossy();
        if let Some(slug) = name
            .strip_prefix("cronjob-")
            .and_then(|rest| rest.strip_suffix(".yaml"))
        {
            out.insert(slug.to_string());
        }
    }
    out
}

/// One entry of `hort_timers_tasks`, reduced to what parity needs.
struct Timer {
    /// The comparable slug — see the module docs for the derivation.
    slug: String,
    /// `dsn-direct` | `admin-task`.
    path: String,
    /// The `hort-server` subcommand, for `dsn-direct` entries only.
    exec_subcommand: Option<String>,
}

fn ansible_timers() -> Vec<Timer> {
    let path = workspace_root().join("deploy/ansible/roles/hort_timers/defaults/main.yml");
    let text = std::fs::read_to_string(&path).expect("read hort_timers defaults");
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&text).expect("hort_timers defaults parse as YAML");

    let tasks = doc
        .get("hort_timers_tasks")
        .and_then(serde_yaml_ng::Value::as_sequence)
        .unwrap_or_else(|| {
            panic!(
                "`hort_timers_tasks` must be a sequence in {}",
                path.display()
            )
        });

    tasks
        .iter()
        .map(|task| {
            let kind = task
                .get("kind")
                .and_then(serde_yaml_ng::Value::as_str)
                .unwrap_or_else(|| panic!("every hort_timers_tasks entry needs a `kind`: {task:?}"))
                .to_string();
            let exec_path = task
                .get("path")
                .and_then(serde_yaml_ng::Value::as_str)
                .unwrap_or_else(|| panic!("`{kind}` needs a `path` (dsn-direct | admin-task)"))
                .to_string();
            let exec_subcommand = task
                .get("exec_subcommand")
                .and_then(serde_yaml_ng::Value::as_str)
                .map(str::to_string);

            let slug = match exec_path.as_str() {
                "dsn-direct" => {
                    let sub = exec_subcommand.as_deref().unwrap_or_else(|| {
                        panic!("`{kind}` is dsn-direct and so must name an `exec_subcommand`")
                    });
                    sub.strip_prefix("enqueue-").unwrap_or(sub).to_string()
                }
                "admin-task" => kind.clone(),
                other => panic!("`{kind}` has unknown path `{other}`"),
            };

            Timer {
                slug,
                path: exec_path,
                exec_subcommand,
            }
        })
        .collect()
}

/// Every scheduled task ships on both deployment flavours, or is one of
/// the named exceptions above.
#[test]
fn chart_cronjobs_and_systemd_timers_cover_the_same_tasks() {
    let chart = chart_cronjob_slugs();
    let timers = ansible_timers();
    let timer_slugs: BTreeSet<String> = timers.iter().map(|t| t.slug.clone()).collect();

    // -- The exception tables must be live, not stale --------------------
    let chart_only: BTreeMap<&str, &str> = CHART_ONLY.iter().copied().collect();
    let timer_only: BTreeMap<&str, &str> = TIMER_ONLY.iter().copied().collect();
    for (slug, why) in &chart_only {
        assert!(
            chart.contains(*slug),
            "`{slug}` is listed as a chart-only task but is not a chart CronJob — drop the \
             entry. Its recorded reason was: {why}"
        );
        assert!(
            !timer_slugs.contains(*slug),
            "`{slug}` is listed as having no systemd counterpart, but a timer for it now \
             exists — drop the entry. Its recorded reason was: {why}"
        );
    }
    for (slug, why) in &timer_only {
        assert!(
            timer_slugs.contains(*slug),
            "`{slug}` is listed as a timer-only task but is not a systemd timer — drop the \
             entry. Its recorded reason was: {why}"
        );
        assert!(
            !chart.contains(*slug),
            "`{slug}` is listed as having no chart CronJob, but one now exists — drop the \
             entry. Its recorded reason was: {why}"
        );
    }

    // -- The parity itself ----------------------------------------------
    let missing_timer: Vec<&String> = chart
        .iter()
        .filter(|slug| !timer_slugs.contains(*slug) && !chart_only.contains_key(slug.as_str()))
        .collect();
    assert!(
        missing_timer.is_empty(),
        "chart CronJob(s) with no systemd timer: {missing_timer:?}. On a non-k8s deploy these \
         tasks never run at all. Either add the timer to \
         deploy/ansible/roles/hort_timers/defaults/main.yml, or add the slug to CHART_ONLY in \
         this file WITH the reason it has no systemd equivalent.",
    );

    let missing_cronjob: Vec<&String> = timer_slugs
        .iter()
        .filter(|slug| !chart.contains(*slug) && !timer_only.contains_key(slug.as_str()))
        .collect();
    assert!(
        missing_cronjob.is_empty(),
        "systemd timer(s) with no chart CronJob: {missing_cronjob:?}. On k8s these tasks never \
         run at all. Either add the template under deploy/helm/hort-server/templates/, or add \
         the slug to TIMER_ONLY in this file WITH the reason it has no chart equivalent.",
    );

    // -- Counter-assertions: the comparison above was not vacuous -------
    assert!(
        chart.len() >= MIN_CHART_CRONJOBS,
        "found only {} chart CronJob templates (expected >= {MIN_CHART_CRONJOBS}) — a moved \
         templates/ directory or a renamed `cronjob-*.yaml` convention would make this \
         comparison vacuous. Found: {chart:?}",
        chart.len(),
    );
    assert!(
        timer_slugs.len() >= MIN_TIMERS,
        "found only {} systemd timers (expected >= {MIN_TIMERS}) — a renamed \
         `hort_timers_tasks` key or a reformatted list would make this comparison \
         vacuous. Found: {timer_slugs:?}",
        timer_slugs.len(),
    );
    assert_eq!(
        timer_slugs.len(),
        timers.len(),
        "two `hort_timers_tasks` entries derive the same slug, so one of them is \
         invisible to this comparison. Slugs: {timer_slugs:?}",
    );
    for slug in MUST_BE_ON_BOTH_SIDES {
        assert!(
            chart.contains(*slug),
            "`{slug}` must be a chart CronJob — if this fired because the slug derivation \
             changed, fix the derivation rather than this list. Chart: {chart:?}"
        );
        assert!(
            timer_slugs.contains(*slug),
            "`{slug}` must be a systemd timer. Timers: {timer_slugs:?}"
        );
    }
}

/// Counter-assertion for the slug derivation's `dsn-direct` half: each
/// `exec_subcommand` must name a real `hort-server` CLI module. A typo
/// there produces a unit whose `ExecStart` fails at every firing — and it
/// would also quietly break the pairing above, so a derivation that
/// stopped matching anything could not hide behind a green parity run.
#[test]
fn every_dsn_direct_timer_names_a_real_subcommand() {
    let cli_dir = workspace_root().join("crates/hort-server/src/cli");
    let timers = ansible_timers();
    let dsn_direct: Vec<&Timer> = timers.iter().filter(|t| t.path == "dsn-direct").collect();
    assert!(
        dsn_direct.len() >= 6,
        "expected several dsn-direct timers; found {}",
        dsn_direct.len(),
    );
    for timer in dsn_direct {
        let sub = timer
            .exec_subcommand
            .as_deref()
            .expect("dsn-direct entries carry an exec_subcommand");
        let module = cli_dir.join(format!("{}.rs", sub.replace('-', "_")));
        assert!(
            module.is_file(),
            "systemd unit for `{}` runs `hort-server {sub}`, but there is no CLI module at \
             {} — the subcommand does not exist and every firing would exit non-zero",
            timer.slug,
            module.display(),
        );
    }
}
