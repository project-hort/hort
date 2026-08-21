# 130 — Record the registry-version precondition in RELEASING.md

Issue: #186 (second of two items; the first is `129-resumable-crates-publish.md`).

## Why

hort publishes its own crates to a hort instance. So the release process can
depend on registry behaviour that ships *in the release being made* — the
write-authorized hold-read (#179) is the current example: without it, a
publish into a quarantining hosted repo cannot resolve its own just-uploaded
siblings.

Whenever that is true, the registry has to be running a build containing the
feature **before** the publish that relies on it. Nothing enforces or records
that today, and nothing makes it easy to check.

The cost of not having it written down is concrete: when the
`v0.11.0-beta.7` publish failed on exactly the sibling-resolution step #179
prevents, the first question — *was the exemption even running?* — could not
be answered from the repository, and the wrong answer was asserted twice
before the operator settled it. **This item does not claim that was the cause
of that failure**; at the time of writing the root cause is still open on
#186. It documents the check whose absence made the question expensive.

## What to write

Add the precondition to `RELEASING.md`, at the pre-release cut and the
promotion both:

> Before a release whose publish path depends on a registry feature, confirm
> `registry.hort.rs` is running a build that contains it.

Make it checkable, and make it match how that host is actually deployed:

- **`registry.hort.rs` is the native deploy** — `site-native.yml` and the
  `hort_binaries` role, which installs cosign-verified GitHub release binaries
  at an explicit `hort_version` given on the command line. It is deliberately
  not pinned in `group_vars`, so **the running version cannot be read out of
  this repository** — ask the host: `hort-server --version`.
- Establish which releases carry the feature: `git tag --contains <sha>`.
- Note the two staleness traps so nobody infers a version from the wrong
  place: `hort_version=latest` resolves `/releases/latest`, which **excludes
  prereleases**; and the `hort_server_image` / `hort_worker_image` `:latest`
  pins in `group_vars/all.yml` belong to the **podman** playbook
  (`site-podman.yml`), not to this host. Both are covered in #185.

State the consequence plainly: if the feature's first tag is newer than what
the host reports, the publish cannot work — and the failure looks exactly like
the feature being broken. That ambiguity is the expensive part, because the
two signatures are identical from outside and only one is cheap to rule out.

## Done when

- `RELEASING.md` states the precondition at both the pre-release cut and the
  promotion, with `hort-server --version` on the host and
  `git tag --contains` written out as the two checks.
- The text says explicitly that the version is not derivable from the
  checkout, and names the two places that look like they answer it but do not.

## Note for the implementer

Docs-only. Per the gate-economy rule this needs no `cargo fmt` / `clippy` /
test run — a docs-only diff touching nothing under `crates/`, `Cargo.*` or
`migrations/`.
