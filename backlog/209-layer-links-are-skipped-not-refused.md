# 209 — A layer's link entries are skipped and counted, never a reason to refuse the archive

**Issue:** #264 · **Branch:** `agent/264-trivy-materialisation` (continues 191/202/206) · single item · `hort-adapters-scanner-trivy/src/extract.rs` + tests + E2E re-run.

## Defect (measured on the compose E2E, `quarantine/trivy-oci-not-applicable`, tip `2dadf82b`)

Manifest and config recorded `not_applicable` and were released; the single `alpine:3.19` layer
was refused: `trivy adapter: refusing to materialise archive; no scan will run`, reason
`archive entry link target is not contained in the workspace` → `UnusableArchive` →
`scan_indeterminate`. Cause: `extract_tar` (`extract.rs:353-368`) never creates link entries
(`a_contained_link_is_accepted_but_not_created`) but still returns `ExtractError::UncontainedLink`
for any link whose target is absolute or resolves above the root
(`link_target_is_contained`, `:218`). A root filesystem is full of exactly those —
`/bin/sh -> /bin/busybox`, merged-usr `lib -> usr/lib`, `/etc/…` targets — so every real OS
layer is refused and every Trivy-policed image holds forever. The two tests
`extract_tar_refuses_an_absolute_symlink_target` (`:827`) and
`extract_tar_refuses_a_symlink_escaping_the_root` (`:812`) pin the wrong policy.

## Invariant

Entry **names** must be contained (`UncontainedPath` stays a refusal: a name that escapes would
write outside the workspace). Link **targets** are never followed and never materialised, so an
uncontained target cannot write, read or expose anything: it is skipped and counted, not a
refusal. Absolute targets are the normal shape inside a layer (rooted at the image root), not an
attack.

## Change

1. `extract_tar`: for `Symlink`/`Link` entries, skip the entry unconditionally and count it
   (`skipped_links`); drop `ExtractError::UncontainedLink` and `link_target_is_contained` (or
   keep the latter only as a debug classification — no control flow). The same for `extract_zip`
   if it handles link entries.
2. Extraction summary (whatever `extract_*` returns) carries `skipped_links`; the adapter logs it
   on the `materialised` debug line and on the empty-report warning.
3. Tests: rewrite `:812`/`:827`/`:842` into "an absolute / escaping / hardlink-escaping link is
   skipped and counted, the archive extracts, the link does not exist on disk"; add a busybox-
   shaped fixture (`bin/busybox` regular file, `bin/sh -> /bin/busybox` absolute symlink,
   `lib -> usr/lib` relative symlink, one `../..` escaping symlink, one hardlink) asserting the
   regular files land, no link exists, `skipped_links == 4`, and — in the `TRIVY_BIN`-gated
   evidence test — that `trivy rootfs` still reads `lib/apk/db/installed`. Keep
   `UncontainedPath` refusal tests untouched.
4. Docs: the `workspace.rs`/`extract.rs` module doc paragraph on containment states the
   name-vs-target distinction; `scanning-pipeline.md`'s extraction-bounds paragraph likewise.
   `CHANGELOG.md`: fold into this branch's bullet.

## Acceptance

- `quarantine/trivy-oci-not-applicable` green on the reporter's harness: the layer records an
  analysed verdict, manifest/config `not_applicable`, all released, anonymous pull 200.
- `--group quarantine --group clients` green.
- Gate green; no issue numbers in code.
