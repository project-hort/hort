# 380 — A digest is invalid before it is unsupported

**Issue:** #407 · **Branch:** `agent/407-digest-grammar-before-algorithm` · single item.

Found by the third review pass over everything since `v0.17.2`; approved by the
maintainer as an obviously correct and necessary correction.

## The finding

**Both digest classifiers test algorithm membership before grammar**, and so
report a grammatically invalid digest as "algorithm not supported":

- `crates/hort-http-oci/src/digest.rs:55-58` — a request-line digest;
- `crates/hort-domain/src/oci.rs:1271-1273` — a digest read out of a document.

The two are deliberately kept in lockstep; the second one's doc comment says
*"Two boundaries, two inputs; one rule."* So the correction has to reach both,
and neither may acquire its own reading.

The [OCI descriptor grammar][oci] requires a non-empty lowercase algorithm and
a non-empty `encoded` portion drawn from a fixed character set. Values like
`sha512:`, `sha512:!`, `:abc` and `SHA256:…` are therefore **invalid digests**,
not merely unsupported ones. The OCI write path answers them `UNSUPPORTED`
today (`crates/hort-http-oci/src/manifests_write.rs:1978-1986`) where the spec
calls for `DIGEST_INVALID`.

[oci]: https://github.com/opencontainers/image-spec/blob/main/descriptor.md#digests

**What made this visible, and it is the part worth keeping in mind:** a guard
added in this cycle (`digest.rs:224-238`) certifies that the two classifiers
agree *arm for arm* — and omits exactly the invalid-other-algorithm case. It
attests to the misclassification instead of catching it. A guard that pins
agreement between two copies of a rule says nothing about whether the rule is
right.

## Why this is a correction and not a decision

The project's authority order puts the protocol specification above the
implementation. Both answers are 4xx refusals, so no client depends on being
told "unsupported" for malformed input: the change moves no input from accepted
to refused or back, only the code and the message.

## The outcome

1. **Grammar first, algorithm support second**, in both classifiers. A value
   that violates the grammar is invalid; a grammatically valid value naming an
   algorithm other than `sha256` stays unsupported.
2. **The lockstep holds** — one rule, two boundaries.
3. **The guard gains the missing rows**: invalid other-algorithm cases (empty
   encoded portion, forbidden character, empty algorithm, uppercase), each
   asserting the same answer on both sides.
4. No attacker-supplied value reaches a response body; the module's existing
   rule stands, and those values belong in `tracing::debug!`.

## Acceptance

1. One test per case pinning the **answer**, not only the classification:
   `sha512:` and `sha512:!` give `DIGEST_INVALID`, while a grammatical
   `sha512:<128 hex>` stays `UNSUPPORTED`.
2. The guard fails when only one of the two sides is corrected — shown by a
   mutation, not asserted.
3. `sha256:<64 hex>` stays valid; no existing acceptance case flips.
4. `CHANGELOG.md`: one entry. The response code for an invalid digest changes,
   which every OCI client can observe.
