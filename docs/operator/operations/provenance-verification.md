# Verify OCI artifact provenance

hort can verify OCI signatures and attestations with a worker-side verifier and a repository-scoped `ScanPolicy`. Verification does not happen solely because a policy is declared: the worker must have the matching verifier configured.

## Prepare the verifier

For keyless Sigstore verification in Kubernetes, provide a **pinned**, maintained trust-root file to the worker, then set:

```yaml
worker:
  enabled: true
  provenance:
    cosign:
      enabled: true
      trustedRootFile: /etc/hort/provenance/trusted_root.json
```

Mount a real trusted-root JSON file at that path using your chart-approved volume configuration. The verifier uses the pinned root offline. If the file is missing, unreadable or stale, worker startup can fail. For keyed cosign signatures, the worker also supports a configured pinned public-key file; consult the version-specific configuration reference before using that backend.

## Choose a repository policy

Start with `verify_if_present` for a repository where signatures may not always exist:

```yaml
apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: verify-internal-images
spec:
  scope:
    repository: internal-images
  provenanceMode: verify_if_present
  provenanceBackends: [cosign]
  provenanceIdentities:
    - issuer: https://token.actions.githubusercontent.com
      san: https://github.com/example-org/example/.github/workflows/release.yml@refs/heads/main
```

Replace the sample issuer and signer identity with the trusted publisher **you actually control**. Validate and apply the configuration using the normal GitOps workflow.

## Enforce only after verifying the whole path

`provenanceMode: required` holds OCI artifacts until a valid attestation from an allowed signer is verified. **Do not turn it on before the verifier, trust root and signed publishing path are working.** GitOps validation cannot establish whether the worker verifier is enabled. A mismatched setup can leave artifacts quarantined indefinitely.

Verify a known signed image end to end before enforcing `required`, then monitor worker logs and quarantined artifacts after the policy change. If verification fails, fix trust-root, signer, signature format and worker configuration rather than bypassing quarantine. See [Scanning & governance](scanning-governance.md) and [Server & workers](workers.md).
