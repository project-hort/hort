# Test-only cosign keypair (keyed provenance E2E)

These are **throwaway, test-only** keys committed on purpose. They exist solely so
the native-tests keyed-provenance round-trip
(`scripts/native-tests/scenarios/quarantine/provenance-push-then-sign.sh`) can run
`cosign sign` against a compose-local Hort whose worker has the matching public key
pinned. They sign **only** throwaway test images pushed to the ephemeral compose
registry — never any real artifact. There is no secret to protect here.

- `cosign.pub` — the ECDSA **P-256** SPKI public key (cosign's default
  `generate-key-pair` shape). Mounted read-only into the compose `hort-worker` at
  `/etc/hort/provenance/cosign.pub` and loaded via
  `HORT_PROVENANCE_COSIGN_PUBLIC_KEYS_FILE` so the worker registers the
  `cosign-key` provenance backend (ADR 0039).
- `cosign.key` — the empty-password-encrypted private key the scenario signs with
  (`COSIGN_PASSWORD="" cosign sign --key cosign.key ...`).

## Regenerating

```bash
cd scripts/native-tests/fixtures/cosign
COSIGN_PASSWORD="" cosign generate-key-pair    # cosign v3.x, ECDSA P-256
```

Regenerating is only needed if the key format ever has to change; the compose
worker pins whatever `cosign.pub` is committed here, so the private half and the
mounted public half stay in lockstep by construction.
