# Test-only OCI token signing key (native-tokens compose overlay)

`oci-signing-key.pem` is a **throwaway, test-only** Ed25519 (PKCS#8) private key
committed on purpose. It exists solely so the sibling
`deploy/compose/docker-compose.native-tokens.yml` overlay can boot the dev/CI
compose stack with `HORT_NATIVE_TOKENS_ENABLED=true` — the boot gate requires an
OCI token signing key (`HORT_OCI_TOKEN_SIGNING_KEY_FILE`) so `/v2/auth` can mint
capability JWTs. It signs **only** short-lived (5-minute) OCI access tokens for
the ephemeral compose registry — never anything real. There is no secret to
protect here; the same convention as the committed cosign test keypair under
`scripts/native-tests/fixtures/cosign/`.

Do NOT reuse this key outside the compose dev/CI stack. Production deployments
generate their own key (the Helm `nativeTokens` values / the
`HORT_OCI_TOKEN_SIGNING_KEY_FILE` environment variable).

## Regenerating

```bash
openssl genpkey -algorithm ed25519 \
  -out deploy/compose/native-tokens/oci-signing-key.pem
```
