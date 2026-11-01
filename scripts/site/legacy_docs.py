"""Transition policy for old operator URLs. This is intentionally not a redirect table.

Preserve existing anchors while curating replacements. A path appearing here means
'possible successor'; it does not imply feature parity.
"""

REPLACEMENTS = {'how-to/oci-pull-through.md': 'repositories/oci-pull-through', 'how-to/deploy/install.md': 'installation/kubernetes-helm', 'how-to/deploy/self-contained-registry-install.md': 'installation/native-linux', 'how-to/declare-gitops-config.md': 'configuration/declarative', 'how-to/operate/claim-based-rbac.md': 'configuration/identity-access', 'how-to/federate-ci-oidc.md': 'configuration/identity-access', 'how-to/federate-k8s-workload-identity.md': 'configuration/identity-access', 'how-to/curator-workflow.md': 'operations/scanning-governance', 'how-to/quarantine-patch-release.md': 'operations/scanning-governance', 'reference/server-and-worker-configuration.md': 'operations/workers', 'how-to/deploy/local-bringup.md': 'installation/native-linux', 'how-to/deploy/values-reference.md': 'installation/kubernetes-helm', 'how-to/operate/metrics-scraper-service-account.md': 'operations/monitoring'}
DEVELOPER_OR_INTERNAL = ['how-to/add-a-format-handler.md', 'how-to/alpha-testing-runbook.md', 'how-to/deploy/examples-overlays.md', 'how-to/operate/public-supply-chain-deployment.md', 'reference/apply-time-linter-rows.md', 'reference/event-taxonomy.md', 'reference/npm-format-entities.md', 'tutorial/first-ingest.md']

def classify(source):
    rel = source.removeprefix("docs/architecture/")
    if rel in DEVELOPER_OR_INTERNAL:
        return "developer", None
    if rel in REPLACEMENTS:
        return "superseded", REPLACEMENTS[rel]
    return "legacy", None
