# Repository types and supported formats

Choose the repository type that matches your clients and publishing workflow.

## Repository types

| Type | Use it when |
| --- | --- |
| `hosted` | Your teams publish and consume artifacts stored in hort. |
| `proxy` | Clients consume artifacts from an external upstream through hort. |
| `virtual` | Clients need a single endpoint across compatible repositories. |
| `staging` | Artifacts require a separate publishing stage before regular consumption. |

Repositories have a stable `metadata.name` and an artifact format. A `proxy` repository requires its proxy configuration; the available upstream-mapping model is explained in [OCI pull-through](oci-pull-through.md). Repository storage uses the configured [deployment-wide content-addressed storage backend](../installation/storage.md), rather than a freely selectable backend per repository.

## Formats and constraints

hort supports OCI/Docker, npm, PyPI, Cargo, and Maven/Gradle. Virtual repositories are supported for npm, PyPI, Cargo and Maven/Gradle, **not OCI**. Do not combine different formats or nest virtual repositories.

## OCI referrers metadata compatibility

OCI subject-reference records written before the descriptor metadata projection
do not contain the referring name, config media type, or annotations. They are
not backfilled. A missing key on such a record means **unknown**, not that the
referring manifest declared the field absent. A same-digest re-push preserves
the existing record's metadata; it does not fill these keys. If the same
manifest bytes are published under multiple names in one repository, those
names still share one artifact and subject-reference record, so the record
cannot retain every name.
The referrers response remains unchanged by this storage update.

## Set up a repository

1. Decide whether clients will publish (`hosted`) or consume from an upstream (proxy or a hosted repository with explicit upstream mappings, depending on the format and supported configuration).
2. Declare the repository and, if needed, its upstream settings in version-controlled YAML.
3. Store upstream credentials outside the repository declaration and refer to them through supported secret references.
4. [Validate and apply the configuration](../configuration/declarative.md).
5. Configure a native client and verify a real pull or push. See [OCI](oci-pull-through.md), [npm](npm-pull-through.md), or [PyPI](pypi-pull-through.md).

For access control, see [Identity & access](../configuration/identity-access.md). For issues during rollout, see [Monitoring & troubleshooting](../operations/monitoring.md).
