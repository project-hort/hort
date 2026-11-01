# Work with ports and adapters

This guide explains the code-level extension pattern used by hort. It is intended for contributors, **not** for operators installing third-party plugins.

## Understand the boundary

- `hort-domain` defines the business model and port traits.
- `hort-app` uses those contracts to implement use cases.
- Outbound adapter crates implement ports for PostgreSQL, storage, identity providers and other infrastructure.
- `hort-server` constructs adapters and wires them into the application at startup.

That is **compile-time composition**, not a dynamically loadable plugin system.

## Trace an existing implementation

For a concrete example, inspect the storage contracts and their implementations:

```text
crates/hort-domain/
crates/hort-app/
crates/hort-adapters-storage/
crates/hort-server/
```

Start at the trait definition; follow where the application calls it; inspect how the adapter implements it; finally find the composition root that wires it. A new adapter should preserve the port's documented behavior and tests.

## Extend a package format

A new registry format is more than an outbound adapter. It typically needs protocol parsing and a dedicated inbound HTTP crate. Use the existing Cargo implementation as a small reference and review the [format handler development guide](../../architecture/how-to/add-a-format-handler.md) in the source repository.

Do not bypass application use cases by reading storage or database state directly from a format HTTP handler. This can bypass authorization, visibility rules and audit semantics.

## Before submitting an extension

Add focused unit tests around port behavior, review failure and retry semantics, and run the checks in [Testing changes](../contributing/testing-changes.md). In your pull request, describe exactly where the component is wired and what changes for operators.

For architectural rationale, consult [Layering and crate map](../../architecture/explanation/layers.md) and the [ADRs](../../adr/) in the repository. Those materials include historical decisions, not necessarily end-user extension promises.
