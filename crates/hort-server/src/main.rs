//! `hort-server` binary entrypoint.
//!
//! Thin dispatcher. All business logic — the serve path, migrations, and
//! future admin/scrub subcommands — lives under [`hort_server::cli`].
//! Keeping `main` trivial means a human can audit the entry point at a
//! glance.

fn main() -> std::process::ExitCode {
    hort_server::cli::run()
}
