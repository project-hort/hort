//! `hort-worker`'s Postgres connect-options builder.
//!
//! Mirrors `hort_server::pg_identity` — every pool this binary opens
//! routes through [`connect_options`] so the version-stamped
//! `application_name` (`hort-worker/<workspace-version>`,
//! [`hort_config::pg_identity`]) is set exactly once. `hort-server
//! migrate`'s runtime fleet fence reads this identity back out of
//! `pg_stat_activity` (ADR 0030 amendment (c)).

use std::str::FromStr;

use anyhow::Context;
use sqlx::postgres::PgConnectOptions;

use hort_config::pg_identity::{pg_application_name, WORKER_ROLE};

/// Parse `database_url` into [`PgConnectOptions`] stamped with this
/// binary's `application_name`. Every `hort-worker` pool must connect via
/// `.connect_with(connect_options(url)?)` rather than the bare `.connect`.
pub fn connect_options(database_url: &str) -> anyhow::Result<PgConnectOptions> {
    let options = PgConnectOptions::from_str(database_url).context("parsing database URL")?;
    Ok(options.application_name(&pg_application_name(WORKER_ROLE)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_the_worker_application_name() {
        let options =
            connect_options("postgres://user:pw@localhost:5432/db").expect("valid DSN parses");
        assert_eq!(
            options.get_application_name(),
            Some(pg_application_name(WORKER_ROLE).as_str())
        );
    }

    #[test]
    fn rejects_an_unparseable_dsn() {
        let err = connect_options("not a dsn").expect_err("must reject a malformed DSN");
        assert!(format!("{err:#}").contains("parsing database URL"));
    }
}
