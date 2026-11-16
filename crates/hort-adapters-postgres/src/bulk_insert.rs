//! Multi-row `INSERT` arity: the one place PostgreSQL's bind-parameter
//! limit meets a statement's column list.
//!
//! A `push_values` insert binds one parameter per column per row, and
//! PostgreSQL refuses a statement carrying more than
//! [`PG_MAX_BIND_PARAMS`] of them before it plans anything — `too many
//! arguments for query: <n>`. So the row count that trips the limit is
//! a function of the statement's column count, and writing it down
//! beside the bind closure cannot keep it true: a column added to the
//! insert moves the real number while the written one stays put, and a
//! stale number is wrong only for batches large enough to reach it.
//!
//! A site therefore declares its column list once and hands it to
//! [`ChunkedInsert`], which renders the `INSERT INTO … (…)` prefix from
//! that list *and* derives [`ChunkedInsert::rows_per_statement`] from
//! the same list. There is no second number to keep equal by hand.
//!
//! Execution runs on the **caller's** connection — one statement per
//! chunk, no nested transaction, no commit between chunks. Both
//! consumers are projections of an event append and share that
//! append's transaction
//! ([`crate::artifact_lifecycle::PgArtifactLifecycle::commit_scan_result_with_score`]):
//! a half-written findings set is worse than a failed one, because the
//! artifact then reads as having fewer findings than the scan assessed.

use sqlx::query_builder::Separated;
use sqlx::{PgConnection, Postgres, QueryBuilder};

/// The most bind parameters one PostgreSQL statement can carry.
///
/// A wire-protocol limit, not a tunable: the extended-query `Bind`
/// message counts its parameters in an `int16`, so no server setting
/// raises it and no statement can express more. Crossing it is a hard
/// refusal of the whole statement, not a truncation.
pub(crate) const PG_MAX_BIND_PARAMS: usize = 65_535;

/// A multi-row `INSERT` whose per-statement row budget is derived from
/// its own column list.
pub(crate) struct ChunkedInsert {
    table: &'static str,
    columns: &'static [&'static str],
}

impl ChunkedInsert {
    /// `columns` is the single source of both the rendered prefix and
    /// the chunk size.
    ///
    /// The two assertions are what make [`Self::rows_per_statement`] a
    /// positive number rather than a division hazard, and because every
    /// construction site is a `const`, they fail the build rather than a
    /// request.
    pub(crate) const fn new(table: &'static str, columns: &'static [&'static str]) -> Self {
        assert!(
            !columns.is_empty(),
            "a multi-row INSERT needs at least one column"
        );
        assert!(
            columns.len() <= PG_MAX_BIND_PARAMS,
            "a single row of this table already exceeds the bind-parameter limit"
        );
        Self { table, columns }
    }

    /// `INSERT INTO <table> (<columns>) ` — the fragment every chunk's
    /// statement opens with, rendered from the same list the budget
    /// below is derived from.
    pub(crate) fn prefix(&self) -> String {
        format!("INSERT INTO {} ({}) ", self.table, self.columns.join(", "))
    }

    /// How many rows fit in one statement. Positive by construction.
    pub(crate) const fn rows_per_statement(&self) -> usize {
        PG_MAX_BIND_PARAMS / self.columns.len()
    }

    /// Split `rows` into the batches one statement each may carry.
    ///
    /// An empty `rows` yields no batch, which is how both sites keep
    /// their promise that an empty input issues no SQL at all.
    pub(crate) fn chunks<'r, T>(&self, rows: &'r [T]) -> std::slice::Chunks<'r, T> {
        rows.chunks(self.rows_per_statement())
    }

    /// Build the statement for one chunk of rows.
    ///
    /// Kept separate from [`Self::execute_chunked`] so a test can render
    /// a small batch and count its placeholders with no database — the
    /// check that catches a column added to the list whose `push_bind`
    /// nobody wrote.
    pub(crate) fn statement<T, F>(&self, chunk: &[T], bind_row: F) -> QueryBuilder<Postgres>
    where
        F: FnMut(Separated<'_, Postgres, &'static str>, &T),
    {
        let mut qb = QueryBuilder::new(self.prefix());
        qb.push_values(chunk, bind_row);
        qb
    }

    /// Insert every row in `rows`, one statement per
    /// [`Self::rows_per_statement`]-sized chunk, on `conn`.
    ///
    /// `conn` is the caller's connection, so every chunk lands in the
    /// transaction the caller already holds: the whole batch commits
    /// with that transaction or none of it does. Empty `rows` yields no
    /// chunk and so issues no statement at all.
    pub(crate) async fn execute_chunked<T, F>(
        &self,
        conn: &mut PgConnection,
        rows: &[T],
        mut build_statement: F,
    ) -> Result<(), sqlx::Error>
    where
        F: FnMut(&[T]) -> QueryBuilder<Postgres>,
    {
        for chunk in self.chunks(rows) {
            build_statement(chunk).build().execute(&mut *conn).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in row: the helper is generic over the row type, so the
    /// arity properties can be pinned without either production table.
    struct Row(i32);

    const TWO: ChunkedInsert = ChunkedInsert::new("t", &["a", "b"]);

    /// The prefix names the table and every column, in the list's
    /// order, and ends in the space `push_values` writes `VALUES `
    /// after.
    #[test]
    fn prefix_renders_the_column_list() {
        assert_eq!(TWO.prefix(), "INSERT INTO t (a, b) ");
    }

    /// The budget is derived from the column count, so a statement at
    /// the budget cannot exceed the parameter limit — and one more row
    /// than the budget would.
    #[test]
    fn the_budget_is_the_parameter_limit_divided_by_the_column_count() {
        assert_eq!(TWO.rows_per_statement(), PG_MAX_BIND_PARAMS / 2);
        assert!(TWO.rows_per_statement() * 2 <= PG_MAX_BIND_PARAMS);
        assert!((TWO.rows_per_statement() + 1) * 2 > PG_MAX_BIND_PARAMS);
    }

    /// One placeholder per column per row, numbered from `$1` — the
    /// property the per-site arity tests assert against their own
    /// column lists.
    #[test]
    fn a_statement_binds_one_placeholder_per_column_per_row() {
        let rows = [Row(1), Row(2), Row(3)];
        let sql = TWO
            .statement(&rows, |mut b, row| {
                b.push_bind(row.0).push_bind(row.0);
            })
            .into_string();
        assert_eq!(sql.matches('$').count(), rows.len() * 2);
        assert_eq!(
            sql,
            "INSERT INTO t (a, b) VALUES ($1, $2), ($3, $4), ($5, $6)"
        );
    }

    /// An empty input yields no batch, so no statement is built and
    /// none is issued — the no-rows fast path, held by the chunker
    /// rather than by an early return each site has to remember.
    #[test]
    fn an_empty_input_yields_no_statement() {
        let none: [Row; 0] = [];
        assert_eq!(TWO.chunks(&none).count(), 0);
    }

    /// One row past the budget is two statements, not one oversized
    /// one — and the first is full. This is the split the parameter
    /// limit exists to force; the DB-backed tests then prove the server
    /// accepts it.
    #[test]
    fn one_row_past_the_budget_splits_into_two_statements() {
        let budget = TWO.rows_per_statement();
        let rows: Vec<Row> = (0..=budget).map(|i| Row(i as i32)).collect();
        let chunks: Vec<usize> = TWO.chunks(&rows).map(<[Row]>::len).collect();
        assert_eq!(chunks, vec![budget, 1]);
    }

    /// A one-column insert binds one parameter a row, so its budget is
    /// the whole limit. Constructed at runtime rather than as a `const`,
    /// which is what exercises the constructor's guards as code.
    #[test]
    fn a_one_column_insert_spends_the_whole_limit_on_rows() {
        let one = ChunkedInsert::new("t", &["a"]);
        assert_eq!(one.rows_per_statement(), PG_MAX_BIND_PARAMS);
        assert_eq!(one.prefix(), "INSERT INTO t (a) ");
    }

    /// An empty column list has no budget to derive — the division has
    /// no answer. Every production construction site is a `const`, so
    /// the refusal is a build failure there; this runtime call is what
    /// shows the refusal exists.
    #[test]
    #[should_panic(expected = "at least one column")]
    fn new_refuses_an_empty_column_list() {
        let _ = ChunkedInsert::new("t", &[]);
    }

    /// A table whose single row is wider than the limit has no workable
    /// chunk size either: one row already cannot be bound, and a budget
    /// of zero would make `chunks` panic instead of the constructor.
    #[test]
    #[should_panic(expected = "exceeds the bind-parameter limit")]
    fn new_refuses_a_row_wider_than_the_limit() {
        // Leaked because the constructor takes a `&'static` list, which
        // a runtime-built one is not without this.
        let wide: &'static [&'static str] =
            Box::leak(vec!["c"; PG_MAX_BIND_PARAMS + 1].into_boxed_slice());
        let _ = ChunkedInsert::new("t", wide);
    }

    /// The limit is the wire-protocol number. Pinned so a "let's make
    /// this configurable" change has to argue with the `int16` rather
    /// than with a reviewer's memory.
    #[test]
    fn the_parameter_limit_is_the_int16_maximum() {
        assert_eq!(PG_MAX_BIND_PARAMS, usize::from(u16::MAX));
    }
}
