-- The earlier backfill replaced prototype scan states with quarantined rows.
-- Validate existing rows when adding the replacement CHECK: any remaining
-- legacy value must stop the migration instead of persisting under the new schema.
ALTER TABLE public.artifacts
    DROP CONSTRAINT artifacts_quarantine_status_check;

ALTER TABLE public.artifacts
    ADD CONSTRAINT artifacts_quarantine_status_check CHECK (
        quarantine_status IN ('quarantined', 'released', 'rejected', 'scan_indeterminate')
    );
