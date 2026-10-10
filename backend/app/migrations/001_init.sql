-- 001_init.sql : initial schema for the NEMSEC Phishing Investigation Workbench
-- Every table that stores observations keeps raw values (JSON) alongside
-- normalised columns so the original evidence is never "cleaned away".

CREATE TABLE evidence (
    id                 TEXT PRIMARY KEY,          -- EV-xxxxxxxx (email) / AT-xxxxxxxx (attachment)
    kind               TEXT NOT NULL CHECK (kind IN ('email', 'attachment')),
    sha256             TEXT NOT NULL,
    size_bytes         INTEGER NOT NULL,
    original_filename  TEXT,                       -- as supplied by uploader / MIME header (display only)
    stored_name        TEXT NOT NULL UNIQUE,       -- generated, never user-controlled
    parent_id          TEXT REFERENCES evidence(id),
    mime_part_ref      TEXT,                       -- e.g. "1.2" path inside the source MIME tree
    imported_at        TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_evidence_email_sha ON evidence(sha256) WHERE kind = 'email';
CREATE INDEX ix_evidence_parent ON evidence(parent_id);

-- One row per upload action, including duplicates of already-preserved bytes.
CREATE TABLE evidence_imports (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id        TEXT NOT NULL REFERENCES evidence(id),
    original_filename  TEXT,
    size_bytes         INTEGER NOT NULL,
    imported_at        TEXT NOT NULL,
    duplicate          INTEGER NOT NULL DEFAULT 0,
    case_id            TEXT
);

CREATE TABLE emails (
    evidence_id     TEXT PRIMARY KEY REFERENCES evidence(id),
    parse_status    TEXT NOT NULL CHECK (parse_status IN ('parsed', 'partial', 'failed')),
    subject         TEXT,
    from_address    TEXT,
    from_display    TEXT,
    date_utc        TEXT,
    message_id      TEXT,
    parsed_json     TEXT NOT NULL,      -- full structured parse incl. raw header values
    warnings_json   TEXT NOT NULL DEFAULT '[]',
    errors_json     TEXT NOT NULL DEFAULT '[]',
    parsed_at       TEXT NOT NULL
);

CREATE TABLE attachments (
    evidence_id        TEXT PRIMARY KEY REFERENCES evidence(id),
    email_evidence_id  TEXT NOT NULL REFERENCES evidence(id),
    filename_raw       TEXT,
    filename_display   TEXT,
    declared_mime      TEXT,
    disposition        TEXT,
    detected_type      TEXT,
    static_status      TEXT NOT NULL DEFAULT 'pending'
        CHECK (static_status IN ('pending', 'running', 'complete', 'partial', 'unsupported', 'encrypted', 'failed', 'too_large')),
    static_result_json TEXT,
    static_updated_at  TEXT
);

CREATE TABLE urls (
    id                 TEXT PRIMARY KEY,
    email_evidence_id  TEXT NOT NULL REFERENCES evidence(id),
    source             TEXT NOT NULL,       -- text_body | html_href | html_text | attachment
    original           TEXT NOT NULL,       -- byte-faithful string as extracted
    visible_text       TEXT,
    scheme             TEXT,
    hostname           TEXT,
    normalized_host    TEXT,
    parse_ok           INTEGER NOT NULL,
    warnings_json      TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE findings (
    id                  TEXT PRIMARY KEY,
    email_evidence_id   TEXT NOT NULL REFERENCES evidence(id),
    subject_evidence_id TEXT,                -- attachment id when the finding concerns one
    rule_id             TEXT NOT NULL,
    name                TEXT NOT NULL,
    category            TEXT NOT NULL,
    explanation         TEXT NOT NULL,
    evidence_json       TEXT NOT NULL,       -- exact supporting values
    confidence          TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    uncertainty         TEXT,
    benign_json         TEXT NOT NULL DEFAULT '[]',
    created_at          TEXT NOT NULL
);
CREATE INDEX ix_findings_email ON findings(email_evidence_id);

CREATE TABLE cases (
    id           TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    closed_at    TEXT
);

CREATE TABLE case_evidence (
    case_id            TEXT NOT NULL REFERENCES cases(id),
    evidence_id        TEXT NOT NULL REFERENCES evidence(id),
    include_in_report  INTEGER NOT NULL DEFAULT 1,
    added_at           TEXT NOT NULL,
    PRIMARY KEY (case_id, evidence_id)
);

CREATE TABLE case_findings (
    case_id            TEXT NOT NULL REFERENCES cases(id),
    finding_id         TEXT NOT NULL REFERENCES findings(id),
    review_status      TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK (review_status IN ('unreviewed', 'relevant', 'benign', 'unresolved')),
    analyst_comment    TEXT NOT NULL DEFAULT '',
    include_in_report  INTEGER NOT NULL DEFAULT 1,
    updated_at         TEXT NOT NULL,
    PRIMARY KEY (case_id, finding_id)
);

CREATE TABLE notes (
    id             TEXT PRIMARY KEY,
    case_id        TEXT NOT NULL REFERENCES cases(id),
    kind           TEXT NOT NULL CHECK (kind IN ('fact', 'interpretation', 'question', 'note')),
    body           TEXT NOT NULL,
    evidence_refs  TEXT NOT NULL DEFAULT '[]',
    resolved       INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE TABLE reference_identities (
    id            TEXT PRIMARY KEY,
    case_id       TEXT,                        -- NULL = global
    display_name  TEXT NOT NULL,
    email         TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,                 -- static_analysis | sandbox_submit | sandbox_poll
    ref_id      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'error')),
    run_after   TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX ix_jobs_ready ON jobs(status, run_after);

CREATE TABLE sandbox_workers (
    name        TEXT PRIMARY KEY,
    adapter     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'busy', 'quarantined')),
    reason      TEXT,
    updated_at  TEXT NOT NULL
);

CREATE TABLE sandbox_jobs (
    id                    TEXT PRIMARY KEY,
    attachment_id         TEXT NOT NULL REFERENCES evidence(id),
    case_id               TEXT,
    adapter               TEXT NOT NULL,          -- cape | demo
    is_demo               INTEGER NOT NULL,
    worker_name           TEXT,
    external_task_id      TEXT,
    state                 TEXT NOT NULL
        CHECK (state IN ('queued', 'running', 'completed', 'failed', 'timed_out', 'cancelled', 'reset_failed')),
    state_detail          TEXT,
    timeout_s             INTEGER NOT NULL,
    submitted_by          TEXT NOT NULL,
    submitted_at          TEXT NOT NULL,
    started_at            TEXT,
    finished_at           TEXT,
    deadline_at           TEXT NOT NULL,
    cancel_requested      INTEGER NOT NULL DEFAULT 0,
    observations_json     TEXT,
    coverage_json         TEXT,
    error                 TEXT
);

CREATE TABLE sandbox_artifacts (
    id              TEXT PRIMARY KEY,
    sandbox_job_id  TEXT NOT NULL REFERENCES sandbox_jobs(id),
    kind            TEXT NOT NULL,              -- screenshot | report_json
    label           TEXT,
    stored_name     TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    retrieved_at    TEXT NOT NULL
);

CREATE TABLE reports (
    id          TEXT PRIMARY KEY,
    case_id     TEXT NOT NULL UNIQUE REFERENCES cases(id),
    created_at  TEXT NOT NULL
);

CREATE TABLE report_revisions (
    id             TEXT PRIMARY KEY,
    report_id      TEXT NOT NULL REFERENCES reports(id),
    revision       INTEGER NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('draft', 'reviewed')),
    content_json   TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    reviewed_at    TEXT,
    reviewer       TEXT,
    pdf_stored_name TEXT,
    pdf_sha256     TEXT,
    UNIQUE (report_id, revision)
);

CREATE TABLE history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      TEXT,
    entity_type  TEXT NOT NULL,
    entity_id    TEXT NOT NULL,
    action       TEXT NOT NULL,
    detail_json  TEXT NOT NULL DEFAULT '{}',
    at           TEXT NOT NULL
);
CREATE INDEX ix_history_case ON history(case_id, at);
