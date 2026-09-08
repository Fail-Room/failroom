"""Version 2. No destructive or implicit migration is supported."""

APPLICATION_ID = 0x4641494C
LEGACY_VERSION = 1
VERSION = 2

STATEMENTS = (
    """CREATE TABLE room_attempts (
        attempt_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        sandbox_id TEXT NOT NULL UNIQUE,
        generation INTEGER NOT NULL CHECK(generation > 0),
        active_sandbox_id TEXT,
        state TEXT NOT NULL CHECK(state IN
            ('PROVISIONING','READY','RUNNING','RESOLVED','STOPPING','FAILED','DESTROYED')),
        session_epoch INTEGER NOT NULL DEFAULT 0 CHECK(session_epoch >= 0),
        version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
        provisioning_intent INTEGER NOT NULL DEFAULT 1 CHECK(provisioning_intent IN (0,1)),
        expiry_intent INTEGER NOT NULL DEFAULT 0 CHECK(expiry_intent IN (0,1)),
        destroy_intent INTEGER NOT NULL DEFAULT 0 CHECK(destroy_intent IN (0,1)),
        runtime_operation_id TEXT,
        CHECK(active_sandbox_id IS NULL OR active_sandbox_id = sandbox_id),
        CHECK(expiry_intent = 0 OR destroy_intent = 1),
        CHECK(destroy_intent = 0 OR state IN ('STOPPING','FAILED','DESTROYED')),
        UNIQUE(attempt_id, sandbox_id, generation, expires_at)
    ) STRICT""",
    """CREATE TABLE sandbox_resources (
        sandbox_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL,
        generation INTEGER NOT NULL CHECK(generation > 0),
        state TEXT NOT NULL CHECK(state IN
            ('REQUESTED','CREATING','STARTING','READY','RUNNING','RESOLVED',
             'STOPPING','FAILED','DESTROYED')),
        version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
        container_id TEXT UNIQUE,
        runtime_operation_id TEXT,
        expires_at INTEGER NOT NULL,
        expiry_intent INTEGER NOT NULL DEFAULT 0 CHECK(expiry_intent IN (0,1)),
        destroy_intent INTEGER NOT NULL DEFAULT 0 CHECK(destroy_intent IN (0,1)),
        evidence_digest TEXT,
        cleanup_evidence_digest TEXT,
        FOREIGN KEY(attempt_id, sandbox_id, generation, expires_at)
            REFERENCES room_attempts(attempt_id, sandbox_id, generation, expires_at),
        CHECK(expiry_intent = 0 OR destroy_intent = 1),
        CHECK(destroy_intent = 0 OR state IN ('STOPPING','FAILED','DESTROYED')),
        CHECK(state != 'DESTROYED' OR cleanup_evidence_digest IS NOT NULL)
    ) STRICT""",
    """CREATE TABLE terminal_capability_uses (
        jti_hash TEXT PRIMARY KEY CHECK(length(jti_hash) = 64),
        attempt_id TEXT NOT NULL REFERENCES room_attempts(attempt_id),
        consumed_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK(expires_at > consumed_at),
        consumed INTEGER NOT NULL DEFAULT 1 CHECK(consumed = 1)
    ) STRICT""",
    """CREATE TABLE lifecycle_operations (
        operation_id TEXT PRIMARY KEY,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        attempt_id TEXT NOT NULL REFERENCES room_attempts(attempt_id),
        sandbox_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('SUCCEEDED','PENDING','RETRY')),
        result_state TEXT NOT NULL,
        result_version INTEGER NOT NULL,
        retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count >= 0),
        retry_at INTEGER NOT NULL DEFAULT 0,
        error_code TEXT CHECK(error_code IN
            ('CREATE_FAILED','START_FAILED','RUNTIME_UNAVAILABLE','CLEANUP_INCOMPLETE')),
        UNIQUE(actor, idempotency_key)
    ) STRICT""",
    "CREATE INDEX attempts_expiry ON room_attempts(expires_at) WHERE state != 'DESTROYED'",
    "CREATE INDEX operations_retry ON lifecycle_operations(status, retry_at)",
    *(
        f"""CREATE TRIGGER {table}_immutable BEFORE UPDATE ON {table}
            WHEN NEW.expires_at != OLD.expires_at
              OR NEW.attempt_id != OLD.attempt_id
              OR NEW.runtime_operation_id IS NOT OLD.runtime_operation_id
              OR NEW.sandbox_id != OLD.sandbox_id
              OR NEW.generation != OLD.generation
              OR NEW.expiry_intent < OLD.expiry_intent
              OR NEW.destroy_intent < OLD.destroy_intent
              OR (OLD.state = 'DESTROYED' AND NEW.state != 'DESTROYED')
            BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_STATE'); END"""
        for table in ("room_attempts", "sandbox_resources")
    ),
    """CREATE TRIGGER attempt_owner_immutable BEFORE UPDATE ON room_attempts
        WHEN NEW.user_id != OLD.user_id OR NEW.room_id != OLD.room_id
          OR NEW.session_epoch < OLD.session_epoch
        BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_OWNER'); END""",
)

V1_STATEMENTS = tuple(
    statement.replace("        runtime_operation_id TEXT,\n", "").replace(
        "              OR NEW.runtime_operation_id IS NOT OLD.runtime_operation_id\n",
        "",
    )
    for statement in STATEMENTS
)

V2_ROOM_ATTEMPTS_IMMUTABLE_TRIGGER = next(
    statement
    for statement in STATEMENTS
    if statement.startswith("CREATE TRIGGER room_attempts_immutable")
)
V2_SANDBOX_RESOURCES_IMMUTABLE_TRIGGER = next(
    statement
    for statement in STATEMENTS
    if statement.startswith("CREATE TRIGGER sandbox_resources_immutable")
)
MIGRATE_V1_TO_V2 = (
    "ALTER TABLE room_attempts ADD COLUMN runtime_operation_id TEXT",
    "ALTER TABLE sandbox_resources ADD COLUMN runtime_operation_id TEXT",
    "DROP TRIGGER room_attempts_immutable",
    "DROP TRIGGER sandbox_resources_immutable",
    V2_ROOM_ATTEMPTS_IMMUTABLE_TRIGGER,
    V2_SANDBOX_RESOURCES_IMMUTABLE_TRIGGER,
)
