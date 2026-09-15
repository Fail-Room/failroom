"""Version 4. No destructive or implicit migration is supported."""

APPLICATION_ID = 0x4641494C
LEGACY_VERSION = 1
V2_VERSION = 2
PREVIOUS_VERSION = 3
VERSION = 4

_V3_BASE_STATEMENTS = (
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

_ATTACHMENT_STATEMENTS = (
    """CREATE TABLE terminal_attachment_leases (
        lease_id TEXT PRIMARY KEY CHECK(length(lease_id) = 32),
        jti_hash TEXT NOT NULL UNIQUE
            REFERENCES terminal_capability_uses(jti_hash),
        actor TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL CHECK(length(request_hash) = 64),
        attempt_id TEXT NOT NULL REFERENCES room_attempts(attempt_id),
        sandbox_id TEXT NOT NULL REFERENCES sandbox_resources(sandbox_id),
        generation INTEGER NOT NULL CHECK(generation > 0),
        session_epoch INTEGER NOT NULL CHECK(session_epoch >= 0),
        gateway_session_hash TEXT NOT NULL
            CHECK(length(gateway_session_hash) = 64),
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
        consumed_at INTEGER NOT NULL
            CHECK(consumed_at >= issued_at AND consumed_at <= expires_at),
        UNIQUE(actor, idempotency_key),
        UNIQUE(gateway_session_hash)
    ) STRICT""",
    "CREATE INDEX attachment_leases_expiry ON terminal_attachment_leases(expires_at)",
)

V2_STATEMENTS = _V3_BASE_STATEMENTS
V3_STATEMENTS = V2_STATEMENTS + _ATTACHMENT_STATEMENTS

_V4_BASE_STATEMENTS = (
    """CREATE TABLE room_attempts (
        attempt_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        sandbox_id TEXT NOT NULL UNIQUE,
        generation INTEGER NOT NULL CHECK(generation > 0),
        active_sandbox_id TEXT,
        active_generation INTEGER CHECK(active_generation IS NULL OR active_generation > 0),
        candidate_sandbox_id TEXT,
        candidate_generation INTEGER CHECK(
            candidate_generation IS NULL OR candidate_generation > 0
        ),
        state TEXT NOT NULL CHECK(state IN
            ('PROVISIONING','RESETTING','READY','RUNNING','RESOLVED',
             'STOPPING','FAILED','DESTROYED')),
        session_epoch INTEGER NOT NULL DEFAULT 0 CHECK(session_epoch >= 0),
        version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
        provisioning_intent INTEGER NOT NULL DEFAULT 1 CHECK(provisioning_intent IN (0,1)),
        reset_intent INTEGER NOT NULL DEFAULT 0 CHECK(reset_intent IN (0,1)),
        expiry_intent INTEGER NOT NULL DEFAULT 0 CHECK(expiry_intent IN (0,1)),
        destroy_intent INTEGER NOT NULL DEFAULT 0 CHECK(destroy_intent IN (0,1)),
        runtime_operation_id TEXT,
        CHECK(
            (active_sandbox_id IS NULL AND active_generation IS NULL)
            OR (active_sandbox_id IS NOT NULL AND active_generation IS NOT NULL)
        ),
        CHECK(
            (candidate_sandbox_id IS NULL AND candidate_generation IS NULL)
            OR (
                candidate_sandbox_id = sandbox_id
                AND candidate_generation = generation
            )
        ),
        CHECK(expiry_intent = 0 OR destroy_intent = 1),
        CHECK(reset_intent = 0 OR state IN ('RESETTING','FAILED','STOPPING','DESTROYED')),
        CHECK(destroy_intent = 0 OR state IN ('STOPPING','FAILED','DESTROYED')),
        UNIQUE(attempt_id, sandbox_id, generation, expires_at)
    ) STRICT""",
    """CREATE TABLE sandbox_resources (
        sandbox_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL REFERENCES room_attempts(attempt_id),
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
        CHECK(expiry_intent = 0 OR destroy_intent = 1),
        CHECK(destroy_intent = 0 OR state IN ('STOPPING','FAILED','DESTROYED')),
        CHECK(state != 'DESTROYED' OR cleanup_evidence_digest IS NOT NULL),
        UNIQUE(attempt_id, sandbox_id, generation)
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
    """CREATE TRIGGER room_attempts_immutable BEFORE UPDATE ON room_attempts
        WHEN NEW.expires_at != OLD.expires_at
          OR NEW.attempt_id != OLD.attempt_id
          OR (
              (
                  NEW.runtime_operation_id IS NOT OLD.runtime_operation_id
                  OR NEW.sandbox_id != OLD.sandbox_id
                  OR NEW.generation != OLD.generation
              )
              AND NOT (
                  OLD.state IN ('READY','RUNNING','RESOLVED')
                  AND NEW.state = 'RESETTING'
                  AND NEW.reset_intent = 1
                  AND NEW.generation = OLD.generation + 1
                  AND NEW.candidate_sandbox_id = NEW.sandbox_id
                  AND NEW.candidate_generation = NEW.generation
                  AND NEW.active_sandbox_id = OLD.active_sandbox_id
                  AND NEW.active_generation = OLD.active_generation
              )
          )
          OR NEW.expiry_intent < OLD.expiry_intent
          OR NEW.destroy_intent < OLD.destroy_intent
          OR (OLD.state = 'DESTROYED' AND NEW.state != 'DESTROYED')
        BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_STATE'); END""",
    """CREATE TRIGGER sandbox_resources_immutable BEFORE UPDATE ON sandbox_resources
        WHEN NEW.expires_at != OLD.expires_at
          OR NEW.attempt_id != OLD.attempt_id
          OR NEW.runtime_operation_id IS NOT OLD.runtime_operation_id
          OR NEW.sandbox_id != OLD.sandbox_id
          OR NEW.generation != OLD.generation
          OR NEW.expiry_intent < OLD.expiry_intent
          OR NEW.destroy_intent < OLD.destroy_intent
          OR (OLD.state = 'DESTROYED' AND NEW.state != 'DESTROYED')
        BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_STATE'); END""",
    """CREATE TRIGGER attempt_owner_immutable BEFORE UPDATE ON room_attempts
        WHEN NEW.user_id != OLD.user_id OR NEW.room_id != OLD.room_id
          OR NEW.session_epoch < OLD.session_epoch
        BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_OWNER'); END""",
)

V4_STATEMENTS = _V4_BASE_STATEMENTS + _ATTACHMENT_STATEMENTS
STATEMENTS = V4_STATEMENTS

V1_STATEMENTS = tuple(
    statement.replace("        runtime_operation_id TEXT,\n", "").replace(
        "              OR NEW.runtime_operation_id IS NOT OLD.runtime_operation_id\n",
        "",
    )
    for statement in V2_STATEMENTS
)

V2_ROOM_ATTEMPTS_IMMUTABLE_TRIGGER = next(
    statement
    for statement in V2_STATEMENTS
    if statement.startswith("CREATE TRIGGER room_attempts_immutable")
)
V2_SANDBOX_RESOURCES_IMMUTABLE_TRIGGER = next(
    statement
    for statement in V2_STATEMENTS
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
MIGRATE_V2_TO_V3 = _ATTACHMENT_STATEMENTS
MIGRATE_V3_TO_V4 = (
    "DROP TRIGGER room_attempts_immutable",
    "DROP TRIGGER sandbox_resources_immutable",
    "DROP TRIGGER attempt_owner_immutable",
    "DROP INDEX attempts_expiry",
    "DROP INDEX operations_retry",
    "DROP INDEX attachment_leases_expiry",
    "ALTER TABLE terminal_attachment_leases RENAME TO terminal_attachment_leases_v3",
    "ALTER TABLE lifecycle_operations RENAME TO lifecycle_operations_v3",
    "ALTER TABLE terminal_capability_uses RENAME TO terminal_capability_uses_v3",
    "ALTER TABLE sandbox_resources RENAME TO sandbox_resources_v3",
    "ALTER TABLE room_attempts RENAME TO room_attempts_v3",
    *V4_STATEMENTS,
    """INSERT INTO room_attempts
    (attempt_id,user_id,room_id,sandbox_id,generation,active_sandbox_id,active_generation,
     candidate_sandbox_id,candidate_generation,state,session_epoch,version,created_at,
     expires_at,provisioning_intent,reset_intent,expiry_intent,destroy_intent,
     runtime_operation_id)
    SELECT attempt_id,user_id,room_id,sandbox_id,generation,
           CASE WHEN active_sandbox_id IS NULL THEN NULL ELSE sandbox_id END,
           CASE WHEN active_sandbox_id IS NULL THEN NULL ELSE generation END,
           CASE WHEN state='PROVISIONING' THEN sandbox_id ELSE NULL END,
           CASE WHEN state='PROVISIONING' THEN generation ELSE NULL END,
           state,session_epoch,version,created_at,expires_at,provisioning_intent,0,
           expiry_intent,destroy_intent,runtime_operation_id
    FROM room_attempts_v3""",
    """INSERT INTO sandbox_resources
    (sandbox_id,attempt_id,generation,state,version,container_id,runtime_operation_id,
     expires_at,expiry_intent,destroy_intent,evidence_digest,cleanup_evidence_digest)
    SELECT sandbox_id,attempt_id,generation,state,version,container_id,runtime_operation_id,
           expires_at,expiry_intent,destroy_intent,evidence_digest,cleanup_evidence_digest
    FROM sandbox_resources_v3""",
    """INSERT INTO terminal_capability_uses
    (jti_hash,attempt_id,consumed_at,expires_at,consumed)
    SELECT jti_hash,attempt_id,consumed_at,expires_at,consumed
    FROM terminal_capability_uses_v3""",
    """INSERT INTO lifecycle_operations
    (operation_id,actor,action,idempotency_key,request_hash,attempt_id,sandbox_id,
     generation,status,result_state,result_version,retry_count,retry_at,error_code)
    SELECT operation_id,actor,action,idempotency_key,request_hash,attempt_id,sandbox_id,
           generation,status,result_state,result_version,retry_count,retry_at,error_code
    FROM lifecycle_operations_v3""",
    """INSERT INTO terminal_attachment_leases
    (lease_id,jti_hash,actor,idempotency_key,request_hash,attempt_id,sandbox_id,generation,
     session_epoch,gateway_session_hash,issued_at,expires_at,consumed_at)
    SELECT lease_id,jti_hash,actor,idempotency_key,request_hash,attempt_id,sandbox_id,
           generation,session_epoch,gateway_session_hash,issued_at,expires_at,consumed_at
    FROM terminal_attachment_leases_v3""",
    "DROP TABLE terminal_attachment_leases_v3",
    "DROP TABLE lifecycle_operations_v3",
    "DROP TABLE terminal_capability_uses_v3",
    "DROP TABLE sandbox_resources_v3",
    "DROP TABLE room_attempts_v3",
)
