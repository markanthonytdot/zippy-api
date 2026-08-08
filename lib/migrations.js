const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const MIGRATION_FILENAME_PATTERN = /^(\d{3})_[a-z0-9_]+\.sql$/;
const MIGRATION_LOCK_ID = "8945720316674201";
const DEFAULT_LOCK_TIMEOUT_MS = 30_000;
const DEFAULT_LOCK_RETRY_MS = 250;
const INITIAL_MIGRATION = "001_flight_booking_sessions.sql";

const INITIAL_COLUMNS = [
  "id", "user_id", "checkout_fingerprint", "duffel_offer_id", "offer_snapshot",
  "payload_snapshot", "traveler_info", "contact_info", "selected_services", "currency",
  "offer_minor", "services_minor", "duffel_total_minor", "zippi_fee_minor",
  "charge_total_minor", "stripe_payment_intent_id", "stripe_payment_status",
  "booking_status", "duffel_order_id", "duffel_booking_reference", "duffel_request_id",
  "confirmation_snapshot", "recovery_status", "stripe_refund_id", "failure_code",
  "failure_message", "duffel_attempted_at", "confirmed_at", "created_at", "updated_at",
];

const INITIAL_COLUMN_SHAPES = {
  id: ["uuid", false, null],
  user_id: ["text", false, null],
  checkout_fingerprint: ["text", false, null],
  duffel_offer_id: ["text", false, null],
  offer_snapshot: ["jsonb", false, null],
  payload_snapshot: ["jsonb", false, null],
  traveler_info: ["jsonb", false, null],
  contact_info: ["jsonb", false, null],
  selected_services: ["jsonb", false, "'[]'::jsonb"],
  currency: ["text", false, null],
  offer_minor: ["int8", false, null],
  services_minor: ["int8", false, "0"],
  duffel_total_minor: ["int8", false, null],
  zippi_fee_minor: ["int8", false, "0"],
  charge_total_minor: ["int8", false, null],
  stripe_payment_intent_id: ["text", true, null],
  stripe_payment_status: ["text", false, "'not_created'::text"],
  booking_status: ["text", false, "'payment_setup'::text"],
  duffel_order_id: ["text", true, null],
  duffel_booking_reference: ["text", true, null],
  duffel_request_id: ["text", true, null],
  confirmation_snapshot: ["jsonb", true, null],
  recovery_status: ["text", true, null],
  stripe_refund_id: ["text", true, null],
  failure_code: ["text", true, null],
  failure_message: ["text", true, null],
  duffel_attempted_at: ["timestamptz", true, null],
  confirmed_at: ["timestamptz", true, null],
  created_at: ["timestamptz", false, "now()"],
  updated_at: ["timestamptz", false, "now()"],
};

const INITIAL_INDEXES = {
  idx_flight_booking_sessions_user_created:
    "create index idx_flight_booking_sessions_user_created on public.flight_booking_sessions using btree (user_id, created_at desc)",
  idx_flight_booking_sessions_status:
    "create index idx_flight_booking_sessions_status on public.flight_booking_sessions using btree (booking_status, updated_at)",
  idx_flight_booking_sessions_fingerprint:
    "create index idx_flight_booking_sessions_fingerprint on public.flight_booking_sessions using btree (user_id, checkout_fingerprint)",
};

const INITIAL_BOOKING_STATUSES = [
  "payment_setup", "awaiting_payment", "payment_paid", "booking_in_progress",
  "booking_unknown", "booking_failed_refunded", "booking_failed_refund_pending", "confirmed",
];

const INITIAL_CONSTRAINT_NAMES = [
  "flight_booking_sessions_pkey",
  "flight_booking_sessions_stripe_payment_intent_id_key",
  "flight_booking_sessions_duffel_order_id_key",
  "flight_booking_sessions_booking_status_check",
];

function migrationChecksum(contents) {
  return crypto.createHash("sha256").update(contents).digest("hex");
}

function discoverMigrations(directory) {
  const migrations = fs.readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".sql"))
    .map((entry) => {
      const match = entry.name.match(MIGRATION_FILENAME_PATTERN);
      if (!match) {
        throw new Error(`Invalid migration filename: ${entry.name}`);
      }
      const contents = fs.readFileSync(path.join(directory, entry.name));
      return {
        filename: entry.name,
        version: Number(match[1]),
        checksum: migrationChecksum(contents),
        sql: contents.toString("utf8"),
      };
    })
    .sort((left, right) => left.version - right.version || left.filename.localeCompare(right.filename));

  for (let index = 1; index < migrations.length; index += 1) {
    if (migrations[index - 1].version === migrations[index].version) {
      throw new Error(`Duplicate migration version: ${String(migrations[index].version).padStart(3, "0")}`);
    }
  }
  for (let index = 0; index < migrations.length; index += 1) {
    if (migrations[index].version !== index + 1) {
      throw new Error(`Migration files must form a contiguous sequence starting at 001`);
    }
  }
  return migrations;
}

function normalizedDefinition(value) {
  return String(value || "").toLowerCase().replace(/\s+/g, " ");
}

function normalizedCheckDefinition(value) {
  return normalizedDefinition(value).replace(/::text/g, "").replace(/\s+/g, "");
}

function bookingStatusCheckDefinition(statuses) {
  return `check((booking_status=any(array[${statuses.map((status) => `'${status}'`).join(",")}])) )`
    .replace(/\s+/g, "");
}

function assessInitialMigrationSchema({ tableExists, columns = [], indexes = [], constraints = [] }) {
  if (!tableExists) return { canAdopt: false, tableExists: false, missing: [] };

  const columnMap = new Map(columns.map((column) => [column.name, column]));
  const indexMap = new Map(indexes.map((index) => [index.name, normalizedDefinition(index.definition)]));
  const missing = [];
  for (const column of INITIAL_COLUMNS) {
    const actual = columnMap.get(column);
    if (!actual) {
      missing.push(`column:${column}`);
      continue;
    }
    const [expectedType, expectedNullable, expectedDefault] = INITIAL_COLUMN_SHAPES[column];
    if (actual.type !== expectedType
        || actual.nullable !== expectedNullable
        || normalizedDefinition(actual.defaultValue) !== normalizedDefinition(expectedDefault)) {
      missing.push(`column_shape:${column}`);
    }
  }
  for (const [name, definition] of Object.entries(INITIAL_INDEXES)) {
    if (indexMap.get(name) !== normalizedDefinition(definition)) missing.push(`index:${name}`);
  }
  for (const name of indexMap.keys()) {
    if (!Object.hasOwn(INITIAL_INDEXES, name)) missing.push(`unexpected_index:${name}`);
  }

  const definitions = constraints.map((constraint) => ({
    name: constraint.name,
    type: constraint.type,
    definition: normalizedDefinition(constraint.definition),
  }));
  if (!definitions.some(({ name, type, definition }) => name === INITIAL_CONSTRAINT_NAMES[0] && type === "p" && definition === "primary key (id)")) {
    missing.push("constraint:primary_key_id");
  }
  for (const [column, name] of [
    ["stripe_payment_intent_id", INITIAL_CONSTRAINT_NAMES[1]],
    ["duffel_order_id", INITIAL_CONSTRAINT_NAMES[2]],
  ]) {
    if (!definitions.some((constraint) => (
      constraint.name === name && constraint.type === "u" && constraint.definition === `unique (${column})`
    ))) {
      missing.push(`constraint:unique_${column}`);
    }
  }
  const acceptedBookingChecks = new Set([
    bookingStatusCheckDefinition(INITIAL_BOOKING_STATUSES),
    bookingStatusCheckDefinition([...INITIAL_BOOKING_STATUSES.slice(0, -1), "payment_canceled", "confirmed"]),
  ]);
  const bookingCheck = definitions.find(({ name, type, definition }) => (
    name === INITIAL_CONSTRAINT_NAMES[3]
    && type === "c"
    && acceptedBookingChecks.has(normalizedCheckDefinition(definition))
  ));
  if (!bookingCheck) missing.push("constraint:booking_status_check");
  for (const { name, type } of definitions) {
    // PostgreSQL 18 exposes named NOT NULL constraints through pg_constraint.
    // Nullability is already verified from information_schema above, and those
    // catalog-generated names are not stable schema objects owned by migration 001.
    if (type !== "n" && !INITIAL_CONSTRAINT_NAMES.includes(name)) {
      missing.push(`unexpected_constraint:${name}`);
    }
  }

  return { canAdopt: missing.length === 0, tableExists: true, missing };
}

async function inspectInitialMigrationSchema(client) {
  const tableResult = await client.query(
    "select to_regclass('public.flight_booking_sessions') is not null as table_exists"
  );
  const tableExists = tableResult.rows[0]?.table_exists === true;
  if (!tableExists) return { tableExists: false, columns: [], indexes: [], constraints: [] };

  const [columnResult, indexResult, constraintResult] = await Promise.all([
    client.query(`
      select column_name, udt_name, is_nullable, column_default
      from information_schema.columns
      where table_schema = 'public' and table_name = 'flight_booking_sessions'
    `),
    client.query(`
      select index_class.relname as indexname, pg_get_indexdef(index_class.oid) as definition
      from pg_index index_data
      join pg_class table_class on table_class.oid = index_data.indrelid
      join pg_namespace namespace on namespace.oid = table_class.relnamespace
      join pg_class index_class on index_class.oid = index_data.indexrelid
      where namespace.nspname = 'public' and table_class.relname = 'flight_booking_sessions'
        and not exists (
          select 1 from pg_constraint constraint_data
          where constraint_data.conindid = index_data.indexrelid
        )
    `),
    client.query(`
      select constraint_name as name, constraint_type as type, pg_get_constraintdef(oid) as definition
      from (
        select c.oid, c.conname as constraint_name, c.contype as constraint_type
        from pg_constraint c
        join pg_class t on t.oid = c.conrelid
        join pg_namespace n on n.oid = t.relnamespace
        where n.nspname = 'public' and t.relname = 'flight_booking_sessions'
      ) constraints
    `),
  ]);

  return {
    tableExists: true,
    columns: columnResult.rows.map((row) => ({
      name: row.column_name,
      type: row.udt_name,
      nullable: row.is_nullable === "YES",
      defaultValue: row.column_default,
    })),
    indexes: indexResult.rows.map((row) => ({ name: row.indexname, definition: row.definition })),
    constraints: constraintResult.rows,
  };
}

function validateMigrationLedger(migrations, rows) {
  const migrationByFilename = new Map(migrations.map((migration) => [migration.filename, migration]));
  const ledger = new Map();
  for (const row of rows) {
    if (ledger.has(row.filename)) throw new Error(`Duplicate migration ledger entry: ${row.filename}`);
    if (!migrationByFilename.has(row.filename)) {
      throw new Error(`Applied migration is absent from disk: ${row.filename}`);
    }
    ledger.set(row.filename, row.checksum);
  }
  for (let index = 0; index < migrations.length; index += 1) {
    const migration = migrations[index];
    const checksum = ledger.get(migration.filename);
    if (index < rows.length && checksum === undefined) {
      throw new Error(`Applied migrations do not form a contiguous prefix; missing ${migration.filename}`);
    }
    if (index >= rows.length && checksum !== undefined) {
      throw new Error(`Applied migrations do not form a contiguous prefix; unexpected ${migration.filename}`);
    }
    if (checksum !== undefined && checksum !== migration.checksum) {
      throw new Error(`Checksum mismatch for applied migration ${migration.filename}`);
    }
  }
  return ledger;
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function acquireMigrationLock(client, {
  timeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
  retryMs = DEFAULT_LOCK_RETRY_MS,
  now = Date.now,
  sleep = wait,
} = {}) {
  const startedAt = now();
  while (true) {
    const result = await client.query("select pg_try_advisory_lock($1::bigint) as locked", [MIGRATION_LOCK_ID]);
    if (result.rows[0]?.locked === true) return;
    const elapsedMs = now() - startedAt;
    if (elapsedMs >= timeoutMs) {
      throw new Error(`Timed out after ${timeoutMs}ms waiting for the migration advisory lock`);
    }
    await sleep(Math.min(retryMs, timeoutMs - elapsedMs));
  }
}

async function recordMigration(client, migration) {
  await client.query(
    "insert into schema_migrations (filename, checksum) values ($1, $2)",
    [migration.filename, migration.checksum]
  );
}

async function inTransaction(client, operation) {
  await client.query("begin");
  try {
    await operation();
    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  }
}

async function runMigrations({ client, migrations, log = console.log, lockOptions } = {}) {
  let lockHeld = false;
  try {
    await acquireMigrationLock(client, lockOptions);
    lockHeld = true;
    await client.query(`
      create table if not exists schema_migrations (
        filename text primary key,
        checksum text not null check (checksum ~ '^[0-9a-f]{64}$'),
        applied_at timestamptz not null default now()
      )
    `);
    const ledger = await client.query("select filename, checksum from schema_migrations");
    const applied = validateMigrationLedger(migrations, ledger.rows);

    for (const migration of migrations) {
      const previousChecksum = applied.get(migration.filename);
      if (previousChecksum !== undefined) {
        log(`[migrate] verified ${migration.filename}`);
        continue;
      }

      if (migration.filename === INITIAL_MIGRATION) {
        const schema = await inspectInitialMigrationSchema(client);
        const assessment = assessInitialMigrationSchema(schema);
        if (assessment.tableExists) {
          if (!assessment.canAdopt) {
            throw new Error(
              `Cannot safely adopt ${migration.filename}; existing schema is missing ${assessment.missing.join(", ")}`
            );
          }
          await inTransaction(client, () => recordMigration(client, migration));
          log(`[migrate] adopted ${migration.filename}`);
          continue;
        }
      }

      await inTransaction(client, async () => {
        await client.query(migration.sql);
        await recordMigration(client, migration);
      });
      log(`[migrate] applied ${migration.filename}`);
    }
  } finally {
    if (lockHeld) {
      await client.query("select pg_advisory_unlock($1::bigint)", [MIGRATION_LOCK_ID]);
    }
  }
}

module.exports = {
  INITIAL_BOOKING_STATUSES,
  INITIAL_COLUMN_SHAPES,
  INITIAL_COLUMNS,
  INITIAL_CONSTRAINT_NAMES,
  INITIAL_INDEXES,
  INITIAL_MIGRATION,
  assessInitialMigrationSchema,
  acquireMigrationLock,
  discoverMigrations,
  inspectInitialMigrationSchema,
  migrationChecksum,
  runMigrations,
  validateMigrationLedger,
};
