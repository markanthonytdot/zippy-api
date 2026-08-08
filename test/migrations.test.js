const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  INITIAL_BOOKING_STATUSES,
  INITIAL_COLUMN_SHAPES,
  INITIAL_COLUMNS,
  INITIAL_CONSTRAINT_NAMES,
  INITIAL_INDEXES,
  INITIAL_MIGRATION,
  assessInitialMigrationSchema,
  acquireMigrationLock,
  discoverMigrations,
  migrationChecksum,
  runMigrations,
  validateMigrationLedger,
} = require("../lib/migrations");

function completeInitialSchema(overrides = {}) {
  return {
    tableExists: true,
    columns: INITIAL_COLUMNS.map((name) => ({
      name,
      type: INITIAL_COLUMN_SHAPES[name][0],
      nullable: INITIAL_COLUMN_SHAPES[name][1],
      defaultValue: INITIAL_COLUMN_SHAPES[name][2],
    })),
    indexes: Object.entries(INITIAL_INDEXES).map(([name, definition]) => ({ name, definition })),
    constraints: [
      { name: INITIAL_CONSTRAINT_NAMES[0], type: "p", definition: "PRIMARY KEY (id)" },
      { name: INITIAL_CONSTRAINT_NAMES[1], type: "u", definition: "UNIQUE (stripe_payment_intent_id)" },
      { name: INITIAL_CONSTRAINT_NAMES[2], type: "u", definition: "UNIQUE (duffel_order_id)" },
      {
        name: INITIAL_CONSTRAINT_NAMES[3],
        type: "c",
        definition: `CHECK ((booking_status = ANY (ARRAY[${INITIAL_BOOKING_STATUSES.map((status) => `'${status}'::text`).join(", ")}])) )`,
      },
    ],
    ...overrides,
  };
}

test("discovers migrations in numeric order and hashes exact file contents", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zippi-migrations-"));
  try {
    fs.writeFileSync(path.join(directory, "003_third.sql"), "select 3;\n");
    fs.writeFileSync(path.join(directory, "001_first.sql"), "select 1;\n");
    fs.writeFileSync(path.join(directory, "002_second.sql"), "select 2;\n");
    const migrations = discoverMigrations(directory);
    assert.deepEqual(migrations.map(({ filename }) => filename), [
      "001_first.sql", "002_second.sql", "003_third.sql",
    ]);
    assert.equal(migrations[0].checksum, migrationChecksum(Buffer.from("select 1;\n")));
    assert.equal(migrations[0].checksum.length, 64);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects invalid filenames and duplicate migration versions", () => {
  const invalidDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "zippi-invalid-migration-"));
  const duplicateDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "zippi-duplicate-migration-"));
  try {
    fs.writeFileSync(path.join(invalidDirectory, "migration.sql"), "select 1;");
    assert.throws(() => discoverMigrations(invalidDirectory), /Invalid migration filename/);
    fs.writeFileSync(path.join(duplicateDirectory, "001_first.sql"), "select 1;");
    fs.writeFileSync(path.join(duplicateDirectory, "001_again.sql"), "select 2;");
    assert.throws(() => discoverMigrations(duplicateDirectory), /Duplicate migration version/);
  } finally {
    fs.rmSync(invalidDirectory, { recursive: true, force: true });
    fs.rmSync(duplicateDirectory, { recursive: true, force: true });
  }
});

test("rejects gaps in migration files", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zippi-gapped-migration-"));
  try {
    fs.writeFileSync(path.join(directory, "001_first.sql"), "select 1;");
    fs.writeFileSync(path.join(directory, "003_third.sql"), "select 3;");
    assert.throws(() => discoverMigrations(directory), /contiguous sequence/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("adopts only a complete pre-existing migration 001 schema", () => {
  assert.deepEqual(assessInitialMigrationSchema({ tableExists: false }), {
    canAdopt: false, tableExists: false, missing: [],
  });
  assert.equal(assessInitialMigrationSchema(completeInitialSchema()).canAdopt, true);
  const incomplete = assessInitialMigrationSchema(completeInitialSchema({
    columns: completeInitialSchema().columns.filter((column) => column.name !== "booking_status"),
  }));
  assert.equal(incomplete.canAdopt, false);
  assert.ok(incomplete.missing.includes("column:booking_status"));

  const wrongDefaultColumns = completeInitialSchema().columns.map((column) => (
    column.name === "booking_status" ? { ...column, defaultValue: "'confirmed'::text" } : column
  ));
  assert.ok(assessInitialMigrationSchema(completeInitialSchema({ columns: wrongDefaultColumns }))
    .missing.includes("column_shape:booking_status"));

  const wrongIndexes = completeInitialSchema().indexes.map((index) => (
    index.name === "idx_flight_booking_sessions_status"
      ? { ...index, definition: index.definition.replace("updated_at", "created_at") }
      : index
  ));
  assert.ok(assessInitialMigrationSchema(completeInitialSchema({ indexes: wrongIndexes }))
    .missing.includes("index:idx_flight_booking_sessions_status"));

  const alternateConstraint = {
    name: "legacy_booking_status_check",
    type: "c",
    definition: "CHECK (booking_status <> 'invalid')",
  };
  assert.ok(assessInitialMigrationSchema(completeInitialSchema({
    constraints: [...completeInitialSchema().constraints, alternateConstraint],
  })).missing.includes("unexpected_constraint:legacy_booking_status_check"));

  const permissiveNamedConstraint = completeInitialSchema().constraints.map((constraint) => (
    constraint.name === INITIAL_CONSTRAINT_NAMES[3]
      ? { ...constraint, definition: "CHECK ((booking_status IS NOT NULL))" }
      : constraint
  ));
  assert.ok(assessInitialMigrationSchema(completeInitialSchema({ constraints: permissiveNamedConstraint }))
    .missing.includes("constraint:booking_status_check"));
});

test("PostgreSQL 18 named NOT NULL catalog constraints do not block safe adoption", () => {
  const postgres18Constraints = [
    ...completeInitialSchema().constraints,
    { name: "flight_booking_sessions_id_not_null", type: "n", definition: "NOT NULL id" },
    { name: "flight_booking_sessions_user_id_not_null", type: "n", definition: "NOT NULL user_id" },
    { name: "flight_booking_sessions_booking_status_not_null", type: "n", definition: "NOT NULL booking_status" },
  ];
  const assessment = assessInitialMigrationSchema(completeInitialSchema({
    constraints: postgres18Constraints,
  }));
  assert.equal(assessment.canAdopt, true);
  assert.deepEqual(assessment.missing, []);

  const unexpectedForeignKey = {
    name: "flight_booking_sessions_unexpected_fkey",
    type: "f",
    definition: "FOREIGN KEY (user_id) REFERENCES users(id)",
  };
  const unsafe = assessInitialMigrationSchema(completeInitialSchema({
    constraints: [...postgres18Constraints, unexpectedForeignKey],
  }));
  assert.equal(unsafe.canAdopt, false);
  assert.ok(unsafe.missing.includes("unexpected_constraint:flight_booking_sessions_unexpected_fkey"));
});

test("requires the migration ledger to be an exact contiguous prefix", () => {
  const migrations = [1, 2, 3].map((version) => ({
    filename: `00${version}_migration.sql`, checksum: String(version).repeat(64), sql: `select ${version}`,
  }));
  assert.equal(validateMigrationLedger(migrations, migrations.slice(0, 2)).size, 2);
  assert.throws(
    () => validateMigrationLedger(migrations, [{ filename: "000_removed.sql", checksum: "0".repeat(64) }]),
    /absent from disk/
  );
  assert.throws(
    () => validateMigrationLedger(migrations, [migrations[0], migrations[2]]),
    /contiguous prefix/
  );
});

test("migration advisory lock has a bounded retry deadline", async () => {
  let clock = 0;
  let attempts = 0;
  const client = {
    async query() {
      attempts += 1;
      return { rows: [{ locked: false }] };
    },
  };
  await assert.rejects(
    acquireMigrationLock(client, {
      timeoutMs: 500,
      retryMs: 250,
      now: () => clock,
      sleep: async (milliseconds) => { clock += milliseconds; },
    }),
    /Timed out after 500ms/
  );
  assert.equal(attempts, 3);
});

test("fails closed when an applied migration checksum has changed", async () => {
  const queries = [];
  const client = {
    async query(sql) {
      queries.push(sql);
      if (String(sql).includes("pg_try_advisory_lock")) return { rows: [{ locked: true }] };
      if (String(sql).includes("select filename, checksum")) {
        return { rows: [{ filename: "002_example.sql", checksum: "different" }] };
      }
      return { rows: [] };
    },
  };
  await assert.rejects(
    runMigrations({
      client,
      migrations: [{ filename: "002_example.sql", checksum: "expected", sql: "select 2" }],
      log() {},
    }),
    /Checksum mismatch/
  );
  assert.ok(queries.some((sql) => String(sql).includes("pg_advisory_unlock")));
});

test("records a verified pre-existing migration 001 without executing its SQL", async () => {
  const calls = [];
  const client = {
    async query(sql, params) {
      const text = String(sql);
      calls.push({ text, params });
      if (text.includes("pg_try_advisory_lock")) return { rows: [{ locked: true }] };
      if (text.includes("select filename, checksum")) return { rows: [] };
      if (text.includes("to_regclass")) return { rows: [{ table_exists: true }] };
      if (text.includes("information_schema.columns")) {
        return { rows: INITIAL_COLUMNS.map((column_name) => ({
          column_name,
          udt_name: INITIAL_COLUMN_SHAPES[column_name][0],
          is_nullable: INITIAL_COLUMN_SHAPES[column_name][1] ? "YES" : "NO",
          column_default: INITIAL_COLUMN_SHAPES[column_name][2],
        })) };
      }
      if (text.includes("from pg_index")) {
        return { rows: Object.entries(INITIAL_INDEXES).map(([indexname, definition]) => ({ indexname, definition })) };
      }
      if (text.includes("from pg_constraint")) return { rows: completeInitialSchema().constraints };
      return { rows: [] };
    },
  };
  const sql = "select 'must not run'";
  await runMigrations({
    client,
    migrations: [{ filename: INITIAL_MIGRATION, checksum: "a".repeat(64), sql }],
    log() {},
  });
  assert.equal(calls.some((call) => call.text === sql), false);
  assert.ok(calls.some((call) => call.text.includes("insert into schema_migrations")));
  assert.ok(calls.some((call) => call.text === "begin"));
  assert.ok(calls.some((call) => call.text === "commit"));
});
