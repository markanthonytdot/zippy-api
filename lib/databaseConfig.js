function databaseSSLForURL(databaseUrl) {
  let parsed;
  try {
    parsed = new URL(databaseUrl);
  } catch {
    throw new Error("DATABASE_URL must be a valid PostgreSQL URL");
  }
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) {
    throw new Error("DATABASE_URL must use the postgres or postgresql scheme");
  }
  const localHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);
  return localHosts.has(parsed.hostname) ? false : { rejectUnauthorized: false };
}

module.exports = { databaseSSLForURL };
