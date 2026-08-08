const test = require("node:test");
const assert = require("node:assert/strict");
const { renderDeployCommit, sanitizedDeployCommit } = require("../lib/deployRevision");

test("exposes only a sanitized Render commit", () => {
  assert.equal(sanitizedDeployCommit("ABCDEF1234567"), "abcdef1234567");
  assert.equal(sanitizedDeployCommit("not-a-commit"), null);
  assert.equal(sanitizedDeployCommit("abc123; secret=value"), null);
  assert.equal(renderDeployCommit({ RENDER_GIT_COMMIT: "0123456789abcdef0123456789abcdef01234567" }),
    "0123456789abcdef0123456789abcdef01234567");
  assert.equal(renderDeployCommit({ OTHER_REVISION: "abcdef123456" }), null);
});
