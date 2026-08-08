function sanitizedDeployCommit(value) {
  const candidate = String(value || "").trim();
  return /^[0-9a-f]{7,40}$/i.test(candidate) ? candidate.toLowerCase() : null;
}

function renderDeployCommit(environment = process.env) {
  return sanitizedDeployCommit(environment.RENDER_GIT_COMMIT);
}

module.exports = { renderDeployCommit, sanitizedDeployCommit };
