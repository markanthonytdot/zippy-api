// Persist only fixed endpoint labels/status categories. Never store payloads,
// URLs with email queries, headers, JWTs or provider-supplied error prose.
const ENDPOINTS = new Set(['group', 'group_app', 'group_builds', 'builds', 'tester_lookup',
  'tester_status', 'tester_create', 'tester_groups', 'tester_group_assignment', 'tester_invitation']);
const CATEGORIES = new Set(['response', 'transport', 'invalid_response']);
const CODES = new Set(['STATE_ERROR.TESTER_INVITE.NO_INSTALLABLE_BUILDS', 'FORBIDDEN_ERROR',
  'NOT_AUTHORIZED', 'RATE_LIMIT_EXCEEDED']);
function safeAppleMetadata(entries) {
  const clean = (Array.isArray(entries) ? entries : []).flatMap(item => {
    if (!ENDPOINTS.has(item?.endpoint) || !['GET', 'POST'].includes(item.method) || !CATEGORIES.has(item.category)) return [];
    return [{ endpoint: item.endpoint, method: item.method,
      httpStatus: Number.isInteger(item.httpStatus) && item.httpStatus >= 100 && item.httpStatus <= 599 ? item.httpStatus : null,
      category: item.category, at: Number.isFinite(Date.parse(item.at)) ? new Date(item.at).toISOString() : null,
      ...(CODES.has(item.appleCode) ? { appleCode: item.appleCode } : {}) }];
  });
  // Retain write outcomes even after many later polling responses.
  const writes = new Set(clean.filter(item => item.method === 'POST').slice(-8));
  const reads = new Set(clean.filter(item => item.method === 'GET').slice(-32));
  return clean.filter(item => writes.has(item) || reads.has(item));
}
module.exports = { safeAppleMetadata };
