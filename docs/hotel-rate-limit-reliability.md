# Hotel rate-limit reliability — local implementation

Date: 2026-09-10. **Not deployed, committed, or physically accepted.**
Base: `codex/partner-preview-staging`, `9feb1c8cdd07fbf9dcb7d776a79afbf8b9e0890f`.

The confirmed Samsung failure was a Zippi daily hotel 429. One Combined execution made one discovery request; no duplicate-request fix is warranted. The previously verified deployed settings are 10/minute, 50/UTC hour and 100/UTC day. These values were not raised or changed in Render. Duffel account-specific Stays allowance is still unknown; the existing discovery credential is test-mode. This implementation improves accounting and evidence, not proof of adequate production capacity.

## A. Production scope

- `lib/hotelRateLimit.js`: safe typed 429 metadata, response serialization and provider cooldown parsing.
- `lib/hotelReadBudget.js`: separate incoming API, per-identity operation and aggregate provider counters.
- `lib/hotelDiscoveryCoalescer.js`: concurrent discovery ownership and cancellation.
- `lib/hotelReadReliability.js`: request context, transport budgeting, response sharing and cleanup.
- `lib/hotelDiscoveryPricing.js`: propagate typed rate-limit/caller-cancellation failures through the opt-in pricing handler.
- `server.js`: narrow integration with existing hotel middleware, discovery and pricing. Non-hotel rate-limit responses keep their existing shape. Commerce routes retain their legacy limiter admission; hotel 429 serialization is now structured.

No mobile code, provider request payload, pricing computation, booking/payment operation, or automatic retry was added or changed. No live provider requests were made during local validation. Commerce regression tests use forbidden real payment/database constructors and mocked service methods only.

## B–C. Structured 429 and reset semantics

Example backend daily rejection:

```json
{
  "ok": false,
  "error": "Hotel rate limit reached. Please try again later.",
  "code": "HOTEL_RATE_LIMITED",
  "rateLimit": {
    "source": "ZIPPI",
    "scope": "DISCOVERY",
    "window": "DAY",
    "limit": 100,
    "remaining": 0,
    "resetAt": "2026-09-11T00:00:00.000Z",
    "retryAfterSeconds": 43200
  }
}
```

The example assumes rejection at September 10 noon UTC. `rateLimit` is the stable nested metadata object. Scope may be `API`, `API_ROUTE`, `API_GLOBAL`, `DISCOVERY`, `PRICING`, `PROVIDER_TOTAL`, or `HOTEL_LEGACY`. Windows are `MINUTE`, `HOUR`, `DAY`; upstream unknown window is `UNKNOWN`.

Backend reset is computed from the counter itself: minute windows start with their first accepted debit and last 60 seconds; hour/day reset at UTC boundaries. If multiple provider windows are exhausted, report the latest blocking reset, avoiding a misleading shorter cooldown. Rejection commits no partial provider debit. `Retry-After` contains rounded-up delta seconds; JSON `resetAt` is ISO UTC. `RateLimit-Reset` also contains delta seconds, not an ISO string. Limit/remaining headers are included when known; the response is `Cache-Control: no-store`. Relevant headers are exposed to browser clients.

Metadata never contains identity bucket keys, IPs, device identifiers, credentials, raw provider bodies, or provider error text. Missing upstream fields are omitted, not invented.

## D–F. Accounting and abuse protection

| Action | Incoming API debit | Actual provider debit |
| --- | --- | --- |
| `/v1/hotels/search` | Every incoming call | One DISCOVERY + shared PROVIDER_TOTAL per actual Duffel search |
| Concurrent equivalent search waiter | Every incoming call | None beyond the shared search |
| `/v1/hotels/prices`, cached/local/unavailable without fetch | Every incoming call | None |
| `/v1/hotels/prices`, `fetch_all_rates` | Every incoming call | One PRICING + PROVIDER_TOTAL per actual fetch; a multi-hotel request can make multiple debits |
| `/v1/hotels/photo` | Every incoming call | No Duffel discovery/pricing debit |
| `/v1/hotels/ping` | Every incoming call | None |
| Protected commerce routes | Existing limiter admission remains | Existing commerce behavior remains outside this read adapter |

Discovery and pricing each have per-identity 10/minute, 50/hour, 100/day ceilings from the existing `HOTELS_*` configuration. A **new conservative aggregate ceiling** spans both read operations and all caller identities using the same provider credential within this process. Its default is also 10/50/100, and optional `HOTEL_PROVIDER_MINUTE`, `HOTEL_PROVIDER_HOUR`, `HOTEL_PROVIDER_DAY` can only lower the corresponding configured identity ceiling. Failed or cancelled operations already sent upstream remain charged; rejected/pre-aborted operations are not sent. No provider quota refund is assumed.

The aggregate is deliberately conservative and **tightens total capacity versus the old per-user-only limiter**. It is not a verified Duffel allowance. This must be reviewed before production deployment; these changes alone do not make 100 users/day feasible. Credentials belonging to the same upstream account may share an upstream allowance that this credential-keyed process cannot infer.

All hotel reads retain per-identity API protection at `HOTELS_RPM` (10 by default), plus existing hotel route (20/minute default) and general API (120/minute default) gates. Cheap reads no longer consume discovery hour/day capacity, but can still throttle incoming API traffic. Negative/invalid new read-budget settings cannot disable protection. Google geocoding/photo enrichment retains its existing code/cache/API protection; the new provider budget covers Duffel Stays work, not a newly invented aggregate Google quota.

## G–H. QA design/security

`HOTEL_TRAFFIC_CLASS=QA` is an optional **server-owned environment classification**, intended for a dedicated restricted QA service. It grants the same finite policy, not extra quota or a bypass. Production defaults to `CONSUMER`. No public request header/body, `bypass=true`, personal identity, or client claim selects QA. Provider aggregation does not partition by traffic class within a budget instance.

No QA environment was created and no configuration changed. Preferred rollout: separately authorized restricted staging, test credentials with verified allowance, and finite budgets. If QA and production share a provider account across processes, these local maps cannot enforce their combined total; allocate verified finite shares or implement shared counters under a separate scope before relying on that arrangement. Changing an environment flag/restarting is not a durable quota boundary.

## I–L. Coalescing and cancellation

Discovery key is a SHA-256 digest of server traffic class, access identity, provider credential identity, endpoint, method, all supplied provider headers, complete normalized provider body, and conservative response facts (`city`, `locale`, `max`, `nights`). Body includes coordinates/radius, check-in/out, guests/adults, rooms (currently one), and mobile flag. Currency is not sent by discovery; money behavior is unchanged. Request IDs are not inventory facts.

Sharing is limited to compatible requests with the **same access identity** (verified account, otherwise existing device+IP/IP policy). Separate users/private inventory cannot share accidentally. Different dates, destination, locale, radius, adults, duration, provider credentials or access context do not coalesce. Header differences also partition sharing; provider-budget identity stays credential-based independently of header differences.

One upstream operation debits once. Each caller decodes/maps the shared immutable body text independently. One caller aborting releases that waiter but leaves upstream active for others. All callers leaving aborts upstream and removes the entry. Success, HTTP error, exception and network failure settle waiters and remove the map entry; a late older completion cannot delete a newer entry for the same key. Route event listeners and transport timers are removed. Provider timeout remains 15 seconds for these backend calls; the timer now bounds body consumption as well as header wait, preventing indefinitely retained shared bodies. This is a backend transport lifetime bound, not a mobile timeout/retry change.

**No completed-result cache exists here.** A later non-concurrent search always needs a fresh provider operation. Cancellation does not erase already incurred provider cost.

## M. Upstream 429

HTTP 429 from Duffel is typed `source=PROVIDER`, with DISCOVERY or PRICING scope and UNKNOWN window. Both legacy room reads and opt-in discovery pricing propagate it instead of hiding it in generic unavailable/502 responses. Safe real Retry-After delta seconds or HTTP date are retained; valid provider reset HTTP-date metadata may also be used. Provider Date handles clock skew. No numeric reset format is guessed. Malformed, negative, overlong and secret-like fields are discarded. A body-cancellation failure cannot replace the 429 category. No raw provider response body is read into the 429 response and no retry is introduced. Other provider HTTP failures retain their previous mapping.

## N–O. Storage and future cache prerequisites

Counters and coalescing are process-local. Restart clears them; two Render replicas can each consume a full allowance, and cannot coalesce with each other. Credential rotation also changes this budget identity. This materially limits account-wide provider protection at multi-instance, multi-service or partner scale. Shared atomic counters keyed by an explicit provider account/budget and trustworthy identity will be needed before depending on an aggregate across those boundaries. Shared coordination would also be required for cross-replica coalescing. No Redis/KV/database infrastructure was added.

Before completed discovery caching: retain provider search/rate expiry through mapping; define complete provider/access identity; compose backend age with Android's existing 120-second local cache and other mobile caches; cap reuse by earliest actual inventory expiry; define invalidation for expired offers/provider refresh/access changes; preserve revalidation before any booking. TTL must be derived from those facts. No blind 120-second backend cache was added.

## P–Q. Local validation

- **56 new tests**, plus extracted shared server harness; the existing 12 route and 21 pricing tests remain covered.
- Focused hotel matrix: **89/89 passed** (limiter, coalescer, transport lifecycle, actual registered search/pricing/photo routes, discovery pricing).
- Full `npm test`: **235 total, 232 passed, 3 skipped, 0 failed**.
- Existing skips require isolated PostgreSQL: Partner Access lifecycle, reviewer lifecycle, durable tester invitations. No hotel tests skipped.
- `node --check` passed for all six production files. Backend has no configured typecheck/lint script.
- `git diff --check` passed. No dependency/package changes.
- Tests use local in-memory provider responses and the actual server's registered middleware/handlers. They do not prove Express socket/proxy behavior, live Duffel allowance, Render multi-instance enforcement or Samsung acceptance.

Added cases cover fixed-window resets, real/absent/malformed provider cooldowns, redaction, finite QA/bypass rejection, cross-user aggregate budgets, photo/local reads, both pricing paths, coalesced single debit and independent results, request/access differences, one/all callers cancelling, provider credential isolation, bounded body reads, cleanup after failure and fresh subsequent requests, and unchanged non-429 HTTP failure mapping.

## R–T. Configuration, rollout and readiness

No runtime configuration was changed. Keep `HOTELS_RPM=10`, `HOTELS_HOURLY=50`, `HOTELS_DAILY=100`. New provider ceilings default conservatively without additional configuration; optional QA classification and lower aggregate settings require deployment-owner review. Do not treat these defaults as verified upstream capacity.

**Locally ready for a separately authorized staging deployment. Not a blanket production-ready approval.** Before production: verify account-specific Duffel Stays allowance and service replica/account sharing; explicitly approve aggregate capacity; isolate this scoped change from concurrent Partner work; review the full deployment base (current branch is newer/different from the previously verified deployed backend); deploy to restricted staging, check real HTTP/CORS/cancellation/reset behavior, then authorize focused Samsung recurrence without excessive provider load. Production promotion requires separate authorization and evidence. A real backend deployment is required for mobile callers to receive the new contract; no APK install is needed for server behavior, though current clients may still present their existing generic 429 UI.

Concurrent unrelated Partner edits exist in admin assets, Partner/tester modules and tests, and two tester-invitation hunks in `server.js` (QA_GROUP import and iosQA provider wiring). They are preserved and are **not part of this hotel implementation**. No commit, push, merge, deployment, mobile installation, booking or payment occurred.
