# Partner Access backend — September 9, 2026

The implementation and admin tooling are checkpointed together on feature branch
`codex/partner-preview-staging`, based on
`18dcdac2131e147a2f077790030ef38e1f4893b7`. The September 9 activation checkpoint
reran all 162 tests against isolated localhost PostgreSQL: zero failures/skips.
This checkpoint is not evidence of a hosted deployment or real SMTP delivery.
The authorized rollout is test/staging only; no main merge or production change.
See [staging activation and QA runbook](partner-preview-staging.md) for remaining
external prerequisites and the approved first-invite configuration. Historical
validation notes below describe their original local scope.

## Source audit and architecture

The real server uses Express 5, Helmet, PostgreSQL through `pg`/`DATABASE_URL`,
numbered checksum-verified SQL migrations, and `jose` HS256 JWTs. Apple identity
tokens are verified with Apple's JWKS and exchanged at `/auth/apple`; Google
uses its JWKS at `/auth/google`. Zippi JWTs contain `sub` and `uid`, use the
configured issuer/audience (defaults `zippy-api`/`zippy-ios`), and expire after
30 days. Verified middleware distinguishes authentication from the anonymous
`x-user-id` telemetry hint. No general users table, verified email-to-account
index, or transactional email delivery integration was found. Existing bookings,
saved items, pricing and audit storage already use PostgreSQL; no Supabase or
new database vendor is needed.

The existing `/admin` surface authenticates a dedicated operator access key and
issues an 8-hour HMAC-signed `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped
to `/admin`. Existing secret environment variables and operator identity are
reused. Partner writes additionally require exact same-origin JSON requests.
No app JWT, `x-user-id`, or knowledge of a person's email grants admin access.

One `createPartnerAccessService` serves both platforms. New focused files own
the model/lifecycle, transport/routes and mail adapter; server integration only
retains verified JWT claims, registers endpoints and applies request-time gates.
Existing Apple/Google signing and normal verified account behavior stay intact.

## Persistence and lifecycle

Migration `013_partner_access.sql` adds:

| Table | Contents |
| --- | --- |
| `partner_organizations` | Name, active/disabled status, optional domain restrictions, timestamps |
| `partner_people` | Unique normalized email, organization, active/disabled status, server start/expiry, revocation, platform/features JSON, activation/check/active timestamps |
| `partner_verifications` | Challenge UUID, keyed code digest, platform, expiry, attempts, consumption and request timestamp |
| `partner_access_audit` | Operational event, person/organization reference, operator, bounded metadata; no searches/conversations |
| `partner_access_rate_limits` | HMAC email/IP/device bucket identifiers, atomic count and expiry |

An exact invitation authorizes verification. Organization domains only restrict
those invitations; matching a domain never auto-enrolls an address. Email is
trimmed/lowercased, ASCII validated, and never modified by removing plus tags or
dots. Duplicate normalized invitations return 409 rather than silently changing
an existing entitlement.

Features are extensible boolean JSON keys. Initial keys are `flights`, `hotels`,
`combinedTrip`, `checkout`; checkout defaults false. Platforms are an array drawn
from `ios`, `android`. Disabling the organization or person, revoking access,
removing a platform, or reaching expiry denies access on the next server request.
Server process time is authoritative; no client date is accepted for validation.

An expired entitlement can be extended without another OTP while the existing
30-day JWT remains valid. Extension never silently reverses explicit revocation;
an operator must use `update` with `status: "active"` to restore revoked access.
Expired events are recorded once when expiry is observed, and rearmed after an
extension. The existing session lifetime still requires verification after JWT
expiry; this is separate from entitlement expiry. No background expiry worker
or active-session JWT claims can override the database decision.

## Verification security and email

Codes contain six digits from `crypto.randomInt`, expire in 10 minutes, allow
five attempts, and are consumed once. Stored digests use HMAC-SHA256 with the
existing server JWT secret and a versioned challenge UUID context. Comparison
uses `timingSafeEqual`. Neither API response, database nor logs stores a raw OTP.
The only cleartext copy is mail delivery (including the explicitly local simulated
recipient mailbox). Resends wait 60 seconds and invalidate previous challenges.
PostgreSQL advisory/row locks serialize concurrent requests and consumption.

Persistent atomic limits apply even to unapproved addresses: requests allow five
per email/hour, 20 per IP/10 minutes, 10 per supplied device/10 minutes; verification
allows 20 per email/hour, 60 per IP/10 minutes, 30 per supplied device/10 minutes.
Rate identifiers are keyed hashes, never raw email/IP/device IDs. IP follows
the deployment's existing Express proxy configuration. These limits complement
the existing global route rate limits. Expired rate identifiers and verification
rows are pruned opportunistically after their retention window. There is no
travel data in partner audit metadata. Account deletion removes the partner
email and verification records, anonymizes person references in audit records,
and makes retained partner JWTs unavailable, including expired/revoked users.

No transactional email provider existed. The implementation adds the small
provider-neutral Nodemailer SMTP transport; it does not choose a vendor or create
an account. `ZIPPI_PARTNER_MAIL_ADAPTER=smtp` requires:

- `ZIPPI_PARTNER_SMTP_HOST`
- `ZIPPI_PARTNER_SMTP_PORT` (`465` implicit TLS, or `587` required STARTTLS)
- `ZIPPI_PARTNER_SMTP_USER`
- `ZIPPI_PARTNER_SMTP_PASSWORD`
- `ZIPPI_PARTNER_SMTP_FROM` (an approved sender at the selected mail service)

Certificate verification, TLS 1.2+, delivery timeouts and disabled transport
debug/file/URL access are enforced. Transport is tested with an injected fake;
no real email was sent. Missing configuration fails closed with 503 for every
request, independently of invitation membership. Individual delivery failures
retain the generic request response, invalidate that challenge and record a
sanitized operational failure event. Unapproved addresses never reach delivery.

The remaining external email blocker is a usable authenticated SMTP service and
approved sender. Database migration and deployment still require the user's
separate authorization; no production configuration has been inspected or changed.

## Shared native API

All dates are ISO-8601 UTC strings. All partner responses are `Cache-Control: no-store`.

| Endpoint | Request | Response |
| --- | --- | --- |
| `GET /partner-access/config` | Public | `{ok:true,required:false}` by default |
| `POST /partner-access/request-code` | `{email,platform,deviceId?,appVersion?}` | Generic 202 with `ok`, message, `resendAfterSeconds:60`, `codeExpiresInSeconds:600` |
| `POST /partner-access/verify-code` | Same fields plus `code` | `{ok:true,token,user:{sub,authMethod:"partner_preview"},partnerAccess:<status>}` |
| `GET /partner-access/status` | Existing `Authorization: Bearer …` | Direct status object below |

```json
{
  "ok": true,
  "access": "active",
  "organization": "Porter Preview Fixture",
  "startsAt": "2026-09-10T00:00:00.000Z",
  "expiresAt": "2026-09-17T00:00:00.000Z",
  "serverTime": "2026-09-10T12:00:00.000Z",
  "refreshAfterSeconds": 60,
  "platforms": ["ios", "android"],
  "features": {"flights":true,"hotels":true,"combinedTrip":true,"checkout":false}
}
```

Access values: `active`, `scheduled`, `expired`, `revoked`, `unavailable`; a normal
verified account returns `none`. Unavailable fields are null/empty and all initial
features are false. Invalid, expired, consumed and attempt-exhausted OTPs share
`401 {ok:false,error:"invalid_code"}`. Invalid email/platform return 400. Rate
limits return 429 `rate_limited` with `Retry-After:60`. Consumer apps map errors
to safe copy and do not present these internal codes.

Partner JWT identity is `partner:<person UUID>` with claims
`auth_method:partner_preview`, `partner_invite_id`, and the verified request's
`platform`, signed by the existing issuer/audience/key. Features and entitlement
expiry are deliberately absent from JWT authorization. Both platforms' OTP flows
produce that same person subject and database entitlement; their session platform
claim differs. Platform is a client-declared, signed session context, not device
attestation. Header changes cannot alter a token's platform authority.

Native clients should retain valid partner JWTs in their existing secure stores,
refresh on foreground and at most 60-second intervals while active, use monotonic
lease timing, and lock when status cannot be refreshed after the lease. No durable
offline entitlement unlock is provided. Existing normal sessions remain a separate
route; no Apple/Google account is auto-linked by matching an email. Future linking
requires both existing-account authentication and email proof, with explicit consent.

`ZIPPI_PARTNER_ACCESS_REQUIRED=true` additionally requires verified authentication
for public travel/AI requests. Normal verified Apple/Google accounts remain valid;
partners additionally need active feature permission. Optional mode leaves public
normal routes available. Partner tokens are always checked, including public
travel reads and all booking/payment aliases. Generic hotel image bytes remain
public so native image loaders work. Invalid partner-token hints can only deny
access; they cannot establish identity. Expired/revoked status and account deletion
remain reachable for recovery and privacy.

Combined Trip orchestrates existing separate flight/hotel endpoints, so clients
gate admission and mark combined work `x-zippi-feature: combinedTrip`; the server
checks that flag in addition to the requested child domain. The server cannot
infer whether an arbitrary caller independently combines two permitted standalone
searches. Entitlements never enable an otherwise-disabled checkout/provider safety
flag, and no travel search/ranking/provider implementation was changed.

## Admin operations

`/admin/partner-access` reuses the existing protected admin surface. Partner page
assets require admin authentication. No travel searches or conversation data is
queried by its API.

- `GET /admin/api/partner-access`: organizations and at most the latest 1000
  people, including server-derived access, activation, expiry and last activity.
- `POST …/organizations`: `{name,allowedEmailDomains?}`.
- `POST …/people`: `{email,organizationId,durationDays:3|7|14}` or custom
  `expiresAt`, optional `startsAt`, `platforms`, `features`.
- `POST …/people/:id/extend`: duration or later custom expiry. Duration extends
  from the later of current expiry and now.
- `POST …/people/:id/revoke`: immediately revoke and consume pending codes.
- `POST …/people/:id/update`: optional `features`, `platforms`, `status`.

Every write requires the existing admin cookie, JSON content type and an exact
same-origin `Origin` header. No new admin secret or public write route exists.

## Deterministic local verification

Use an isolated PostgreSQL instance, never the production `DATABASE_URL`. For this
task PostgreSQL 17 was initialized under `/private/tmp/zippi-partner-pg` listening
only on `127.0.0.1:55432`; migrations 001–013 were applied there by the existing
runner. PostgreSQL integration tests create/drop a random schema without touching
the local demo fixture.

```sh
PARTNER_TEST_DATABASE_URL=postgres://marks@127.0.0.1:55432/postgres node --test test/partnerAccess.test.js
npm test
PARTNER_DEV_DATABASE_URL=postgres://marks@127.0.0.1:55432/postgres PARTNER_DEV_ADMIN_SECRET='<local-only-key>' npm run dev:partner-access
```

The standalone local runner binds `127.0.0.1:4317`, refuses production runtime
flags and non-loopback database hosts, and creates only the `.test` fixture
`preview@porter.test`. It uses the same PostgreSQL service/routes/admin security,
with a simulated mailbox at `/__dev/mailbox?email=preview%40porter.test` and fixed
local code `314159`. These debug routes/codes do not exist in `server.js`.
No supplier, AI, payment or SMTP service is contacted; its travel endpoints are
explicitly empty local responses, not travel parity evidence. A fresh random JWT
key on restart invalidates local sessions unless a local-only
`PARTNER_DEV_JWT_SECRET` is supplied for a stable QA session.

Unit tests cover normalization, feature/platform validation, exact server-time
boundaries, digest properties, production mail guards, SMTP TLS configuration,
all checkout aliases, required/public/normal behavior, admin origin/auth and
request-time revocation. Real PostgreSQL tests cover approved/unapproved email,
wrong/expired/consumed codes, attempts, resend and races, cross-platform identity,
scheduled/expired/revoked/extended access, remote features/platforms, organization
disablement, account deletion and durable email/IP/device rate limits. Backend
SMTP transport requires real credentials only after authorized testing/deployment.

Recommended backend commit: focused service/routes/mail, migration, existing
server wiring, dependency lock and tests. Admin assets/docs can be a separate
logical review commit once all native acceptance evidence is assembled.

## Validation recorded September 9

- `PARTNER_TEST_DATABASE_URL=postgres://marks@127.0.0.1:55432/postgres node --test`:
  **162 passed, zero failed, zero skipped**, including **29 Partner Access tests**
  (10 focused unit contracts, the integration parent and 18 real-PostgreSQL cases).
- The ordinary `npm test` without a local database passed 143 tests and skipped
  only the explicitly opt-in PostgreSQL integration parent. The authoritative
  final run above includes that parent and all children.
- All 13 migrations applied successfully to the isolated local PostgreSQL 17
  database using `scripts/run_migrations.js`; no production database was accessed.
- JavaScript syntax checks and `git diff --check` passed. Existing hotel
  discovery/auth, flight pricing/booking, admin session/pricing, migration, webhook
  and CORS regressions remained green.
- `npm audit --omit=dev` reports no Nodemailer advisory and one pre-existing
  moderate transitive `qs` advisory; that dependency/version was not changed.
  No unrelated dependency upgrade was made.

Backend-owned changed files: `server.js`, `lib/adminDashboard.js`,
`lib/partnerAccess.js`, `lib/partnerAccessRoutes.js`, `lib/partnerAccessMail.js`,
`migrations/013_partner_access.sql`, `scripts/run_partner_access_dev.js`,
`test/partnerAccess.test.js`, `package.json`, `package-lock.json`, and this document.
The parent task separately owns `admin/public/index.html` and the three
`admin/public/partner-access.{html,css,js}` files, native apps, screenshots and
the cross-platform report.
