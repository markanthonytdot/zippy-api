# Partner Preview staging activation — September 9, 2026

## Current scope and source checkpoint

Use `codex/partner-preview-staging`, never `main`, for the isolated Partner Preview
backend. The Resend follow-up passes **174 tests, zero failures/skips**, including
mail mocks, PostgreSQL OTP/rate-limit/admin lifecycles, existing auth, pricing,
flight/hotel and Stripe tests. Tests use temporary schemas on isolated localhost
PostgreSQL (`127.0.0.1:55432`, data `/private/tmp/zippi-partner-pg/data`).
Automated tests never send real mail or use a hosted database.

The user superseded the Postmark/SMTP setup with Resend HTTPS. Keep Render as the
backend, database and environment-secret host; Resend only delivers transactional
email. Keep SMTP support optional and local deterministic delivery unchanged.
Do not create Postmark resources. Do not merge to main, deploy production, invite
partners, install on a device, upload to TestFlight or publish an app.

## Isolated Render resources

The staging API is live at `https://zippi-partner-staging.onrender.com`, service
`srv-dagq12ht0dsc73a7dm40`, deployed from
`93d9e4f0a6bcf96935b425b69075745c3ce3ff38`. Its separate Postgres is
`zippi-partner-staging-db`, ID `dpg-dagpide1egvs73au4k20-a`, database
`zippi_partner_staging`, PostgreSQL 18, in Virginia. Public database inbound access
is blocked; the API uses the new private connection. The free database expires
**October 9, 2026**. The
existing API uses `zippy_social_db` in Production, and the test-named hotel worker
shares that database. Neither is a staging target. Do not use any existing shared
Zippi database or change existing Render services.

Resend uses HTTPS port 443, so SMTP port 465/587 access is no longer a prerequisite.
A free web instance is suitable for initial QA with cold-start limits. Free Render
Postgres is limited to 1 GB, expires after 30 days and has no backups; it is only a
temporary QA environment. Paid always-on resources can be selected after explicit
billing approval. The previously prepared $6.30/month database was not approved
or created. Do not infer paid approval from the user's Resend steering.

Use `npm ci`, then `npm run migrate` against only the new database before
`node server.js`. On a free instance without a pre-deploy command, use
`npm run migrate && node server.js` as the start command. Existing migrations
serialize and verify checksums. Use manual deployment from the feature branch.
Auto-deploy is Off and health check is `/health/db`. All 13 migrations succeeded.
Never copy a production database connection, signing key or admin secret.

Fresh-database bootstrap exposed legacy tables (`saved_items` and
`apple_auth_tokens`) that are not created by numbered migrations. On this new
staging database only, the existing protected `POST /admin/init` was run once with
an authenticated admin session and a temporary independent `ADMIN_INIT_SECRET`.
The secret was then removed and the service redeployed. Authenticated initialization
now returns **403, Admin init disabled**. Synthetic account deletion then passed.
Do not enable this route on production or leave its temporary secret configured.

## Required staging environment

Enter secrets directly in Render environment fields. Never store them in source,
documentation, screenshots, shell history or reports.

| Variable | Configuration |
| --- | --- |
| `NODE_ENV` | `production` |
| `AUTH_MODE` | `prod` |
| `DATABASE_URL` | New staging database's private connection URL only |
| `JWT_SECRET` | New independent staging signing secret |
| `JWT_ISSUER` | `zippy-api` |
| `JWT_AUDIENCE` | `zippy-ios` |
| `ZIPPI_ADMIN_SECRET` | New independent staging operator secret |
| `ZIPPI_ADMIN_SESSION_SECRET` | New independent staging session secret |
| `ZIPPI_ADMIN_HOST` | Actual new staging API hostname |
| `ZIPPI_ADMIN_ACTOR` | Staging QA operator label |
| `ZIPPI_PARTNER_ACCESS_REQUIRED` | `true` |
| `ZIPPI_PARTNER_MAIL_ADAPTER` | `resend` |
| `RESEND_API_KEY` | Resend sending key, preferably restricted to heyzippi.com |
| `ZIPPI_PARTNER_EMAIL_FROM` | `Zippi Partner Preview <preview@heyzippi.com>` after verification |
| `FLIGHT_BOOKING_MODE` | `disabled` |
| `FLIGHT_PUBLIC_CHECKOUT_ENABLED` | `false` |
| `FLIGHT_INTERNAL_LIVE_BOOKING_ENABLED` | `false` |
| `FLIGHT_TEST_BOOKING_ENABLED` | `false` |
| `HOTEL_TEST_BOOKING_ENABLED` | `false` |

The user explicitly approved copying only `DUFFEL_LIVE_TOKEN_READONLY`,
`DUFFEL_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_PLACES_API_KEY` and
`GOOGLE_DIRECTIONS_API_KEY` into this staging service. These are configured; no
values are recorded here. Flights retain live read-only search and Hotels retain
the source service's test credential mode. No payment credentials were copied.

Preserve normal JWT issuer/audience contracts. Do not enable
checkout or provision/copy payment credentials merely to configure Partner Access.
The iOS production default URL and travel behavior remain unchanged in source;
only the eventual build-specific staging configuration changes its environment.

Legacy SMTP variables are **optional and unused with `resend`**:
`ZIPPI_PARTNER_SMTP_HOST`, `ZIPPI_PARTNER_SMTP_PORT`, `ZIPPI_PARTNER_SMTP_USER`,
`ZIPPI_PARTNER_SMTP_PASSWORD`, `ZIPPI_PARTNER_SMTP_FROM`. They are required only
when explicitly selecting `smtp`. No fallback from failed Resend to SMTP exists.
The development adapter is refused in production mode; do not use it on staging.

## Resend sender verification

The authenticated heyzippi workspace now has **heyzippi.com verified**, domain ID
`f5ba5136-e3b4-48d9-920d-e627f468b9b7`, North Virginia, sending on and receiving off.
The user completed DNS ownership approval. DKIM, SPF and sending MX are verified.
A dedicated `zippi-partner-staging` API key has Sending access restricted to
heyzippi.com and was placed directly in Render. Existing Proproval resources were
unchanged. The initial unused key was revoked before its replacement was configured.

The sending records are (TTL Auto):

| Type | Name within heyzippi.com | Content | Priority |
| --- | --- | --- | --- |
| TXT | `resend._domainkey` | Exact DKIM public key displayed by Resend | — |
| MX | `send` | `feedback-smtp.us-east-1.amazonses.com` | 10 |
| TXT | `send` | `v=spf1 include:amazonses.com ~all` | — |

DNS ownership/approval remains with the user. Do not change root MX, receiving or
existing domain records. Exactly one real OTP was sent to the user's approved QA
inbox on September 9. Resend reported Delivered, the user confirmed receipt, and
verification succeeded. The code was consumed; do not resend for this checkpoint.

## Deployment and hosted acceptance

1. Verify the exact new database identity and selected feature-branch SHA before
   migration. Configure the environment without logging secret values.
2. Confirm deployed SHA, `/health`, `/health/db` and `GET /partner-access/config`:
   HTTP 200, `ok:true`, `required:true`, `Cache-Control: no-store`.
3. Confirm `/admin/partner-access` requires the existing admin login and its API
   rejects unauthorized/cross-origin writes. Verify anonymous protected flight/
   hotel routes remain gated. Run existing non-booking flight/hotel smoke checks
   after their staging provider settings are reviewed.
4. Once Resend is verified/configured, ask only for the exact QA email the user
   personally controls. Create that invitation, then request one real OTP. Do not
   use an address merely because it was visible in a dashboard.
5. Verify the code once, status/refresh, checkout denied, feature edits, revoke,
   restore, extend and server expiry. Retain only sanitized status/expiry/feature
   evidence. Never record the code, JWT, cookie or API key. Hosted lifecycle and
   inbox delivery must be tested separately from mocked delivery.

Hosted acceptance is now complete: config 200 (`ok:true`, `required:true`,
`no-store`); health, isolated database and deployed revision pass; unauthorized
admin/status/travel/checkout return 401; an unapproved request stays generic (202)
without delivery and verification returns 401. Admin login/list and same-origin
writes succeed; cross-origin writes return 403.

The real QA OTP verified once and reuse returned 401. Active status, feature refresh,
Combined denial/re-enable, revoke, restore and extension all passed on the same
session. Checkout stays 403. A short-lived synthetic `.test` fixture proved actual
server expiry disables every feature and denies travel; extension restored that
session. The fixture was deleted successfully, leaving only the real QA person.
No email was sent to the synthetic fixture. An empty smoke-test organization remains.

Non-booking travel smoke passed: YYZ–YVR flight search returned 201 with 189 offers;
Miami hotel search returned 200 with 10 hotels and images; the three-hotel price
follow-up returned 200 with 108 rows and intact search-context continuity.
The prior `/partner-access/config` 404 is gone on this staging target. Production
was not changed and no claim is made that its older endpoint was deployed.

## First QA invitation — active and verified

Only the user-approved QA address was invited under `Zippi Internal QA`.
The one-day invitation starts September 9 at 18:16:39 UTC. The extension smoke added
one minute, so its current expiry is **September 10, 2026 at 18:17:38.915 UTC**
(2:17 PM Toronto). It is active, iOS-only, Flights/Hotels/Combined Trip on and
Checkout off. Recheck expiry before physical acceptance; extension never needs a
new app build. Do not create another invitation or send another email automatically.

In the staging admin choose an internal QA organization, then add only the approved
email. Choose **1 day**, iOS checked, Android unchecked, Flights/Hotels/Combined
Trip checked, Checkout unchecked. The form's generic default remains 7 days and
both platforms, so make these selections explicitly.

The 1-day shortcut uses existing custom `expiresAt`, based on server time or a
chosen future start. Extension adds a day from the later of server time and current
expiry. Existing 3/7/14 API presets and entitlement semantics are unchanged.

```json
{
  "platforms": ["ios"],
  "features": {
    "flights": true,
    "hotels": true,
    "combinedTrip": true,
    "checkout": false
  }
}
```

The wire key is `combinedTrip`, not `combined_trip`. The form also supplies email,
organization and calculated custom expiry. Adding a person sends no mail; code
request triggers delivery. Expiry starts at the chosen start, not verification.
Revoke applies on the next server request; native UI locks on refresh or lease
expiry (at most 60 seconds while active). Restore preserves flags and platforms;
extending alone never reverses revocation.

## iOS acceptance boundary

App Store Connect's authenticated audit confirms **1.3 (10) is used** and expired.
Build **11** remained unused in the September 9 activation recheck, with no newer
processing upload. The local candidate uses **1.3 (11)**.
Existing external groups have no current builds and review metadata needs updating.
No upload, group creation, invitation or metadata change is authorized here.

After hosted staging passes, build standard `Zippy` / `Release`, optimized arm64,
with signing. In the iOS repository, `scripts/build-partner-preview.sh archive`
sets `ZIPPI_API_BASE_URL=https://zippi-partner-staging.onrender.com/` at build time;
`ZIPPY_API_BASE_URL` in the app Info.plist expands this setting. The normal project's
default remains the production URL. The script verifies version/build, effective
staging URL and signature. Use its `debug` mode for the signed Debug validation.
Do not patch an already-signed app or change the public default URL. Inspect the
result's effective URL, version/build, entitlements and signature. Stop before
physical installation. The old development-signed Release archive points at
production and is not a staging candidate. TestFlight distribution signing/export,
review and upload are later steps requiring their stated authorization.
