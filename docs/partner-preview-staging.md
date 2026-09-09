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

Create a separate API `zippi-partner-staging` and Postgres
`zippi-partner-staging-db` / database `zippi_partner_staging`, in Virginia. The
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
Never copy a production database connection, signing key or admin secret.

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

Preserve normal JWT issuer/audience contracts. Review required provider/search
settings separately before claiming flight/hotel live acceptance. Do not enable
checkout or provision/copy payment credentials merely to configure Partner Access.
The iOS production default URL and travel behavior remain unchanged in source;
only the eventual build-specific staging configuration changes its environment.

Legacy SMTP variables are **optional and unused with `resend`**:
`ZIPPI_PARTNER_SMTP_HOST`, `ZIPPI_PARTNER_SMTP_PORT`, `ZIPPI_PARTNER_SMTP_USER`,
`ZIPPI_PARTNER_SMTP_PASSWORD`, `ZIPPI_PARTNER_SMTP_FROM`. They are required only
when explicitly selecting `smtp`. No fallback from failed Resend to SMTP exists.
The development adapter is refused in production mode; do not use it on staging.

## Resend sender verification

The authenticated heyzippi workspace initially had only `proproval.com` verified.
A `heyzippi.com` domain setup is prepared in Resend, North Virginia, sending on and
receiving off. Resend requests the following DNS records (TTL Auto):

| Type | Name within heyzippi.com | Content | Priority |
| --- | --- | --- | --- |
| TXT | `resend._domainkey` | Exact DKIM public key displayed by Resend | — |
| MX | `send` | `feedback-smtp.us-east-1.amazonses.com` | 10 |
| TXT | `send` | `v=spf1 include:amazonses.com ~all` | — |

DNS ownership/approval remains with the user. Do not change root MX, receiving or
existing domain records. Check the current provider screen before applying records;
verify status in Resend before setting the sender ready. Configuration presence or
mocked tests cannot prove delivery. Use the user's own approved QA address only.

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
   inbox delivery remain pending until actually exercised.

## First QA invitation — prepared, not created

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
Build **11** was unused at that inspection; recheck before preparing **1.3 (11)**.
Existing external groups have no current builds and review metadata needs updating.
No upload, group creation, invitation or metadata change is authorized here.

After hosted staging passes, build standard `Zippy` / `Release`, optimized arm64,
with signing and a build-specific Info.plist pointing to the verified staging URL.
Do not patch an already-signed app or change the public default URL. Inspect the
result's effective URL, version/build, entitlements and signature. Stop before
physical installation. The old development-signed Release archive points at
production and is not a staging candidate. TestFlight distribution signing/export,
review and upload are later steps requiring their stated authorization.
