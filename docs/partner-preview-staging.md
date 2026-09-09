# Partner Preview staging activation — September 9, 2026

## Verified checkpoint and environment boundaries

The backend and existing protected admin are one coupled checkpoint on
`codex/partner-preview-staging`. `node --test` with an isolated PostgreSQL database
passed 162 tests, zero failures/skips. Tests create and remove random schemas on
`127.0.0.1:55432`; the verified data directory is
`/private/tmp/zippi-partner-pg/data`. No hosted database was used.

The iOS Debug, InternalLive and Release configurations currently read
`ZIPPY_API_BASE_URL` from the shared `Zippy-Info.plist`:
`https://zippy-api-6c59.onrender.com/`. This is the existing production target,
not an approved staging target. The last read-only Partner Access configuration
probe returned HTTP 404. A localhost development runner is available, but it
does not qualify as hosted SMTP or provider acceptance.

The repository runs Express/PostgreSQL using `npm start`, installs from
`package-lock.json` using `npm ci`, and applies numbered, checksum-verified
migrations with `npm run migrate`. Migration 013 contains Partner Access tables.
Render hosts the configured endpoint. The actual service branch, deployment
commands, environment groups, hosted database and SMTP values require access to
the Render account; no local Render credentials or CLI are available. GitHub
lists no Actions workflows, environments, repository secret names or deployment
records for this repository. These facts do not prove staging does not exist.

Render and App Store Connect opened at sign-in screens. No production deployment,
database migration, environment change, real invitation, email, physical install,
TestFlight upload or App Store publication is part of this checkpoint.

## Resume the authorized staging rollout

1. Inspect the authenticated Render account for an existing test web service and
   separate test PostgreSQL database. Record their non-secret IDs, URLs, linked
   branch and deployment commands. Verify database identity before migrations.
   If there is no suitable test service, report that before any production change;
   the current authorization does not permit a production fallback.
2. Use the validated feature branch. Preserve the service's existing provider,
   search and pricing settings; do not copy production credentials or databases
   blindly. Keep checkout/provider execution in test-safe configuration.
3. Configure the existing staging secret store. Required Partner Access dependencies
   are `DATABASE_URL`, a staging `JWT_SECRET`, and existing admin authentication
   through `ZIPPI_ADMIN_SECRET` / `ZIPPI_ADMIN_SESSION_SECRET`. Preserve configured
   JWT issuer/audience. Use `ZIPPI_PARTNER_ACCESS_REQUIRED=true` for the intended
   first-launch preview gate; existing verified normal accounts remain a separate
   supported path. Admin host routing must match the staging service's hostname.
4. Install dependencies and run `npm run migrate` against the verified staging
   database before starting the new server. Use the existing service's deployment
   mechanism, then confirm the deployed commit and `GET /partner-access/config`
   returns HTTP 200 with `ok:true, required:true` and no-store caching.
5. Verify protected admin authentication and read-only flight/hotel smoke routes.
   Run the real-code lifecycle only with the separately approved QA recipient.
   Local integration evidence covers request-code, verification, lease refresh,
   expiry, revocation, restoration and feature/platform changes; it must not be
   reported as a hosted or delivered-email pass.

## Authenticated SMTP values required

Enter these in the staging service's secret manager, never in source or chat:

| Setting | Required value |
| --- | --- |
| `ZIPPI_PARTNER_MAIL_ADAPTER` | `smtp` |
| `ZIPPI_PARTNER_SMTP_HOST` | Provider's SMTP hostname |
| `ZIPPI_PARTNER_SMTP_PORT` | `465` for implicit TLS or `587` for required STARTTLS |
| `ZIPPI_PARTNER_SMTP_USER` | Provider's SMTP username |
| `ZIPPI_PARTNER_SMTP_PASSWORD` | SMTP password or provider-issued SMTP credential |
| `ZIPPI_PARTNER_SMTP_FROM` | Provider-approved From address |

The selected provider must have an approved sender/domain and permit delivery to
the user's QA address. Complete its sender/domain verification and sandbox-recipient
approval if applicable. No usable credentials have been found locally; hosted
configuration remains unverified pending account access. Do not use the development
mail adapter on a hosted production-mode process. Missing SMTP fails closed.

## First QA invitation — prepared, not created

After the user explicitly approves one email they control, sign in to the staging
`/admin/partner-access` using existing admin authentication. Create or select an
internal QA organization. Add that exact address, select three days, and explicitly
uncheck Android (the generic form defaults both platforms on). Set:

```json
{
  "durationDays": 3,
  "platforms": ["ios"],
  "features": {
    "flights": true,
    "hotels": true,
    "combinedTrip": true,
    "checkout": false
  }
}
```

The wire key is `combinedTrip`, not `combined_trip`. The form also supplies the
approved email and chosen organization ID. Adding the invitation sends no mail;
delivery occurs only when the user requests a code. Duration starts at the selected
start time (now by default), not first verification. Do not invite partner companies.

After email acceptance, use Revoke, Restore, then Extend on this same person.
Keep the verified app account signed in. Revoke applies to server requests
immediately; native content locks on refresh or lease expiry (at most 60 seconds
while active), and foreground triggers refresh. Restore preserves platforms and
features; extending alone does not reverse revocation. Capture only HTTP statuses,
access, expiry and flags, never JWTs or OTPs.

## Physical iOS acceptance boundary

After hosted smoke passes, inspect App Store Connect read-only to verify whether
version 1.3 build 10 is unused. Do not infer availability from the Xcode project.
Build standard `Zippy` / `Release`, optimized arm64, with normal device signing.
Supply a build-specific Info.plist containing the verified staging URL via
`INFOPLIST_FILE`; do not patch an already-signed app or change the public default
URL. Inspect the built app's effective URL, bundle/version/build, entitlements and
signature before the authorized iPhone 15 Pro install.

The previously validated Release archive still contains the production URL and
must not be installed for this staging task. No new physical install can proceed
until the staging URL, backend smoke and build-number check are resolved. After
installation, stop for the user's real-email acceptance. A future App Store Connect
distribution archive/export and external TestFlight review remain separate from
this development-signed physical acceptance; no upload is authorized.
