# Additive flight timing evidence

Local candidate on `codex/flight-map-timing-stage-base`, based on the verified
current API staging commit `b852e822259aafd7a1851c2e51d204323a8ddd9b`. It applies
the eight-file timing patch from `310d3b7`, preserving intervening staging code
and all migration files, including migration 015. The original API checkout has
unrelated uncommitted work; it was inspected but not edited or copied here.
No push, deployment, database migration or credentials change is included.

## Contract additions

`data.zippiFlightSearch.contractVersion` remains **1**. Each normalized segment
adds nullable fields; its original fields retain their previous values.

| Field | Meaning |
| --- | --- |
| `durationMinutes` | Positive whole minutes from supplier `duration`, or exact elapsed minutes from verified UTC endpoints if supplier duration is absent/invalid. Never allocated from a multi-segment slice total. |
| `departingAtUtc`, `arrivingAtUtc` | UTC instants derived from a valid explicit offset or a uniquely resolved supplied airport IANA timezone plus full local date/time. `null` means uncertainty. |
| `origin.timeZone`, `destination.timeZone` | Valid supplier `time_zone`, never inferred from city, IATA code or viewer location. |

`departingAt` and `arrivingAt` remain the original local/offset-bearing supplier
strings. Slice `durationMinutes`, total duration, fare pricing, baggage, carrier
fields, ordering/ranking and supplier-shaped `data.offers` are unchanged.

Temporal `disambiguation: 'reject'` rejects nonexistent/repeated DST clocks.
Explicit numeric offsets disambiguate repeated hours only if they agree with a
supplied zone. `Z` already denotes a UTC instant. Invalid dates, offsets/zones,
unknown `-00:00`, negative/sub-minute elapsed times and unsafe durations stay
unavailable. A valid supplier duration remains independently usable even when its
local timestamps cannot establish UTC. Resolution is cached per search request.

The API pins `@js-temporal/polyfill` **0.5.1** and its lockfile-resolved `jsbi`
dependency. No prior locked dependency versions change. This backend dependency
is not shipped to the browser. See the [Temporal timezone documentation](https://tc39.es/proposal-temporal/docs/zoneddatetime.html)
and [polyfill source](https://github.com/js-temporal/temporal-polyfill).

## Consumer behavior and evidence

- Updated Web consumes segment durations and subtracts verified UTC endpoints for
  layovers. A present-null UTC field cannot fall back to conflicting raw clocks.
- Older API contracts still work; unknown connecting durations remain unavailable.
- Older Web ignores the additions. The iOS source decodes supplier-shaped
  `data.offers` and reads only normalized customer pricing; both remain unchanged.
  No iOS device/build or Android execution is claimed.
- The captured YYZ → DCA → MIA schedule normalizes to **120m**, **46m layover**,
  **168m**, with the local 5:13pm / 10:47pm schedule preserved.
- Replaying 200 captured offers through API normalization, Web snapshot storage,
  presentation and map projection verifies all 380 outbound legs and 180 layovers.
  Removing only the additions gives an exact match to the base contract. The raw
  provider offers also remain byte-for-byte equivalent as JSON objects.
- Independent tests cover direct/overnight/cross-zone routes, multiple connections,
  missing zones, repeated and missing DST hours, Lord Howe half-hour DST,
  explicit-offset disagreement, malformed dates and fractional seconds.

Captured schedules are evidence, not live availability or bookable fare quotes.

On the original 9feb1c8-based candidate, 187 API tests passed with three opt-in
PostgreSQL suites skipped. On this current-staging-based candidate, the full suite
reports **318 passed, four failed at the missing local database prerequisite,
and four skipped** (326 total). The four failures are the unchanged
`partnerAccessAdjustment.test.js` cases requiring `PARTNER_TEST_DATABASE_URL`;
three other database suites and the optional shared-feedback-admin integration
remain skipped. Tests were not weakened to hide the missing prerequisite.

Existing PostgreSQL 17 binaries are installed, but no server responds on local
ports 5432/55432, the documented temporary fixture is absent, and no test URI is
configured. No cluster, role, credential or schema was created. Installed Node
dependencies were reused through a temporary local link after verifying the
lockfile is identical to the previously tested candidate; no new install occurred.

The 200-offer replay against this exact staging base still verifies 380 outbound
legs and 180 layovers and exact legacy-field/ranking compatibility. The replay's
Web snapshot is 493,102 bytes, below the existing 4 MiB limit. Unchanged Web
`558e850` has 265 passing tests including its local gateway-to-map seam. Its build
and validators previously passed. Native compatibility is source/contract
inspection, not an iOS/Android runtime acceptance claim. The full API release gate
is not green until the local PostgreSQL coverage can run.

## Staged rollout and recovery — review required before execution

1. Confirm the exact deployed **isolated API staging** service, release base,
   supported Node/ICU runtime and flight-search access. The current Web staging
   defaults to `https://zippy-api-6c59.onrender.com`, a shared existing API; that is
   not permission to deploy or alter production. The older Partner Preview staging
   document is historical and does not verify today's control-plane configuration.
   Read-only public checks now confirm this URL is reachable at `b852e822`, DB
   health succeeds, booking is disabled and Partner Access is required. Render
   ownership, DB binding, current deployment ID and start/build settings remain
   unverified because no permitted Render control-plane access is available.
2. Apply only this timing commit to that verified staging release lineage, resolve
   any overlap in `flightSearchContract.js` / package files, run `npm ci` and the API
   gate. Do not deploy the entire unrelated local branch history by assumption.
   This local source preparation is complete on `b852e822`; recheck for drift
   before release. There is no new migration or secret/price/provider-setting
   change. Full testing still needs the dedicated local database prerequisite.
3. With separate deployment approval, release the API additions to that isolated
   staging target first. Verify raw offers/customer pricing compatibility and fresh
   normalized timing fields. Keep the preceding API release identity for rollback.
4. Review a staging-only flight authentication/routing design before any Web
   switch. The existing global base routes hotels too; it must not be repointed
   for a narrow timing test. The current API returned anonymous flight access
   `401 partner_access_required`, and Web sends no bearer token. Existing user
   JWT auth is supported; a machine flight-read capability is not implemented.
   No gate may be disabled and no reviewer/feedback/ancillary token repurposed.
   Prepare/test the separately approved flight-only access design, then build
   and run its staging-only guard before an approved upload.
   Production routes/services must remain unchanged. Retain Web staging version
   `3ca2d5a0-003b-429b-8234-21c3fed51e5d` as the recovery version.
5. Use fresh QA sessions (existing snapshots expire after five minutes) to check
   the real timing fields, direct/connecting/overnight results, AM/PM/date labels,
   saved departure-time reset and unchanged baggage qualification/provider counts.
   Chrome remains paused; desktop/mobile sticky behavior, map interactions and
   Mapbox visual QA need an approved visual check before further release decisions.
6. If fields or interactions fail, restore the prior Web staging version, then the
   preceding API staging release if necessary. The new Web also tolerates an old
   API: elapsed values become unavailable. No database rollback is required.

No deployment step above has been executed for this combined candidate.
