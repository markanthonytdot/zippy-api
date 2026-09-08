# Hotel discovery pricing Phase 1 — local backend checkpoint

September 8, 2026. This checkpoint contains the Phase 1 backend implementation,
its tests and this contract. It has not been deployed.
Base HEAD is `9cf96fba2cad8bfa930693b5c830ce8eebaeafe1`; the local
`codex/web-hotels-cors` branch is being checkpointed to the dedicated remote
`codex/hotel-discovery-pricing` branch. The original upstream was `origin/main`;
this checkpoint does not update main or deploy the implementation.

## Read contract

`POST /v1/hotels/prices` retains its existing legacy room-read behavior. The
opt-in `discoveryPricing` object selects a separate exact-rate projection via
`lib/hotelDiscoveryPricing.js`. It requires `hotelId`, `searchResultId`, `rateId`,
`checkIn`, `checkOut`, `adults`, `rooms`, and `currency`: exact ISO dates spanning
1–30 nights, 1–9 adults and exactly one room. Invalid opt-in requests return 400
and never fall through to the legacy route.

Every assessment obtains fresh Duffel fetch-all-rates data and checks the exact
property/search-result/rate/stay/occupancy tuple. Version 1 returns
`{ok: true, discoveryPrice: ...}` with source `duffel_fetch_all_rates` and status
`authoritative`, `incomplete`, `incompatible_currency`, `refresh_needed`,
`identity_mismatch`, or `unavailable`. Only authoritative output carries a
`customerTotalMinor`. Explicit tax/mandatory-fee coverage and separately due
property charges must be known; add mandatory property charges exactly once.
Use safe integer minor units in one currency, with no guessed conversion, legacy
card-price substitution, first-rate substitution or booking quote as authority.
Both provider expiries must be valid and future; carry the earlier expiry.
The iOS consumer re-evaluates retained data against current selection and clock.

Provider 404/410/422 requires refreshed search; other provider failures produce
unavailable. Error-status preservation and opt-in wiring are the small changes
in `server.js`. No database migration, booking route, payment behavior or auth
exception is introduced. Reads remain anonymous/optional-auth with existing CORS
and abuse limits; quote/session/guest/payment/confirm/status writes and protected
reads retain their existing verified-auth rules.

## Consumer and evidence

Local iOS Combined Trip prefers strict authority but has a separately flagged
internal display-estimate path. That fallback belongs to iOS and never changes
this backend authority contract. Provider-backed Simulator display estimates are
not evidence that this undeployed route branch returned live authoritative prices.
The standalone hotel lifecycle fix changes iOS presentation ownership only.

Tests: `test/hotelDiscoveryPricing.test.js` and
`test/hotelDiscoveryRoutes.test.js` cover projection and the actual route/auth
middleware using isolated mocks. The September 7 full backend suite passed
**133 tests**, including 33 new discovery tests. September 8 hotel/discovery/
recovery/Stripe coverage passed **54 tests** with local mocks. No live booking or
payment was performed. The controlled checkpoint reran these 54 focused tests
against this exact backend tree; all passed, with no failures or skips.

The parent iOS checkout contains the full field/fee contract at
`docs/ai/hotel-discovery-pricing.md`, current platform/status docs, and the
September 8 validation/checkpoint reports under `docs/ai/validation/`.
These parent paths are outside a standalone backend checkout; the contract and
tests here travel with the backend commit itself. Publish a reviewed backend
feature-branch commit before pushing an iOS gitlink that references it.
