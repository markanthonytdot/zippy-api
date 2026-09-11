# Apple invitation candidates — September 11, 2026

This supersedes the IN_BETA_TESTING-only interpretation in the earlier rollout and
live-diagnosis notes. Apple returned 409 "Testers already notified" for the single
authorized build-13 activation while its external state remained BETA_APPROVED.
No further buildBetaNotifications operation is permitted or implemented here.

## Audit and correction

The previous preflight checked the exact configured external group, app ID/bundle,
complete group-build collection, future expiry and external IN_BETA_TESTING state.
It did **not** explicitly check processing state, beta review state, platform or
external build audience. This wrongly used testing state as the entire approval
proxy and blocked the first individual invitation before Apple could decide.

Preflight now follows only builds actually associated with the configured group.
The documented build collection includes betaAppReviewSubmission, preReleaseVersion
and buildBetaDetail. Every candidate must have:

- processingState VALID;
- explicit beta review APPROVED;
- expired false and a future expirationDate;
- preReleaseVersion platform IOS and APP_STORE_ELIGIBLE build audience;
- external state BETA_APPROVED or IN_BETA_TESTING.

Unknown/missing approval, incompatible platform/audience, incomplete pagination,
wrong app/group, unassociated response IDs and expired/invalid builds fail closed.
There is no blanket BETA_APPROVED bypass and no assumption of installation on a
particular physical device; Apple's individual enrollment remains authoritative.

The existing find/create tester, exact-group membership, app-scoped tester status,
individual invitation API and notification throttle are retained. No build or
group-distribution mutation exists in the adapter. Apple NO_INSTALLABLE_BUILDS stays
a sanitized failure and prevents the welcome email. Other provider failures also
remain failures. NOT_INVITED cannot produce success or a welcome: only INVITED,
ACCEPTED or INSTALLED confirms enrollment. When automatic notification is pending,
do not send a duplicate manual invitation; expose pending and allow normal retry.

The existing support@heyzippi.com invitation must be retried by ID, preserving its
Zippi Testers organization, original permissions and September 18 expiry. Repeated
retries reuse the durable row and existing Apple tester/membership. A previously
accepted welcome is not sent again by retry.

## Validation

316 backend tests passed with isolated loopback PostgreSQL and mocked Apple/mail.
Coverage includes both candidate states, provider acceptance/refusal, all local
safety conditions, NOT_INVITED handling, authorization, OTP/reviewer controls,
organization retention and repeat retry without duplicate welcome/identity.
Live read-only preflight with the revised adapter passed for Zippi Partners/build13.
Actual live invitation outcome is recorded after the authorized dashboard retry.

Reference: [Apple List Builds supported includes and state fields](https://developer.apple.com/documentation/appstoreconnectapi/get-v1-builds).
