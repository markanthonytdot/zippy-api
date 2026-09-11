# Live invitation diagnosis — September 11, 2026

## Observed before any retry

Staging `/version` reported `0f9cfbba81a417e10693bcfae88664ac19097451`, a hotel
reliability commit whose parent was `9feb1c8`. It omitted accepted invitation commit
`623d6bd` despite that commit remaining the remote staging branch head. The live
page consequently lacked organization selection and showed the old Add Person UI.
The integrated repair retains both accepted histories and preserves the hotel code.

Render's configured primary group is **Zippi Partners**,
`b13afcde-cbb2-44cf-9518-5d6ce9724731`; its configured name also matches. Live Apple
HTTP 200 reads confirm it is external and still contains build **1.3.1 (13)**,
`2c26fddd-3e48-431f-8ece-7f9e6eec3017`. That build is processed (`VALID`), beta review
`APPROVED`, unexpired until December 9, 2026, but external state **BETA_APPROVED**,
not **IN_BETA_TESTING**. Automatic notifications are off. No missing association,
pagination or expiry error was found.

The exact adapter collection lookup returned the build and its beta detail. Its
external-state equality check rejects BETA_APPROVED, leaving no eligible builds.
This is a current live-state change from the earlier rollout observation; no audit
trail establishes which intervening Apple action caused it. Do not loosen this
check merely to conceal a distribution/activation blocker.

Build 13's only associated groups are Zippi Partners and Zippi Dashboard QA
(`39a3f713-9168-4e9a-abc4-2d97f7cf7cdb`). Both currently have zero testers; the build
has zero individual testers. Complete non-paginated reads confirmed all counts.
QA also has build 12, now BETA_APPROVED; neither group currently passes eligibility.
No membership or build assignment was modified during diagnosis.

The existing `support@heyzippi.com` person is
`52b38a5f-9082-4455-b285-1c74ce7ed89b`, organization **Zippi Testers**, iOS,
Flights/Hotels/Combined Trip enabled and Checkout disabled. Access remains valid
through September 18, 2026, 7:45 AM Toronto time. The invitation remains failed
(`apple_no_testable_build`) and its welcome email has not been sent. No retry,
resend, duplicate identity or entitlement change was performed during diagnosis.

## Activation boundary

Apple's documented buildBetaNotifications operation targets all testers assigned
to a build. The current build-13 audience is zero, but automatic approval review
rejected invoking that endpoint without explicit authorization. Do not work around
this rejection with a UI action or another transport. Ask for approval of the exact
build-13 activation operation; revalidate every group and individual assignment
immediately beforehand and stop if any unexpected recipient appears.

After authorized activation, first confirm live IN_BETA_TESTING and adapter
eligibility. Only then use the existing support invitation's Retry action, preserving
its identity, organization, expiry and permissions. Check Apple membership/status,
welcome delivery and duplicate counts. No public App Store action or new binary is
needed. Leave builds 11/12, QA membership, unrelated testers and production alone.

## Repair validation

Integrated backend suite: **299 passed, zero failures/skips** with isolated loopback
PostgreSQL and mocked external services. The runtime change relative to the live
hotel deployment restores only the previously accepted invitation changes; it
preserves the existing hotel reliability implementation. No installability filter
was weakened. Syntax and git diff checks pass. Deployment outcome is recorded in
the task report.

[Apple's build-wide notification scope](https://developer.apple.com/documentation/appstoreconnectapi/build-beta-notifications)
