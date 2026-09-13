# Adjust existing tester access

Both Android production and iOS staging administrators use Adjust access with Set-from-now and Extend. Presets are 1, 3, 7 (default), 14 and 30 days; Custom requires an integer from 1 to 90.

Set expiry = captured server now + N elapsed 24-hour days. Extend expiry = max(existing expiry, captured server now) + N days. Set can shorten access. Exact date/time selection is deferred.

The explicit adjust action requires operation set/extend, durationDays, confirm=true and expectedExpiresAt. The row lock and expected-expiry comparison reject stale writes. Audit event access_adjusted records previous/new expiry, operation, duration and captured timestamp. Existing extend clients remain compatible.

Revoked and Disabled states remain blocked after expiry adjustment. Eligible expired access can be renewed explicitly. Scheduled starts and organization blocks remain authoritative. Prepare/Invite, resend, OTP/login and Play/TestFlight operations preserve expiry. No schema/config/mobile/authority changes.

Validated locally: 264 production tests, 382 dashboard/staging tests, 42 unchanged Android auth/gate tests, 11 dashboard controller tests; browser Set/Extend/Custom/expiry refresh, syntax and diff checks pass. External delivery was mocked. All 416 accepted Android source hashes and version-11 signed artifacts remain unchanged.

Deploy backend first, verify health/auth/adjustment/stale safety, then dashboard/staging. No invitation or OTP is needed for smoke testing. Roll back affected service to its prior deployment if validation fails. Keep existing configuration and database schema unchanged.
