# Android invitation post-send guidance — 2026-09-12

One presentation-only line in `admin/public/android-testers.js` now advises the administrator to check Spam or Promotions when the persisted Android invitation status is `sent`. It is absent for not-sent, pending and failed deliveries. It does not send mail, change tester state, modify eligibility, alter action handling or change the iOS workflow.

The focused regression exercises the shipped controller for all four delivery states and verifies no writes. Validation: 19 focused dashboard/branding tests and 358 full dashboard/iOS tests passed with no failures or skips; syntax and diff checks passed. The existing recovered-error-display correction remains intact.

The user explicitly authorized this scoped commit and deployment, alongside the separately reviewed production backend HTTPS logo/fixed branded CTA correction. After deploying the exact new dashboard SHA, verify successful refresh, sent-only guidance, unchanged Android tester state and iOS read behavior. Do not send an invitation or OTP. Record live results separately after deployment; another controlled Gmail delivery requires separate authorization.
