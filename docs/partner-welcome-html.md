# Approved iOS Partner Preview welcome email

The approved HTML and plain-text fallback live in `lib/emailTemplates/partnerWelcome.html` and `.txt`. The design includes the gold bunny, charcoal background, TestFlight instructions and Zippi Technologies closing. `invitationInstructions('ios', invitedEmail)` returns both formats and an inline PNG attachment using the existing `admin/public/zippi-logo-nano.png` asset. The HTML references `cid:zippi-bunny`; Resend receives the same `content_id` with base64 content and image/png type, so rendering does not depend on dashboard image-host permissions.

The Resend adapter now forwards optional HTML and attachments alongside text. Sender identity, HTTPS endpoint, timeouts, failure sanitization and idempotency remain unchanged. OTP and Android email payloads remain text-only. Invitation orchestration, existing stored retry payloads, permissions and Apple operations are unchanged. No invitation is created by deployment.

CTA: https://apps.apple.com/app/testflight/id899247664
Sender: existing ZIPPI_PARTNER_EMAIL_FROM configuration, not a new sender.
Inline attachment API: https://resend.com/docs/dashboard/emails/embed-inline-images

Validation covers byte-for-byte match with the approved design except the invited-address substitution; logo bytes/content-ID; absence of remote assets, scripts and tracking; fallback and CTA; persisted-payload/idempotency behavior; legacy text retries; Android content; generic provider errors; existing OTP and Partner Access tests. PostgreSQL integration tests require their existing isolated database configuration and otherwise remain skipped.

Only staging is authorized for this deployment. A single standalone welcome-email test to the previously approved s.mark@mac.com is authorized after deployment; it must bypass invitation/enrollment operations and must not modify any person or Apple/TestFlight records.

## Approved invited-address personalization

Step 4 uses the normalized email from the stored invitation's joined `partner_people.email` row. The renderer uses the existing normalization contract, escapes HTML and preserves the same address in plain text. Replacement callbacks preserve literal `$` sequences in valid addresses. No other recipient data is interpolated.

New messages and explicit resends get the personalized copy. Existing uncertain delivery retries retain their original persisted payload and idempotency key, including legacy messages; they are not rewritten. Invitation orchestration, authorization, sender configuration, Apple/TestFlight and mobile code are unchanged. The verification-email redesign remains separate and is not included.

The focused suite verifies stored person, delivery recipient and rendered address equality, normalization, escaping, unchanged design, legacy retries and resend behavior, with only mocked external delivery. Deployment is limited to `zippi-partner-staging`. One direct welcome-only test to an existing authorized internal identity is approved after deployment; it must not create an invitation or change any person or Apple records.
