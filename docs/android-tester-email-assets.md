# Android invitation assets and branded opt-in — 2026-09-12

## Scope and observed delivery

The first controlled Android invitation was accepted and delivered by Resend/Gmail, but the recipient observed Spam placement, a broken header logo and a separate `zippi-bunny.png` attachment. Resend Insights identifies the direct Google Play link as a sending-domain mismatch. No additional email/OTP, tester update, DNS change, deployment or Play action was performed during this work.

## Asset trace and diagnosis limits

`androidTesterEmail` reused `verificationLayout`, whose header contains `src="cid:zippi-bunny"`, width 128, height 96 and alt text `Zippi`. `inlineLogo()` reads the existing 512 × 382 PNG and provides a base64 attachment named `zippi-bunny.png`, type `image/png`, with `content_id: zippi-bunny`. The Resend adapter passes attachments unchanged to POST `/emails`.

The two CID strings match, and `content_id` is the documented raw HTTP API field. There is no proven spelling mismatch, local-path HTML reference or malformed PNG. The attachment itself is deliberately part of the outbound payload, explaining why Gmail has a downloadable bunny file. The broken header is an unresolved CID image in the delivered client. Resend exposes the HTML and attachment entry, but the stored request log omits attachment metadata and does not expose delivered MIME headers. The exact MIME/client reason for the association failure is not proven; do not invent one. See [Resend inline-image documentation](https://resend.com/docs/dashboard/emails/embed-inline-images).

The existing iOS welcome and verification templates use the same CID/attachment strategy. Their source and output remain unchanged. Prior local preview/tests are not proof that iOS CID rendering works in Gmail; the Android correction therefore uses public HTTPS instead of copying an unverified client assumption.

## Correction

- Email CTA, in both HTML and plain text: `https://admin.heyzippi.com/android-test`.
- Public GET/HEAD route returns HTTP 302 to the unchanged fixed destination `https://play.google.com/apps/internaltest/4701051442738255142`. No input, query, host, recipient identifier or configuration can select another destination. No generic redirect facility.
- Header logo: `https://admin.heyzippi.com/email-assets/zippi-logo-v1.png`.
- Public asset route serves the existing approved PNG with correct content type, cross-origin image permission and immutable public caching. It has no authentication, signed URL, cookie, download disposition or user-supplied filesystem path. Bump the asset URL version if replacing its bytes later.
- Routes are registered before authentication and API accounting. They do not query the tester database or invoke a provider.
- Android HTML keeps the existing logo size/alt text and branded layout. The welcome now has no `attachments` property, CID, data URI or base64 image. OTP/shared/iOS templates and the Resend adapter are unchanged.
- Sender remains configured as `Zippi <support@heyzippi.com>`. Android/Partner Preview steps, six-digit-code instructions and the plain-text alternative remain intact.
- Both Android dashboard copies show a small Spam/Promotions helper only when persisted delivery status is `sent`. No such instruction was added to the recipient email.

The existing Zippi-controlled `admin.heyzippi.com` domain already routes to production. Anonymous HTTPS retrieval of its existing public logo returned 200/image/png, 72,915 bytes, matching repository SHA-256 `cb7e7249290f669737f6571b58124c0fe606f27f619ff1504037193254c4c600`. No new DNS or marketing-site change is needed. The new public paths require deployment; they were tested on loopback, not claimed live.

## Deliverability review

- Resend domain `heyzippi.com`: Verified; DKIM and sending SPF/MX checks Verified.
- Public return-path subdomain `send.heyzippi.com`: SES SPF include and SES feedback MX present. Root SPF remains its existing mailbox-provider policy; it should not be replaced merely because transactional mail uses a subdomain.
- DMARC exists with `p=quarantine`, relaxed DKIM/SPF alignment. Resend rates it valid. A configured return path under `send.heyzippi.com` and signing under `heyzippi.com` fit that alignment; the exact received message's Authentication-Results/Return-Path headers were not available.
- Insights also rates plain text, body size, custom tracking-domain checks and non-no-reply sender positively. The direct Play URL is the one needs-attention item. No new Insights result can be claimed before another delivery; redirects are not a guarantee against Gmail classification.
- No authentication configuration defect was established. New-sender reputation/classification is plausible, not proven. SPF/DKIM/DMARC and Resend settings were left untouched.
- The message contains useful text, one small PNG, one intentional CTA and a matching support mailto. No malformed HTML, missing text alternative, unexpected Reply-To override or suspicious variable destination was found.

## Validation

- 33 focused backend email/public-route/transport/lifecycle tests passed.
- Full production-baseline suite: **231 passed, zero failed/skipped** using isolated local PostgreSQL schemas and mocked email/provider calls.
- 19 focused dashboard/branding tests passed; full dashboard/iOS suite: **358 passed, zero failed/skipped**.
- Actual Resend adapter request captured only against a mock: preserved From/text/instructions/idempotency; no attachments; only Zippi HTTPS image/CTA URLs in HTML.
- Anonymous loopback HTTP: fixed 302; query redirect injection ignored; HEAD correct; POST/extra paths not admitted; image bytes/content type/cache/cross-origin headers correct; no cookie or attachment header.
- HTML structure balanced, exactly one image/two links, 4,340 HTML bytes and 508 plain-text bytes. No unsafe tags, inline base64, credentials or recipient data in URLs.
- Browser render: approved gold logo loaded at 128 × 96, natural 512 × 382; no horizontal overflow or broken-image indicator. Preview mapped only the fixed host to loopback so the undeployed image route could be rendered. This is not a Gmail delivery claim.
- Syntax and `git diff --check` passed. Existing retries retain their stored payload/idempotency; an explicit authorized resend after an already-sent message obtains the current template through the existing service behavior. No record migration or replay was introduced.

## Files and deployment

Production candidate: `lib/androidTesterEmail.js`, new `lib/androidTesterLinks.js`, one registration in `server.js`, one helper line in `admin/public/android-testers.js`, `test/androidTesterEmail.test.js`, `test/androidTesterService.test.js`, new `test/androidTesterLinks.test.js`, this report.

Dashboard companion (based on the accepted stale-error correction): `admin/public/android-testers.js`, `test/androidTesterRefresh.test.js` for sent-only guidance. No iOS source changes.

On 2026-09-12 the user explicitly authorized one scoped backend commit and one scoped dashboard commit, and deployment of those exact commits after confirming the staged diffs match this scope. No configuration, tester-state, mobile, Play or mail-send action is included. Deploy the backend template/public routes and dashboard guidance separately from their existing baselines; verify the running revisions, anonymous HTTPS image, fixed redirect (including hostile query parameters), generated payload, unchanged tester state and iOS dashboard reads. Record live results separately after deployment. One controlled Gmail resend requires separate authorization. Only that delivery can confirm Gmail presentation, attachment absence, inbox/spam placement and updated Resend Insights. Do not send during deployment.
