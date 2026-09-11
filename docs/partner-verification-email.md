# Branded Partner Preview verification email

The Resend OTP email uses the approved charcoal/gold Partner Preview layout, the
existing gold bunny as an inline CID attachment, a large six-digit code, responsive
mobile type sizing, support address and Zippi Team / Zippi Technologies closing.
The HTML matches the approved verification preview. Header/footer styles reuse the
live welcome template; the welcome template and its rendering path are unchanged.

The previous plain-text fallback and subject are preserved exactly. Lifetime copy
uses the expiry supplied by Partner Access (currently 600 seconds). Rendering does
not create, store, validate, log or change the lifetime of a code. OTP generation,
hashed storage, one-time use, attempt limits, cooldowns, generic responses and all
Partner Access rules remain in their existing implementation.

The sender, Resend configuration and transport error handling are unchanged. Tests
use only mocked HTTP delivery and deterministic fixture codes, checking escaping,
leading zeros, inline logo, content, fallback and absence of codes in errors/logs.
A hosted acceptance test uses the existing request-code endpoint for the approved
internal identity, never the TestFlight invitation workflow. Provider confirmation
must use email delivery metadata only; do not display or record the real code.
