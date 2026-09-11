# Guest speech sessions

`POST /v1/speech/session` accepts an empty JSON object and the existing installation `x-user-id` hint. No account login is required. It returns only a short-lived Deepgram Bearer credential and remaining lifetime with `Cache-Control: no-store`. The server-only Member key is read exclusively from `DEEPGRAM_SERVER_API_KEY`; there is no fallback to a mobile key and no management endpoint exposed.

Independent finite limits per process: installation 6/minute and 60/hour; IP 30/minute and 300/hour; aggregate 120/minute and 2,000/day; eight simultaneous upstream grants. Caller identifiers are hints, not trusted authentication. Device rotation does not evade the independent IP/global caps. Counter identities are salted hashes, storage is bounded, and saturation fails closed. No QA bypass. Multi-replica operation would multiply these process-local caps and requires shared accounting before scale-up.

The upstream request has an eight-second deadline including body reading, a 16 KiB response ceiling, no redirects and no retries. Browser origins use the existing explicit allowlist; native requests without Origin remain supported. On Render only the last X-Forwarded-For entry is considered; elsewhere the socket address is used. Aggregate caps remain independent of all forwarded/device values.

The requested grant TTL is 30 seconds and permits voice inference, not management APIs. Expiry controls new connections, not an established socket's duration. Android retains its existing 25-second capture ceiling; issuance caps alone cannot enforce that ceiling on an untrusted client. Provider account usage monitoring remains necessary. No audio or transcripts pass through this endpoint. Logs contain only a generated request ID, safe outcome, upstream status and elapsed time.

Validation: 26 focused endpoint/limit tests and 196 full backend tests passed, including localhost HTTP, body/header timeout, cancellation, malformed upstream responses, guest requests, spoof safety, quota reset and redaction. No hotel, flight, pricing, migration, dependency, or Partner behavior changed.

Rollback: redeploy the prior production revision `862941053f59e38f7266d017d515fc68529bc558` / deployment `dep-dahvrdcs728c73dq69qg`. The additional server secret can remain unused; do not revoke the existing Default key. A mobile build that uses this endpoint requires the endpoint to remain available for voice.
