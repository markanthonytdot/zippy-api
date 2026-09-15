# Combined demo survey — review candidate, September 15, 2026

The new combined flight/package video uses a distinct survey, `combined_demo_v3`. The version is explicit on every new form submission. It does not assign a new meaning to any earlier answer.

## Storage and version boundary

Migration `019_combined_demo_feedback.sql` creates only `combined_demo_feedback_responses`, with server UUID, unique request UUID, constrained survey version, `clarity`, `use_likelihood`, `booked_travel_last_12_months`, source slug, and submitted/created/updated timestamps. The three answer-column names are stable question IDs; exact wording and choices are defined in `lib/combinedDemoFeedback.js` as `QUESTIONS`. New answers have distinct columns rather than reusing historical meanings. No existing table, row, ID, timestamp, constraint, or migration is altered. There is no data backfill, historical copy, or destructive down migration.

Migrations 001–018 retain the checksums from deployed API `7582b1accc4b0de56f6e135a7712694613e081b2`. Historical flight responses remain in `demo_feedback_responses`; historical package responses, independent CTA clicks, and package rate limits remain in their original tables. PUBLIC gets no privileges on the new table. The existing API role and transient HMAC rate limiting continue to apply.

`free_text_v1` and `multiple_choice_v2` are the earlier application's existing inferred question-format names, determined from NULL/non-NULL comprehension choice without writing a version onto stored rows. They do not identify exact historical wording. The flight likelihood wording changed on September 14 without per-response version capture; both known historical phrasings must remain historical context. Exact wording cannot be recovered reliably per response from timestamps, because old browser forms can remain open. None of the new questions is identical to the previous ones, despite overlapping likelihood labels.

## Public API compatibility

`POST /v1/demo-feedback` accepts:

```json
{
  "request_id": "<random UUID v4>",
  "survey_version": "combined_demo_v3",
  "clarity": "Very clear",
  "use_likelihood": "Definitely",
  "booked_travel_last_12_months": true,
  "source": "direct",
  "website": ""
}
```

Allowed clarity values are Very clear, Somewhat clear, Not very clear, Not clear at all. Likelihood values are Definitely, Probably, Probably not, Definitely not. All three answers are required; the booking answer is a JSON boolean. Missing source defaults to direct; `source=qa-combined-demo` clearly marks local verification. Existing capture did not include a referrer or dedicated test flag: source is retained, and older package entry paths remain in package records.

An explicit unknown version is rejected. Unversioned older clients keep the original validation/storage behavior, so an already-open earlier form cannot become a new-survey answer. Exact retries acknowledge success, conflicting payload retries return 409, and writes return only `{ "ok": true }`. Public read denial, strict CORS, honeypot, size limits, and existing no-store behavior remain unchanged.

## Reports, history and exports

The existing report and CSV routes accept `survey_version=combined_demo_v3|free_text_v1|multiple_choice_v2`. Omission retains the legacy flight report and legacy CSV contract. The dashboard explicitly selects the current combined version initially; historical flight formats are separately selectable and historical packages remain at the existing protected package dashboard/export routes.

Current filters: source, likelihood, clarity, booked=yes|no, from/to UTC dates, sort, page. Historical flight selectors retain recent=yes|no and old answer semantics. Incompatible recent/clarity/booked combinations are rejected rather than silently recasting the question. The shared-admin proxy allowlist admits only the new filter keys alongside its existing keys. The bridge keeps its same four authenticated read routes.

Versioned reports include `totals` with `all`, `current`, `free_text_v1`, `multiple_choice_v2`, and `package_v1` counts. These respect source/date filters, independently of selected survey/answer filters. Counts describe responses, not unique people; package click events are not survey responses. Current metric denominators respect all current filters, and no old responses enter them.

`overall.validation` counts respondents whose same stored row has booking=true and use_likelihood=Definitely or Probably, divided by `overall.booked.answered` (all current rows that answered the booking question, including No). Empty denominators return null for a displayed dash. This is a respondent-level intersection, not a product of independent percentages.

Versioned CSV exports retain the previous 12 columns and append Survey version, Request ID, Clarity question ID, Clarity, Use likelihood question ID, Use likelihood, Booking question ID, and Booked travel in last 12 months. Old-question answer columns are blank for current rows; new-question answer columns are blank for historical rows. Historical question format and answer values remain unchanged. CSV exports stream all matching pages inside a consistent snapshot; existing formula protection and UTC timestamps apply. No-version exports preserve their original headers and content.

## Local validation and release boundary

`test/combinedDemoFeedback.test.js` covers all 32 answer combinations, required/exact values, segment intersection/denominator, version filtering, current and historical exports, multi-page exports, existing admin login and anonymous denial, production read bridge, idempotency/conflicts, production-history checksums, migration failure rollback/rerun, and full-row hashes/counts of earlier flight/package/click records. Migration and new submissions must leave those historical hashes and legacy report/funnel snapshots equal.

Use disposable loopback PostgreSQL only. No hosted data was changed or read by this implementation. Recheck production row counts/hashes, ledger, exact service revisions and concurrent releases before any future release; local fixture invariants do not prove live counts. Apply 019 on the production feedback API database only. The tester-admin service has no new feedback tables or migrations: it continues to read through the existing credential-scoped bridge. Deploy the API with 019 before the new dashboard or website begins requesting the current version. Preserve all existing secrets, tester routes, old bookmark redirects and source metadata. Publish the exact `FINAL_DEMO.mp4` filename in the approved website bundle. Roll back application assets if needed while retaining the additive table and all responses.

This candidate is local and uncommitted. No deployment or production migration is authorized by its test results; the requested pre-deployment review remains the handoff boundary.

Final local API regression result: **323 passed, zero failed, zero skipped**, with `node --test --test-concurrency=1` and all feedback/partner database variables targeting disposable loopback PostgreSQL. Log: `/private/tmp/zippi-combined-demo-api-tests.log`. The new integration fixture covers 32 answer combinations and 53 rows for pagination, with eight of 32 respondents (25%) in the validation segment before the pagination samples. These are synthetic test counts, not production counts. Preview counts are recorded separately by the preview harness and browser review.

Request UUID uniqueness is scoped to each survey table, consistent with the existing separate flight/package tables. Reusing a UUID across historical and current survey storage does not overwrite either response; retry comparison remains within the target survey. Current UUID input is normalized to PostgreSQL's canonical lowercase representation so uppercase UUID retries are idempotent.
