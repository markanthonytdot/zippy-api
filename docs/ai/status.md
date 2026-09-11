# Backend local status

2026-09-10: Hotel rate-limit reliability implemented and locally validated; **uncommitted and not deployed**. Full details, scope, configuration cautions and deployment prerequisites: [hotel-rate-limit-reliability.md](../hotel-rate-limit-reliability.md).

- Structured Zippi/provider 429 and accurate known cooldowns.
- Separate API abuse and actual Duffel discovery/pricing budgets; no numeric limit increase.
- Finite server-owned QA preparation, no caller bypass.
- Same-access in-flight discovery coalescing with independent caller cancellation and one upstream debit; no completed cache.
- 89 focused tests passed; full suite 232 passed, 3 existing PostgreSQL skips (235 total). Production syntax and diff checks passed.
- Android/iOS, booking/payment and runtime configuration unchanged. No live provider tests in this implementation task.
- Staging-ready subject to separate authorization. Production capacity requires provider allowance/aggregate scope review and distributed-counter assessment.
- Concurrent Partner edits are preserved, including unrelated `server.js` hunks; isolate scope before any deployment checkpoint.
