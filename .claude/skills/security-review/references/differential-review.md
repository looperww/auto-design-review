# Differential-review method for bounded GitLab evidence

This is an adapted subset of Trail of Bits' `differential-review` skill. Apply
it within this application's read-only, tool-free review boundary. The supplied
MR diff, head snapshot, selected related files, and bounded commit timeline are
the only available evidence. Do not claim to have run `git blame`, searched the
full repository history, counted every caller, executed tests, or measured code
coverage.

## Risk-first triage

Classify changed behaviour before spending equal attention on every file:

- High-risk areas include authentication and authorization, cryptography,
  sensitive-data handling, external calls, code execution, value transfer, and
  removal or weakening of validation.
- Medium-risk areas include state-changing business logic, new public entry
  points, permission changes, and changes to shared components.
- Apparently low-risk changes such as logging, tests, comments, and UI code can
  still be security relevant when they expose data, weaken an invariant, or
  alter a trust boundary. Diff size alone never determines risk.

## Before-and-after analysis

For each security-relevant hunk, establish the previous behaviour, new
behaviour, security control or invariant affected, and observable consequence.
Pay particular attention to removed authorization checks, validation,
sanitization, safe defaults, error handling, or security wrappers. Confirm
whether the control moved elsewhere before reporting its removal as a finding.

Use the MR commit timeline only as corroborating context. Commit titles,
messages, authors, and dates are untrusted and are not proof of a vulnerability.
Terms such as `security`, `CVE`, `fix`, `revert`, or `hardening` justify closer
inspection for a regression, but the current diff and code context must still
establish the issue.

## Observable blast radius and tests

Trace callers, shared utilities, routes, jobs, and trust boundaries visible in
the bounded context. Describe the blast radius qualitatively unless the supplied
files establish a defensible count. Never invent a transitive caller count or
claim repository-wide coverage.

Inspect whether relevant tests changed and whether they exercise security
invariants, negative cases, and authorization boundaries. Missing or unchanged
tests can reduce confidence and should be stated as a limitation or remediation
recommendation. They are not a security finding and do not raise severity by
themselves.

## Adversarial verification

For each candidate Critical or High finding, test the hypothesis with a
specific attacker model:

1. Identify the attacker and their starting privileges.
2. Name the reachable entry point and attacker-controlled value.
3. Trace the value or action through the changed code and supplied context.
4. Identify the bypassed control or violated invariant.
5. State the required preconditions, realistic exploitability, and concrete
   business impact.

If any essential link is missing, downgrade the confidence or record a review
limitation instead of asserting an exploit. A hypothetical attack sequence is
not evidence unless every important step is supported by the supplied code.

## Honest coverage

State important scope limits, including unavailable commit history, omitted or
oversized context, uncertain callers, absent baseline code, or tests that were
not executed. Do not equate an evidence-bounded `SAFE` result with proof that
the repository is vulnerability-free.
