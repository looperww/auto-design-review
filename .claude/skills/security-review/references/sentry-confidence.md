# Sentry-derived confidence and context checks

This local reference adapts the high-confidence review method from Sentry's
`security-review` skill. Apply it within the company workflow and required
report format in `SKILL.md`.

## Evidence gate

Before reporting a candidate vulnerability, establish all applicable links:

1. The merge request introduced or materially worsened the behavior.
2. A realistic attacker can influence the source value or security decision.
3. The value reaches the sensitive operation through the supplied bounded
   context.
4. Relevant validation, authorization, framework protections, encoding, or
   sanitization do not break the attack path.
5. The impact and required preconditions support the assigned severity.

A dangerous API name alone is not a finding. Trace the value that reaches it.
If one of these links cannot be confirmed, do not present the concern as an
evidence-backed finding. State a material unresolved limitation or manual
verification need where appropriate.

## Source classification

- Treat HTTP inputs, uploaded content, untrusted messages, third-party data,
  and attacker-influenced stored records as potentially attacker controlled.
- Do not assume environment variables, deployment settings, application
  configuration, constants, or administrator-controlled values are attacker
  controlled. Report them only when the supplied context establishes a
  credible attacker-controlled path or the unsafe configuration is itself the
  changed security weakness.
- Data from a database is not automatically trusted or untrusted. Determine who
  can write it and whether its original validation is appropriate for the
  current sink.

## Context and mitigation verification

- Inspect callers, helpers, middleware, serializers, validators, policy checks,
  and framework defaults included in the supplied context before concluding a
  safeguard is absent.
- Confirm that validation or encoding is appropriate for the exact sink. A
  generic allowlist, HTML encoding, shell quoting, or SQL parameterization is
  not interchangeable across contexts.
- Distinguish reachability from exploitability. A code path requiring
  authentication can still contain a serious vulnerability; authentication is
  a precondition that may affect severity, not an automatic dismissal.
- Report only the changed behavior. Existing surrounding weaknesses can explain
  the attack path but remain out of scope unless the MR materially worsens them.

## Confidence handling

- **High confidence**: the changed vulnerable behavior, attacker control,
  missing or ineffective mitigation, and plausible impact are supported by the
  supplied evidence.
- **Medium confidence**: an important link requires verification. Do not promote
  it to a finding merely because the sink is dangerous; identify the missing
  evidence as a limitation when it matters.
- **Low confidence**: speculative or theoretical. Omit it.

The local `SKILL.md` controls severity, wording, dashboard-compatible output,
and the non-negotiable read-only boundaries.

Adapted from Sentry's security-review skill at revision
`c2f99a5b04b4cd992ec3022d7c2c3e23e938d241`. The source material is licensed
under CC BY-SA 4.0; see `../SENTRY-UPSTREAM.md` and
`../LICENSE.getsentry-security-review`. This adaptation changes the upstream
scope from an unrestricted repository review to bounded GitLab MR context,
preserves authenticated vulnerabilities as reviewable findings, and retains
the application's existing report schema.
