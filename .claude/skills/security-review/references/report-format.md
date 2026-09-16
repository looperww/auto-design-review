# Project security-review report reference

This project uses a compact Markdown format so findings can be parsed and shown
in the web console. It adapts the reporting concepts from GitHub's
`awesome-copilot` security-review skill. The exact headings and finding prefix
defined in `SKILL.md` are mandatory.

## Required structure

```markdown
# Security review

## Summary
One or two sentences describing the changed behavior, review result, and the
most important safeguards or risks.

## Findings
### [HIGH] Short finding title
Category: Injection
Confidence: High
Location: src/example.py:42

Changed behavior: ...
Attack path: attacker-controlled source -> transformations -> sensitive sink.
Business impact: ...
Recommended remediation: ...

Proposed patch (human review required; not applied):
Before: ...
After: ...

## Overall severity rationale
Explain why the highest severity is appropriate and identify material
preconditions or scope limitations.
```

For a review with no evidence-backed findings, use exactly:

```markdown
## Findings
No high-confidence security findings.
```

Then explain the concrete validation, authorization, encoding, parameterization,
or other data-flow evidence supporting the `SAFE` result under
`## Overall severity rationale`. A safe result is evidence-bounded and is not a
guarantee that the repository is vulnerability-free.

## Reporting principles

- Give a file path and line when the supplied evidence makes one available.
- Explain what an attacker can actually control and what security-sensitive
  operation is reached.
- Separate severity (impact) from confidence (strength of evidence).
- Do not report informational observations as vulnerabilities.
- Never imply that a patch was applied. The reviewer is read-only.
