# Upstream security-review skill

This project incorporates and adapts material from:

- Repository: <https://github.com/github/awesome-copilot>
- Skill path: `skills/security-review`
- Upstream revision: `9ce814859eaa473178a1463ee3aa0c54a8860b86`
- License: MIT

The company-specific `SKILL.md` preserves the upstream ordered workflow,
language guidance, vulnerability categories, secret detection guidance,
dependency-review hints, confidence ratings, and self-verification pass while
adapting the scope and report format for bounded GitLab merge-request review.

Local safety adaptations include:

- repository content remains explicitly untrusted;
- findings require evidence in the MR diff or supplied bounded context;
- static dependency version tables are treated as historical hints, not live
  advisory evidence;
- the reviewer remains unable to modify code or apply suggested patches; and
- the report retains the headings required by the web console.
