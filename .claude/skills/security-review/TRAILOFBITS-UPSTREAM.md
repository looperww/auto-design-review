# Trail of Bits differential-review skill attribution

This project incorporates and adapts material from:

- Creator: Trail of Bits
- Repository: <https://github.com/trailofbits/skills>
- Skill path: `plugins/differential-review/skills/differential-review`
- Upstream revision: `a6d1b234198d95082523645d2fea8745ca7273bd`
- License: Creative Commons Attribution-ShareAlike 4.0 International
- License URI: <https://creativecommons.org/licenses/by-sa/4.0/>

`references/differential-review.md` is an adapted and shortened version of the
upstream workflow. It preserves the risk-first differential analysis,
before/after reasoning, regression cues, blast-radius analysis, test-gap review,
adversarial verification, and explicit coverage limits while changing the
workflow to fit this application:

- the reviewer receives bounded GitLab API evidence rather than a local git
  checkout and cannot run `git blame`, shell searches, tests, or coverage tools;
- commit metadata is treated as untrusted corroborating context, not proof;
- missing tests do not become vulnerabilities or automatically raise severity;
- the application's evidence threshold and dashboard-compatible report format
  remain authoritative;
- the reviewer does not create a separate report file or use upstream agents;
  the returned report is stored by this service; and
- all code review remains read-only and product code is never executed.

The adapted material is distributed under CC BY-SA 4.0. Changes are identified
above, and the source and license links are preserved.
