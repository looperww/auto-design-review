# Sentry security-review skill attribution

This project incorporates and adapts material from:

- Repository: <https://github.com/getsentry/skills>
- Skill path: `skills/security-review`
- Upstream revision: `c2f99a5b04b4cd992ec3022d7c2c3e23e938d241`
- License: Creative Commons Attribution-ShareAlike 4.0 International
- Upstream attribution: portions of the reference material are derived from
  the OWASP Cheat Sheet Series

The following upstream files are redistributed without content changes:

- `languages/python.md` as `sentry/languages/python.md`
- `languages/javascript.md` as `sentry/languages/javascript.md`
- `infrastructure/docker.md` as `sentry/infrastructure/docker.md`
- `LICENSE` as `LICENSE.getsentry-security-review`

`references/sentry-confidence.md` is an adapted and shortened version of the
upstream workflow. It is changed to:

- review only the MR diff and supplied bounded context;
- preserve this application's dashboard-compatible report schema;
- treat authentication as a risk precondition rather than an automatic reason
  to suppress a vulnerability;
- require evidence before applying any general "always flag" guidance; and
- load detailed language and Docker guidance only when relevant changed paths
  are present.

The adapted material remains available under CC BY-SA 4.0. The full license and
attribution notice are preserved in this directory.
