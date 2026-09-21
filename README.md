# Portable GitLab security-review service

This repository is a self-contained, read-only security checkpoint for GitLab.
Clone it onto any Docker host and start it with Docker Compose. The authenticated
setup page stores the GitLab token, selected LLM provider, model, API key,
optional custom endpoint, GitLab URL, optional GitLab group path, and all review
settings in SQLite. It automatically discovers the selected group's projects
or all projects visible to the GitLab token, reviews new merge requests and new
MR revisions, and keeps reports locally.

No GitLab Runner, webhook listener, pipeline trigger, or `.gitlab-ci.yml` change
is required in product repositories.

## How it works

```text
GitLab projects visible to the token
              │
              │ poll open MRs every five minutes
              ▼
     portable reviewer container
              │
              ├── MR metadata, bounded commit timeline, and diff
              ├── exact read-only repository snapshot at the MR head SHA
              ├── bounded source/sanitizer/sink context selection
              └── centrally managed security-review skill
              │
              ▼
  selected LLM provider
  (Anthropic by default)
              │
              ▼
     local reports and review state
              │
              ▼
 authenticated local web console
```

The service never builds, imports, installs dependencies from, or executes
product code. Repository archives are processed as untrusted data in memory.
The selected LLM receives the MR diff plus a bounded selection of full changed
files and related files. When Anthropic is selected, all Claude Code tools are
disabled. OpenAI and Gemini are called through their official HTTPS APIs;
custom providers use an administrator-supplied OpenAI-compatible Chat
Completions endpoint.

## Requirements

- Docker with the Compose plugin.
- Network access to the GitLab API, Docker image sources, and the selected LLM
  provider. Anthropic also requires access to Claude Code download endpoints.
- At least 4 GB RAM for the Docker host.
- An API key and billing controls for the selected LLM provider when reviews are
  enabled. GitLab discovery can be tested before this key is added.
- A GitLab fine-grained personal access token or service-account token.

## GitLab token permissions

Create the token at the highest company group that should be reviewed. The
token's resource boundary is the deployment scope: every existing and future
project visible inside that boundary is discovered automatically.

Grant only these fine-grained permissions. The project-discovery permission is
under the token's **User** boundary; the review permissions use the selected
company group/project boundary:

| Boundary | Resource | Permission | Why |
| --- | --- | --- | --- |
| User | Project | Read | Discover projects visible to the token owner. |
| Group and project | Merge Request | Read | Read open MRs, metadata, and diffs. |
| Group and project | Repository | Read | Download a source snapshot at the exact MR commit. |

If the GitLab version offers legacy scopes instead of resource permissions, use
`read_api`. A 403 during **Test GitLab access** usually means **User → Project:
Read** is missing from a fine-grained token, the selected resource boundary does
not contain the projects, or a GitLab access policy is denying the request. A
401 normally means the token is invalid, expired, revoked, incomplete, or was
created for a different GitLab instance.

For a group-scoped access token, enter its namespace in **GitLab group path**,
for example `maas`. The service then uses the group-projects API instead of the
user-wide projects API and includes projects in nested subgroups automatically.
For a nested group, enter the full namespace such as `company/platform`; do not
enter a browser URL or an `/api/v4` endpoint. Leave the field blank when using a
user or service-account token that supports user-wide project discovery.

Do not grant create, update, approve, merge, push, administration, runner, or
deployment permissions. The token-owning account should have only Reporter
membership inherited from the top-level company group.

For production, use a dedicated non-human service account instead of a person's
token. Set an expiration date, record an owner, and define a rotation process.

## Deploy

### 1. Clone the repository

```bash
git clone git@gitlab.bce.lu:security/automated-design-review.git
cd automated-design-review
```

### 2. Prepare the persistent data folder

The container stores its SQLite database, encrypted credentials, runtime
settings, review state, and reports in the repository's `data/` folder. Prepare
that folder for the container's unprivileged user (UID `10001`):

```bash
mkdir -p data
sudo chown 10001:10001 data
sudo chmod 700 data
```

The folder is excluded by both Git and the Docker build context. Never commit or
copy its contents into an image because it contains encrypted credentials and
company security-review records.

### 3. Build and start

```bash
docker compose up --detach --build
```

The image installs Claude Code from Anthropic's stable channel during the build
so Anthropic remains available as the default provider. OpenAI, Gemini, and
custom providers use direct HTTPS requests and require no additional SDK.
The combined reviewer and web-console container is named
`automated-design-review`. It runs as an unprivileged user with a read-only root
filesystem, no Linux capabilities, no-new-privileges, and no Docker socket.

### 4. Check the service

```bash
docker compose ps
```

```bash
docker compose logs --follow app
```

### 5. Create the administrator

The management console is bound to all host network interfaces on port `6789`.
Open it using the deployment machine's IP address:

```text
http://SERVER-IP:6789/setup
```

Restrict inbound TCP port `6789` to the approved management network in the host
or network firewall. For production, place the service behind an approved HTTPS
reverse proxy rather than transmitting credentials over plain HTTP.

Create the first administrator username and password. The password is
PBKDF2-HMAC-SHA256 hashed with a unique salt and stored in SQLite. After the
account is created, the setup page is disabled and you are directed to sign in.

### 6. Sign in and configure the reviewer

After signing in, select **Settings** in the dashboard header, then configure:

- the GitLab URL;
- optionally, the GitLab group path associated with a group-scoped token;
- the read-only GitLab token; and
- an LLM provider and model (Anthropic, OpenAI, Gemini, or Custom);
- optionally, the selected provider's API key; and
- for Custom only, the exact HTTPS OpenAI-compatible Chat Completions URL.

The Custom API URL field is hidden unless **Custom** is selected in the provider
dropdown.

The GitLab token can be saved without an LLM API key. The service then
checks the GitLab connection, discovers open MR revisions, and records them as
`pending` in SQLite. It does not download repository archives or diffs and does
not invoke an LLM in this mode. The dashboard shows the last GitLab connection
result, every repository visible to the token, and the queued MR count. This
allows the administrator to verify the GitLab URL, token, scope, and permissions
without incurring LLM cost.

The LLM API key can be added later without re-entering the stored GitLab token.
Once it is saved, queued open MR revisions are reviewed in order, subject to the
configured maximum reviews per cycle. Leaving either secret field blank during
a later update preserves its stored value when the provider remains unchanged.
Changing provider requires entering the new provider's key so a key is never
silently reused with a different provider.

After a key is saved, its empty password field displays a masked
`•••••••••••• (stored)` placeholder. This confirms that a value exists without
returning the secret to the browser or submitting the placeholder as a new key.

The provider dropdown offers these built-in modes:

| Provider | Default model | Connection method |
| --- | --- | --- |
| Anthropic | `opus` | Claude Code CLI with tools disabled |
| OpenAI | `gpt-6-astra` | Official Responses API with response storage disabled |
| Gemini | `gemini-3.8-flash` | Official Generate Content API |
| Custom | Administrator-supplied | Exact HTTPS OpenAI-compatible Chat Completions endpoint |

Model names are editable because availability depends on the provider account
and models change over time. “Custom” does not mean every possible proprietary
API protocol: the endpoint must accept the common OpenAI Chat Completions JSON
request shape and bearer-token authentication.

Before saving, use the two credential-test buttons in the web console:

- **Test GitLab access** calls the GitLab Projects API and reports how many
  repositories are visible to the submitted or stored token.
- **Test LLM connection** sends one minimal request using the selected provider,
  key, URL, and model. Anthropic uses a USD 0.05 hard budget for this test; other
  providers receive a 16-token output limit. A very small API charge may occur.

Testing does not save or replace either credential. Signing in derives and
unlocks the vault encryption key in memory, so the credential form does not ask
for the administrator password again. The plaintext password is never retained.

Use **Fetch models** beside the Model field after entering or saving the selected
provider's API key. The browser asks the local service for the provider's model
list and displays a dropdown; choosing an item copies its identifier into the
editable Model field. This operation does not save the key, URL, or model and
does not invoke a generation request. Anthropic, OpenAI, and Gemini use their
official model-list endpoints. For a Custom OpenAI-compatible Chat Completions
URL, the service derives the conventional sibling `/models` endpoint; custom
providers that do not expose that endpoint require the model name to be entered
manually.

The GitLab and active LLM API credentials, provider, model, custom URL, and GitLab
URL are encrypted with AES-GCM using a key derived from the administrator
password. Password hashes, encrypted credentials, operational settings, review
state, report content, and report metadata are stored in SQLite under the host's
`data/` folder, which is mounted inside the container at `/data`.

The service cannot contact GitLab until the encrypted GitLab credentials have
been saved and unlocked. LLM reviews remain disabled until the encrypted active
provider key is also present.

The container publishes `0.0.0.0:6789`, so the console is reachable through any
host interface permitted by the firewall. Do not expose this port directly to
the internet. An SSH tunnel remains an option if direct network access is later
disabled.

The authenticated console uses a responsive sidebar with four primary pages:

- **Dashboard** is the main operational view. It shows review outcomes and the
  Critical and High security-finding queue. A compact green/red indicator
  beneath the page title shows the latest GitLab connection status.
- **Completed MRs** lists the latest completed review for every MR, including
  SAFE reviews with no findings. Results can be filtered by severity and human
  review status, and each row expands to show the reviewed diff, review summary,
  severity rationale, finding evidence, and recorded human decision.
- **Repositories** provides a focused inventory of repository coverage,
  per-repository access status, MR activity, finding totals, date filters, and
  pagination. Overall GitLab health remains in the compact Dashboard header.
- **Settings** contains runtime controls, credential tests and rotation, and the
  protected data-reset action.

The sidebar also shows the current reviewer state and signed-in administrator.
Stored secrets are never displayed again.

Every finding row on the Dashboard and Completed MRs page, and every MR row on
the repository-specific MR page, has a human-review control. Its default state
is **Open**. An administrator can change it to **In Progress** or **Done**. A
Done decision requires the administrator to choose **False positive** or
**Confirmed finding**, select a severity for a confirmed finding, and record
comments explaining the verification decision. These decisions are stored in
SQLite against the exact MR commit and finding, together with the administrator
and update time.

A finding resolved as a false positive is removed from the Dashboard queue and
repository finding totals. It remains in Completed MRs with a **SAFE** label,
the original AI evidence, and the human comments, preserving the audit trail.
An MR-level decision made from the repository MR page applies to the entire MR
revision; a finding-level decision takes precedence for that individual
finding. New MR commits start with a fresh Open status. Completed MRs and
repository MR lists can both be filtered by Open, In Progress, or Done.

The Settings page also provides a protected **Reset repository and MR data**
action. The administrator must type `RESET` exactly before it runs. The reset
deletes the repository inventory, every MR revision, report, parsed finding,
and associated human-review decision,
clears the previous GitLab scan status, and records the reset time as a new
deployment cutoff. Administrator accounts, active login sessions, encrypted
GitLab and LLM credentials, and runtime settings remain unchanged. The reviewer
is then woken for a fresh discovery cycle; open MRs created before the reset
time are not imported again.

After every container or host restart, any existing authenticated web session
is invalidated and the administrator is redirected to the sign-in page. Signing
in again automatically unlocks the encrypted credential vault in memory. No
separate unlock action exists in Settings. This is necessary because no
plaintext credential or separate master encryption key is stored on disk;
until sign-in succeeds, both GitLab discovery and security reviews wait.

Keep an approved backup of the host `data/` folder. Stop the service before
copying it so the SQLite backup is consistent. The encryption password is not
recoverable from SQLite. If it is lost, the API credentials must be revoked and
the service must be initialized again. Fully unattended unlock after a restart
would require an external secret manager or master key, which this deployment
intentionally does not store.

When GitLab and LLM credentials are supplied together, choose whether to
review existing open MRs before the first scan. The default records them as a
baseline without spending LLM tokens. Any MR created later, or any new commit
pushed to an MR, is reviewed automatically. Enabling existing-MR review can
create significant API cost.

When GitLab discovery is deliberately started before the LLM key is
available, discovered MR revisions are queued instead of baselined. This ensures
the administrator can add the LLM key later and review the MRs that were
used to validate GitLab access.

## Read the reports

Reports can be opened from the authenticated web console. The Markdown report,
bounded reviewed diff, and metadata are stored directly in SQLite with the MR
identity, commit, selected context files, prompt size, provider, model, token
usage when returned, and Anthropic duration and estimated cost when returned.
Reviews created before diff retention was introduced remain visible, but their
expanded view explains that the historical diff is unavailable.
Report records never contain either token; API credentials exist in a separate
SQLite table only as authenticated ciphertext.

MR revisions discovered before the LLM key is configured appear with a `pending`
status and have no report until the selected LLM reviews them.

The Repositories page combines visible repositories and fetched-MR activity in one
**Repositories and MRs** table. For each repository it shows:

- the numeric GitLab ID;
- **Up** when the latest GitLab MR-list request for that repository succeeded,
  **Down** when it failed, and **Unknown** before the first completed check;
- the number of distinct MRs in the selected period, counting multiple commit
  revisions of one MR only once;
- the number of parsed security findings in the latest reviewed revision of
  those MRs; and
- the latest MR creation date and time in that period.

The table displays 50 repositories per page by default. A selector above the
table allows 10, 25, 50, or 100 rows per page. Changing either the row limit or
the page number is submitted immediately by the repository page without an
additional button. These
selectors and the Previous/Next controls preserve the active rolling period or
custom UTC date range. Repository totals continue to cover all visible
repositories, not only the current page.

Click a non-zero MR count to open that repository's filtered MR list and its
available security reports. The repository-specific MR page has the same Day,
Week, Month, and inclusive UTC date-range filters as the repository inventory.
Each MR row is selectable and expands into a bounded code-diff panel for manual
inspection. The latest commit SHA links directly to that commit in GitLab. A
compact list of commit messages and authors loads automatically above the diff
when the row is expanded. The messages and authors are plain text; the existing
commit SHA remains the link to GitLab. There is no separate commit section or
additional button, and no commit API request is made until the row is expanded.
A completed review uses its retained diff immediately. If a queued
or historical row has no retained diff, expanding it fetches the exact current
MR revision from GitLab on demand and caches it in SQLite. The service refuses
to display a mismatched diff or commit history if GitLab has received a newer
commit; the next discovery cycle must record that revision first. Commit data
comes from GitLab's read-only
[Retrieve merge request commits](https://docs.gitlab.com/api/merge_requests/#retrieve-merge-request-commits)
endpoint and is normalized before it is returned to the browser. Diff panels use a light
code-review theme: additions are green, deletions are red, hunk markers are
blue, and file metadata is purple for easier manual inspection.

The Dashboard **High-severity findings** section lists only unresolved or
confirmed Critical and High findings for the active period. Each row shows the
finding title, a direct link to the corresponding GitLab MR, an expandable
vulnerability details panel, and the human-review status control.

The Completed MRs table adds **Manual review** to the common **Severity**,
**Finding title**, **MR**, and **Vulnerability details** columns. It includes
Critical, High, Medium, Low, and SAFE results, supports severity and
human-review-status filters, and displays 20 rows per page. Clicking a result
row expands a full-width evidence panel with the reviewed diff and the same
inline commit-message and author summary. SAFE means either the evidence-bounded
review established no high-confidence vulnerability or an administrator
verified the AI result as a false positive; the retained resolution explains
which applies. Neither case guarantees that the repository is
vulnerability-free.

On both Dashboard and Repositories, Day, Week, and Month select rolling windows
of 24 hours, 7 days, and 30 days. The administrator can also select an inclusive
UTC start-date and end-date range; choosing the same date in both fields filters
one calendar day. MRs created before the deployment cutoff remain excluded.

## Automatic discovery

The service does not maintain a repository allowlist. The GitLab token and
optional group path define the boundary. Every polling cycle:

1. GitLab returns projects from the configured group and its subgroups, or all
   active projects in which the token owner has at least Reporter access when
   the group path is blank.
2. The service lists open MRs in those projects.
3. The local SQLite database identifies MR commit SHAs not seen before.
4. Unseen revisions are queued and reviewed in order.

New projects are therefore included automatically when the service account
inherits access to them. To exclude a project, remove that service account's
access to the project or place the project outside the token's resource boundary.

The first application start creates a persistent `deployment_started_at` cutoff
in SQLite. GitLab may return open MRs that were created before the reviewer was
deployed, but those MRs are not queued, counted, or reviewed. Only MRs whose
GitLab `created_at` timestamp is on or after the cutoff are included. Rebuilding
or replacing the container does not reset the cutoff because it is stored in the
host `data/` folder.

A deployment on another server with a newly created, empty `data/` folder gets a
new cutoff based on that server deployment's start time. Intentionally copying
or restoring an existing `data/` folder is treated as moving the same deployment
and therefore retains its original cutoff and review history.

Each successful GitLab scan refreshes a persistent inventory of all repositories
currently visible to the token, including repositories with no open MRs. The web
console lists the full inventory and each repository's latest successful
observation time.

## Review-cycle limit

`MAX_REVIEWS_PER_CYCLE=5` means that one polling cycle processes at most five
pending MR revisions. It does not discard the remainder. For example, if 12 new
MR revisions are found, the default configuration processes five, then five,
then two over three cycles.

Set the value to `0` in the web console to process all pending revisions in the
same cycle. This still processes reviews sequentially, and any MRs created while
that cycle is running are discovered in the next cycle. Unlimited mode can
create a large and sudden API bill, so a finite limit is recommended for normal
operation.

Runtime settings saved in the web console are stored in SQLite and apply
automatically on the next polling cycle. No `.env` file is used.

## Context and data-flow analysis

For each new MR revision, the reviewer downloads a repository archive at the
exact source commit and selects:

- full contents of changed text files;
- related files sharing changed identifiers, functions, classes, and paths;
- security-relevant files involving authentication, authorization, routes, and
  permissions;
- the complete MR diff and MR description; and
- up to 100 MR commit records, bounded to 32 KB, as untrusted historical
  context for regression analysis.

The selected LLM is instructed to trace attacker-controlled input through transformations
and sanitizers to SQL, command, filesystem, template, deserialization, logging,
redirect, and outbound-request sinks. This is bounded, heuristic contextual
analysis rather than a formal proof. Production assurance should combine it
with the company's SAST and dependency-scanning controls.

## Security-review skill

The centralized reviewer uses
`.claude/skills/security-review/SKILL.md` plus a strict allowlist of reference
files. The approved package incorporates and adapts GitHub's
[awesome-copilot security-review skill](https://github.com/github/awesome-copilot/tree/main/skills/security-review)
at upstream revision `9ce814859eaa473178a1463ee3aa0c54a8860b86` under the
MIT License, together with Sentry's
[security-review skill](https://github.com/getsentry/skills/tree/main/skills/security-review)
at upstream revision `c2f99a5b04b4cd992ec3022d7c2c3e23e938d241` under CC BY-SA
4.0, and Trail of Bits'
[differential-review skill](https://github.com/trailofbits/skills/tree/main/plugins/differential-review/skills/differential-review)
at upstream revision `a6d1b234198d95082523645d2fea8745ca7273bd` under CC BY-SA
4.0.

The upstream ordered workflow adds technology identification, changed-dependency
review, secrets scanning, language-specific vulnerability checks, cross-file
data-flow analysis, confidence ratings, and a mandatory self-verification pass.
Local instructions take precedence where needed: only the MR change is in scope,
repository content is untrusted, findings require concrete evidence, static
package tables are not treated as current advisory data, and the reviewer
remains read-only. The local report-format reference preserves the headings the
web console parses. Sentry's method adds an explicit evidence gate, source
classification, framework-mitigation checks, and stronger false-positive
controls. Authentication is treated as a risk precondition, not an automatic
reason to suppress an otherwise evidenced vulnerability. The Trail of Bits
adaptation adds risk-first before/after analysis, regression cues from the MR
commit timeline, observable blast-radius reasoning, test-gap review, adversarial
verification, and explicit coverage limits. Commit messages are untrusted and
corroborative only; missing tests are a limitation rather than a vulnerability,
and the model may not claim `git blame`, repository-wide caller counts, test
execution, or coverage measurements that the service did not supply.

The service always loads the approved core references and Sentry-derived
confidence rules. It loads the redistributed Sentry Python, JavaScript, or
Docker guide only when the MR changes a matching file. This technology routing
keeps unrelated instructions out of the prompt and controls token cost. The
combined skill package is limited to 512 KB, and arbitrary files in the skill
directory are never loaded. Source attribution, pinned revisions, adaptations,
and licenses are recorded in `.claude/skills/security-review/UPSTREAM.md`,
`.claude/skills/security-review/SENTRY-UPSTREAM.md`, and the corresponding
license files.

Trail of Bits attribution and adaptation details are recorded in
`.claude/skills/security-review/TRAILOFBITS-UPSTREAM.md` and
`.claude/skills/security-review/LICENSE.trailofbits-differential-review`.

The default limits keep one review within a manageable input and cost envelope:

| Setting | Default |
| --- | ---: |
| Poll interval | 300 seconds |
| Reviews per cycle | 5; `0` means all pending |
| Changed files | 200 |
| Diff size | 300 KB |
| Repository archive | 100 MB |
| Context files | 20 |
| Individual context file | 100 KB |
| Total selected context | 350 KB |
| MR commit context | 100 commits and 32 KB |
| Anthropic budget per review | USD 5.00 |

Oversized, collapsed, or incomplete changes produce a manual-review-required
report instead of a false clean result.

## Operations

Stop the service:

```bash
docker compose down
```

Update it without deleting review history:

```bash
git pull
docker compose up --detach --build
```

The host `data/` folder survives container replacement, image rebuilding, and
`docker compose down`. A normal update therefore preserves the administrator
account, encrypted API credentials, settings, review history, and reports.

Back up the persistent data safely:

```bash
docker compose stop app
tar -czf ../automated-design-review-data-backup.tgz data
docker compose start app
```

To restore, stop the service, replace the `data/` folder with the backed-up
contents, restore ownership to UID and GID `10001`, and start the service again.
Store the backup in an approved protected location because it contains company
security-review records and encrypted credentials. Never delete `data/` unless
you intentionally want to erase all stored configuration and review history.

Rotate a GitLab or LLM credential from the authenticated, unlocked web console.
The replacement is encrypted in SQLite and the reviewer starts using it without
a container restart. Re-entering the administrator password is not required;
only its derived encryption key remains in process memory after sign-in.

## Security boundaries

- GitLab access is read-only and limited by the token's resource boundary.
- Product code is never executed.
- Repository archives are never written into the container filesystem.
- Claude Code runs in bare print mode with tools disabled and no session history
  when Anthropic is selected.
- The GitLab token is never sent to or placed in the process environment of an
  LLM client. Only the active provider's API key is sent to that provider.
- OpenAI requests set `store` to `false`. Provider-side retention and training
  terms must still be confirmed contractually for every selected provider.
- A Custom endpoint receives selected proprietary code and is trusted as an LLM
  destination; administrators must verify its owner, TLS, retention, and access
  controls before saving it.
- Secret-like unchanged files, private keys, dependency directories, generated
  output, binary files, and oversized files are excluded from context.
- The container cannot modify GitLab, approve an MR, merge code, or read
  deployment secrets.
- Web passwords are salted and hashed in SQLite; session tokens are stored only
  as SHA-256 digests, forms use CSRF protection, and login attempts are limited.
- The credential-vault encryption key is derived during sign-in, held only in
  process memory, and lost on restart. The administrator password is not stored
  in memory for credential changes.
- The web console listens on `0.0.0.0:6789` at the Docker host and therefore
  relies on a host/network firewall and an approved HTTPS reverse proxy for
  production access. The container listens internally on port `8080`.

Because selected proprietary source code is sent to the active LLM provider,
obtain company approval for that provider, data-processing terms, retention
settings, permitted repositories, and geographic processing before production
use.

## Local tests

```bash
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

## Official references

- [GitLab Projects API](https://docs.gitlab.com/api/projects/)
- [GitLab Merge Requests API](https://docs.gitlab.com/api/merge_requests/)
- [GitLab repository archive API](https://docs.gitlab.com/api/repositories/#retrieve-file-archive)
- [GitLab fine-grained token permissions](https://docs.gitlab.com/auth/tokens/fine_grained_access_tokens_rest/)
- [GitLab access-token scopes](https://docs.gitlab.com/security/tokens/access_token_scopes/)
- [GitLab token troubleshooting](https://docs.gitlab.com/security/tokens/token_troubleshooting/)
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage)
- [Claude Code installation](https://code.claude.com/docs/en/setup)
- [OpenAI Responses API](https://developers.openai.com/api/reference/cli/resources/responses/methods/create)
- [Gemini text generation API](https://ai.google.dev/gemini-api/docs/generate-content/text-generation)
