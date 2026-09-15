# Portable GitLab security-review service

This repository is a self-contained, read-only security checkpoint for GitLab.
Clone it onto any Docker host and start it with Docker Compose. The authenticated
setup page stores the GitLab token, selected LLM provider, model, API key,
optional custom endpoint, GitLab URL, and all review settings in SQLite. It
automatically discovers all projects visible to the GitLab token, reviews new
merge requests and new MR revisions, and keeps reports locally.

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
              ├── MR metadata and diff
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

Grant only these fine-grained permissions:

| Resource | Permission | Why |
| --- | --- | --- |
| Project | Read | Discover the projects visible to the token. |
| Merge Request | Read | Read open MRs, metadata, and diffs. |
| Repository | Read | Download a source snapshot at the exact MR commit. |

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

The management console is bound to the deployment machine's localhost interface
by default. On that machine, open:

```text
http://127.0.0.1:6789/setup
```

Create the first administrator username and password. The password is
PBKDF2-HMAC-SHA256 hashed with a unique salt and stored in SQLite. After the
account is created, the setup page is disabled and you are directed to sign in.

### 6. Sign in and configure the reviewer

After signing in, configure:

- the GitLab URL;
- the read-only GitLab token; and
- an LLM provider and model (Anthropic, OpenAI, Gemini, or Custom);
- optionally, the selected provider's API key; and
- for Custom only, the exact HTTPS OpenAI-compatible Chat Completions URL.

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

Testing does not save or replace either credential. The administrator password
is still required so a blank input can securely reuse an encrypted stored value.

The GitLab and active LLM API credentials, provider, model, custom URL, and GitLab
URL are encrypted with AES-GCM using a key derived from the administrator
password. Password hashes, encrypted credentials, operational settings, review
state, report content, and report metadata are stored in SQLite under the host's
`data/` folder, which is mounted inside the container at `/data`.

The service cannot contact GitLab until the encrypted GitLab credentials have
been saved and unlocked. LLM reviews remain disabled until the encrypted active
provider key is also present.

For a remote server, keep the console bound to localhost and use an SSH tunnel:

```bash
ssh -L 6789:127.0.0.1:6789 user@security-review-server
```

Then open `http://127.0.0.1:6789` on your computer. Do not publish the console
directly to a company network or the internet without an approved HTTPS reverse
proxy and an infrastructure security review.

The web console provides review status, recent reports, validated runtime
settings, and credential rotation. Stored secrets are never displayed again.

After every container or host restart, sign in once to unlock the encrypted
credential vault in memory. This is necessary because no plaintext credential
or separate master encryption key is stored on disk. Until it is unlocked, the
web console remains available but both GitLab discovery and security reviews
wait.

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

Reports can be opened from the authenticated web console. The Markdown report
and its metadata are stored directly in SQLite with the MR identity, commit,
selected context files, prompt size, provider, model, token usage when returned,
and Anthropic duration and estimated cost when returned.
Report records never contain either token; API credentials exist in a separate
SQLite table only as authenticated ciphertext.

MR revisions discovered before the LLM key is configured appear with a `pending`
status and have no report until the selected LLM reviews them.

The dashboard includes Day, Week, and Month filters. These show the number of
distinct MRs first discovered during the last 24 hours, 7 days, or 30 days and
filter the MR-revision table to the same period.

## Automatic discovery

The service does not maintain a repository allowlist. The GitLab token itself
defines the boundary. Every polling cycle:

1. GitLab returns all active projects in which the token owner has at least
   Reporter access.
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
- the complete MR diff and MR description.

The selected LLM is instructed to trace attacker-controlled input through transformations
and sanitizers to SQL, command, filesystem, template, deserialization, logging,
redirect, and outbound-request sinks. This is bounded, heuristic contextual
analysis rather than a formal proof. Production assurance should combine it
with the company's SAST and dependency-scanning controls.

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

Rotate a GitLab or LLM credential from the authenticated web console. The
replacement is encrypted in SQLite and the reviewer starts using it without a
container restart.

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
- The web console listens only on `127.0.0.1:6789` at the Docker host by
  default. The container continues to listen internally on port `8080`.

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
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage)
- [Claude Code installation](https://code.claude.com/docs/en/setup)
- [OpenAI Responses API](https://developers.openai.com/api/reference/cli/resources/responses/methods/create)
- [Gemini text generation API](https://ai.google.dev/gemini-api/docs/generate-content/text-generation)
