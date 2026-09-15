# Portable GitLab security-review service

This repository is a self-contained, read-only security checkpoint for GitLab.
Clone it onto any Docker host and start it with Docker Compose. The authenticated
setup page stores the GitLab token, Anthropic API key, GitLab URL, and all review
settings in SQLite. It automatically discovers all projects visible to the
GitLab token, reviews new merge requests and new MR revisions, and keeps reports
locally.

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
          Claude Opus
              │
              ▼
     local reports and review state
              │
              ▼
 authenticated local web console
```

The service never builds, imports, installs dependencies from, or executes
product code. Repository archives are processed as untrusted data in memory.
Claude receives the MR diff plus a bounded selection of full changed files and
related files. All Claude Code tools are disabled.

## Requirements

- Docker with the Compose plugin.
- Network access to the GitLab API, Docker image sources, Claude Code download
  endpoints, and the Anthropic API.
- At least 4 GB RAM for the Docker host.
- An Anthropic API key with billing and a spending limit configured.
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

### 2. Build and start

```bash
docker compose up --detach --build
```

The image installs Claude Code from Anthropic's stable channel during the build.
The combined reviewer and web-console container runs as an unprivileged user
with a read-only root filesystem, no Linux capabilities, no-new-privileges, and
no Docker socket.

### 3. Check the service

```bash
docker compose ps
```

```bash
docker compose logs --follow app
```

### 4. Create the administrator

The management console is bound to the deployment machine's localhost interface
by default. On that machine, open:

```text
http://127.0.0.1:8080/setup
```

Create the first administrator username and password. The password is
PBKDF2-HMAC-SHA256 hashed with a unique salt and stored in SQLite. After the
account is created, the setup page is disabled and you are directed to sign in.

### 5. Sign in and configure the reviewer

After signing in, first review and save the runtime settings. Then configure:

- the GitLab URL;
- the read-only GitLab token; and
- the Anthropic API key.

The two API credentials and GitLab URL are encrypted with AES-GCM using a key
derived from the administrator password. Password hashes, encrypted credentials,
operational settings, review state, report content, and report metadata are
stored in SQLite in the persistent Docker volume.

The reviewer remains locked and cannot contact GitLab or Anthropic until the
runtime settings and encrypted credentials have both been saved.

For a remote server, keep the console bound to localhost and use an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 user@security-review-server
```

Then open `http://127.0.0.1:8080` on your computer. Do not publish the console
directly to a company network or the internet without an approved HTTPS reverse
proxy and an infrastructure security review.

The web console provides review status, recent reports, validated runtime
settings, and credential rotation. Stored secrets are never displayed again.

After every container or host restart, sign in once to unlock the encrypted
credential vault in memory. This is necessary because no plaintext credential
or separate master encryption key is stored on disk. Until it is unlocked, the
web console remains available but security reviews wait.

Keep an approved backup of the Docker volume. The encryption password is not
recoverable from SQLite. If it is lost, the API credentials must be revoked and
the service must be initialized again. Fully unattended unlock after a restart
would require an external secret manager or master key, which this deployment
intentionally does not store.

Before the first scan, choose whether to review existing open MRs in the setup
page. The default records them as a baseline without spending Claude tokens.
Any MR created later, or any new commit pushed to an MR, is reviewed
automatically. Enabling existing-MR review can create significant API cost.

## Read the reports

Reports can be opened from the authenticated web console. The Markdown report
and its metadata are stored directly in SQLite with the MR identity, commit,
selected context files, prompt size, Claude duration, and estimated Claude cost.
Report records never contain either token; API credentials exist in a separate
SQLite table only as authenticated ciphertext.

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

Claude is instructed to trace attacker-controlled input through transformations
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
| Claude budget per review | USD 5.00 |

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

The named data volume survives `docker compose down`. Do not use
`docker compose down --volumes` unless you intentionally want to delete all
review state and stored reports.

Rotate a GitLab or Anthropic credential from the authenticated web console. The
replacement is encrypted in SQLite and the reviewer starts using it without a
container restart.

## Security boundaries

- GitLab access is read-only and limited by the token's resource boundary.
- Product code is never executed.
- Repository archives are never written into the container filesystem.
- Claude Code runs in bare print mode with tools disabled and no session history.
- The GitLab token is not put in Claude's process environment; only the
  Anthropic API key is supplied to the isolated Claude process.
- Secret-like unchanged files, private keys, dependency directories, generated
  output, binary files, and oversized files are excluded from context.
- The container cannot modify GitLab, approve an MR, merge code, or read
  deployment secrets.
- Web passwords are salted and hashed in SQLite; session tokens are stored only
  as SHA-256 digests, forms use CSRF protection, and login attempts are limited.
- The web console listens only on `127.0.0.1` at the Docker host by default.

Because selected proprietary source code is sent to Anthropic, obtain company
approval for the provider, data-processing terms, retention settings, permitted
repositories, and geographic processing before production use.

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
