# Repository Manager — Specification

**Status:** Draft v0.2
**Last updated:** 2026-08-26

---

## 1. Overview

Repository Manager is a Python/FastAPI web application for managing the contents of Linux
package repositories (APT and RPM). It provides a browser interface for creating repositories,
uploading and removing packages, and keeping repository metadata and signatures correct.

It is distributed as a Python package on **PyPI** (`repository-manager`) and as a container
image.

### 1.1 Goals

- Let a small team publish internal `.deb` and `.rpm` packages without hand-running
  `apt-ftparchive` / `createrepo_c`.
- Make repository contents publicly readable, and all mutations authenticated and audited.
- Be operable as a single process with no external services beyond an optional database.
- Meet WCAG 2.2 Level AA.

### 1.2 Non-goals (v1)

- Mirroring or syncing from upstream repositories.
- Building packages (no build farm, no source uploads producing binaries).
- Source package indices (`Sources`, `.dsc`, SRPMs) — see §14.
- Serving repository content to `apt`/`dnf` clients (see §4.4).
- TLS termination, certificate management, or HTTP→HTTPS redirection (the reverse proxy's
  job — see §10.6).
- Other formats (Alpine `apk`, Arch, Python, OCI registries).
- Multi-tenancy beyond LDAP-group role mapping.

### 1.3 Terminology

| Term | Meaning |
|---|---|
| **Repository** | A managed unit with a name, a type (`apt` or `rpm`), a root path on disk, and a signing key. |
| **Distribution** (APT) | A suite/codename within an APT repository, e.g. `noble`. Owns components and architectures. |
| **Component** (APT) | A section within a distribution, e.g. `main`, `contrib`. |
| **Variant** (RPM) | A separately-indexed subtree of an RPM repository, e.g. `el9/x86_64`. |
| **Publication target** | The specific (distribution, component, architecture) or (variant) a package belongs to. |
| **Job** | A background unit of work, e.g. regenerating metadata for one repository. |

---

## 2. Architecture decisions

These were settled during spec refinement and are treated as fixed for v1.

| # | Decision | Rationale |
|---|---|---|
| AD-1 | **Server-rendered Jinja2 + HTMX**, no SPA, no Node build step. | Simplest path to WCAG AA and standard CSRF; forms work with JavaScript disabled; one deployable artifact. |
| AD-2 | **APT metadata generated in pure Python; RPM metadata via `createrepo_c`.** | APT indices are plain text and cheap to emit correctly. RPM metadata (XML + sqlite, delta updates) is not worth reimplementing. |
| AD-3 | **The application does not serve repositories to clients.** An external web server (nginx/Apache) serves the repository root over HTTP(S). | Keeps bandwidth and static-file serving out of the Python process. Example nginx config ships in the docs. |
| AD-4 | **State split: database + filesystem.** SQLite by default, PostgreSQL supported. Packages and generated metadata live on disk. | An audit trail, job state, and API tokens need a database regardless. |
| AD-5 | **Authorization via LDAP group → role mapping.** Roles: `admin`, `maintainer`, anonymous read. | Matches existing org structure; no in-app user management to build. |
| AD-6 | **Signing keys stored in an app-managed GnuPG home; passphrases supplied via configuration/secrets.** | Unattended signing is required for API-token uploads and background re-signing. |
| AD-7 | **Scoped API tokens for machine access**, in addition to interactive LDAP login. | CI must be able to publish without an interactive session or a shared LDAP credential. |
| AD-8 | **In-process background job queue with a per-repository exclusive lock.** | Metadata regeneration exceeds request timeouts on large repos, and concurrent regeneration corrupts indices. No Redis/Celery dependency. |
| AD-9 | **Repositories are internally subdivided.** An APT repository holds multiple distributions, components, and architectures; an RPM repository holds multiple variants (e.g. `el9/x86_64`). | Matches the real formats; avoids forcing one repository per release or architecture. |
| AD-10 | **Metadata is signed; package artifacts are never rewritten.** | Re-signing an uploaded `.rpm`/`.deb` changes its checksum and breaks upstream provenance. |
| AD-11 | **Multiple versions per package name are retained**, with a retention count chosen by the user at repository creation. | Version pinning and rollback are baseline expectations for a package repository, but the right depth varies per repository. |
| AD-12 | **Deleting a repository deregisters it; purging files from disk is a separate, explicitly-confirmed action.** | Destructive only on clear intent. |
| AD-13 | **TLS is terminated at a reverse proxy; the application speaks plain HTTP and trusts forwarded headers from configured proxies only.** Exactly one application instance runs. | No certificate handling in the app. A single instance is what permits the in-process job queue and rate limiter (AD-8). |
| AD-14 | **The application is deployable at a sub-path** (e.g. `https://host/repoman/`) as well as at a domain root. | Common when sharing a hostname with the repository tree itself, which AD-3 puts on the same web server. |
| AD-15 | **APT `Release` files do not carry `Valid-Until`.** | Avoids obliging periodic re-signing of idle repositories; clients will not expire the repository. |
| AD-16 | **Every repository is readable by everyone; there are no private repositories.** | Read access is uniform, so no per-repository visibility model, no filtered listings, and no risk of a metadata leak through search or job pages. |
| AD-17 | **GPL-3.0-or-later**, with dependency licences checked in CI. | MIT was the initial preference, but `python-debian` (GPL-2.0-or-later) is imported directly and `ldap3` is LGPL-3; keeping both — rather than reimplementing around them — settles the combined work at GPL-3-or-later. Covers this application's source only, never the packages it hosts. See §14.1. |
| AD-18 | **`pre-commit` enforces formatting, linting, and typing locally; GitHub Actions re-runs the same checks in CI.** | The same commands run in both places, so CI never fails on something a commit could have caught. |

---

## 3. Roles and permissions

Authentication is via LDAP (§7). Authorization is by role, derived from LDAP group membership
at login and cached in the session.

| Capability | Anonymous | `maintainer` | `admin` |
|---|:--:|:--:|:--:|
| List repositories, browse packages, download metadata/public keys | ✅ | ✅ | ✅ |
| View audit log | ❌ | own actions | all |
| Upload / remove packages | ❌ | ✅ | ✅ |
| Trigger metadata regeneration | ❌ | ✅ | ✅ |
| Create / edit repository settings | ❌ | ❌ | ✅ |
| Add distributions, components, architectures, variants | ❌ | ❌ | ✅ |
| Import / generate / rotate GPG keys | ❌ | ❌ | ✅ |
| Deregister a repository | ❌ | ❌ | ✅ |
| Purge repository files from disk | ❌ | ❌ | ✅ |
| Mint own API tokens | ❌ | ✅ | ✅ |
| Revoke any user's API tokens | ❌ | ❌ | ✅ |

Notes:

- **Read access is universal and unconditional** (AD-16). Every repository, its package list,
  its metadata, and its public key are visible to unauthenticated users. There is no private
  or hidden repository state, so listings are never filtered by identity.
- Roles are global, not per-repository. Per-repository ACLs are explicitly deferred (§15).
- If a user matches both group mappings, `admin` wins.
- If a user authenticates but matches no mapped group, login fails with a clear message
  ("your account is not a member of any group permitted to make changes") rather than
  granting a silent read-only session.
- An API token can never exceed the role of the user who minted it, and is re-evaluated
  against that user's current groups at request time (see §7.4).

---

## 4. Repository formats

### 4.1 APT

**On-disk layout**, rooted at the repository's configured path:

```
<root>/
  dists/
    <codename>/
      Release
      Release.gpg
      InRelease
      <component>/
        binary-<arch>/
          Packages
          Packages.gz
          Packages.xz
          Release
  pool/
    <component>/<prefix>/<source-name>/<file>.deb
  <keyname>.asc            # armoured public key, for client trust setup
```

`<prefix>` follows Debian convention: the first letter of the source package name, or the
first four characters for names beginning `lib` (e.g. `pool/main/libf/libfoo/`).

**Index generation** (pure Python, per AD-2):

- Package control fields are extracted with `python-debian` (`debian.debfile.DebFile`).
- `Packages` contains one stanza per package with at minimum: `Package`, `Source`,
  `Version`, `Architecture`, `Maintainer`, `Installed-Size`, `Depends`/`Pre-Depends`/
  `Recommends`/`Suggests`/`Conflicts`/`Breaks`/`Replaces`/`Provides` (as present),
  `Filename` (relative to `<root>`), `Size`, `MD5sum`, `SHA1`, `SHA256`, `Section`,
  `Priority`, `Homepage`, `Description`, `Description-md5`.
- `binary-all` packages are additionally materialised into every configured
  architecture's `Packages` index, as `apt` requires.
- `Release` per distribution contains `Origin`, `Label`, `Suite`, `Codename`, `Version`
  (optional), `Date`, `Architectures`, `Components`, `Description`, and
  `MD5Sum`/`SHA1`/`SHA256` blocks listing every index file with size and hash, paths
  relative to `dists/<codename>/`.
- `Valid-Until` is deliberately not emitted (AD-15), so metadata never expires on clients
  and idle repositories never need re-signing.
- `Date` uses RFC 2822 in UTC (`%a, %d %b %Y %H:%M:%S UTC`).
- Signing: `InRelease` (inline-signed `Release`) and `Release.gpg` (detached, armoured)
  are both produced for client compatibility.
- `Description-md5` is the MD5 of the raw `Description` field value plus a trailing
  newline, with continuation lines keeping their single leading space — verified against
  `apt-ftparchive -o APT::FTPArchive::LongDescription=false`, which is the definition apt
  itself uses.
- Indices are written deterministically (stanzas sorted, compression timestamps zeroed), so
  regenerating an unchanged repository produces byte-identical files.
- Version ordering uses `debian.debian_support.Version` (Debian policy comparison).

### 4.2 RPM

**On-disk layout:**

```
<root>/
  <variant>/                 # e.g. "el9/x86_64"
    Packages/
      <name>-<version>-<release>.<arch>.rpm
    repodata/
      repomd.xml
      repomd.xml.asc
      primary.xml.gz
      filelists.xml.gz
      other.xml.gz
  RPM-GPG-KEY-<keyname>      # armoured public key
```

- A repository must define at least one variant. Each variant is an independently indexed
  subtree with its own `repodata`, its own `.repo` client snippet, and its own package set;
  a package is uploaded into exactly one variant. Variant names are validated as one or
  more slug segments joined by `/` (e.g. `el9`, `el9/x86_64`) and may not traverse upward.
- Metadata is generated by invoking `createrepo_c --update` against the variant
  directory (subprocess; the Python bindings are used when importable). Variants are
  regenerated independently, so an upload only reindexes the variant it landed in.
- `repomd.xml` is signed with a detached armoured signature at `repomd.xml.asc`.
- NEVRA is read from the RPM header via `rpmfile` (pure Python) so the `rpm` Python
  bindings are not a hard dependency.
- Version ordering uses `rpm-vercmp` semantics (epoch, version, release).

### 4.3 Repository creation

The creation form collects: name, type (`apt`/`rpm`), root path, description, signing key
(import existing or generate new), retention choice (§5.3), and the initial subdivision —
at least one distribution with its components and architectures for APT, or at least one
variant for RPM. More can be added later.

Creating a repository then:

1. Validates that the target path is inside a configured allowed root (§10.4), is absolute,
   contains no symlink traversal, and is either empty or nonexistent.
2. Creates the directory tree for the chosen type with mode `0755` (files `0644`).
3. Associates a signing key — either an imported existing key or a newly generated one.
4. Writes the initial (empty but valid and signed) metadata so clients can add the repo
   immediately.
5. Exports the armoured public key into the repository root.

**Key generation defaults:** RSA 4096, no expiry, UID `<repo name> repository signing key
<configured email domain>`. Key type and size are selectable (RSA 4096, RSA 3072, Ed25519).

### 4.4 Serving to clients

Out of scope for the application (AD-3). Documentation will include a reference nginx
configuration exposing the repository root read-only with directory indexes enabled, plus
client-side setup snippets:

- APT: `deb [signed-by=/usr/share/keyrings/<name>.asc] https://host/<repo> <codename> <components>`
- RPM: a `.repo` file with `baseurl`, `gpgcheck=1`, `repo_gpgcheck=1`, `gpgkey`.

The application generates and displays both snippets on each repository's page.

---

## 5. Package operations

### 5.1 Upload

1. The client (browser form or API token request) supplies a file plus a publication target:
   for APT a distribution and component (architecture is read from the package); for RPM a
   variant.
2. The upload is streamed to a temporary file inside the same filesystem as the repository
   root, with a configurable size limit (`REPOMAN_MAX_UPLOAD_BYTES`, default 2 GiB).
3. The file is validated:
   - magic bytes match the expected format (`!<arch>` for `.deb`, `0xEDABEEDB` for `.rpm`);
   - metadata parses and yields a complete name/version/architecture;
   - the architecture is one configured on the target (or `all`/`noarch`);
   - optionally (`REPOMAN_VERIFY_UPLOAD_SIGNATURES=true`) the package's own signature
     verifies against a configured keyring — failures are rejected with a clear reason.
   Uploads are never gated on the package's licence — any package is accepted (§14.1).
4. Duplicate handling: an identical name+version+architecture already present is rejected
   as a conflict (HTTP 409) unless it is byte-identical, in which case the upload is a no-op
   success. Overwriting a published version with different content is never permitted.
5. The file is moved into place with an atomic rename, the database row is written, an audit
   entry is recorded, and a metadata-regeneration job is enqueued for the repository.

### 5.2 Removal

Removing a package deletes its database row and its file from the pool, records an audit
entry, and enqueues regeneration. Removal is per (name, version, architecture, target).

### 5.3 Retention

Retention is chosen by the user when the repository is created (AD-11) and is editable
afterwards by an admin. The creation form presents it as a required choice:

- **Keep all versions** (`retention_count = 0`), or
- **Keep the newest N versions per package name** (N ≥ 1).

No implicit default is applied — the form makes the user pick, so unbounded disk growth is
always a deliberate decision rather than an oversight.

Retention is **version-based, not time-based** — a count of versions kept per package name
per publication target. No package is ever pruned for age alone. Time-based expiry is
deliberately excluded: a package that is simply stable rather than abandoned would otherwise
be deleted despite being the only version clients can install.

When N is set, after a successful publish the oldest versions of that package name beyond
the newest N are pruned from that publication target, using the format's own version
ordering (§4.1, §4.2). Pruning is recorded in the audit log. A pool file is only deleted
once no publication target references it.

Lowering N on an existing repository does not retroactively prune; it takes effect on the
next publish for each affected package. The repository settings page shows how many packages
would be pruned and offers an explicit "apply retention now" action.

### 5.4 Metadata regeneration

Always performed as a job (AD-8), never inline. Regeneration is:

- **Locked** — one job at a time per repository, via a database advisory lock plus an
  on-disk lockfile.
- **Atomic where possible** — indices are written to a temporary directory and moved into
  place; `createrepo_c --update` writes new `repodata` before swapping `repomd.xml`.
- **Coalescing** — multiple pending regeneration requests for the same repository collapse
  into one queued job.
- **Idempotent and resumable** — a job interrupted by restart is re-queued at startup.

A manual "regenerate metadata" action is available to maintainers for recovery after
out-of-band filesystem changes, along with a "rescan repository" action that reconciles the
database against what is actually on disk and reports drift.

---

## 6. Background jobs

- Implemented as an `asyncio` worker pool started with the application lifespan; CPU-bound
  and subprocess work runs in a thread/process executor so the event loop is never blocked.
- Job states: `queued`, `running`, `succeeded`, `failed`, `cancelled`.
- Job records persist progress, a log excerpt, timing, the actor, and the error on failure.
- Concurrency is bounded by `REPOMAN_JOB_CONCURRENCY` (default 2).
- On startup, jobs left in `running` (from an unclean shutdown) are marked `failed` with a
  restart reason and their repository is re-queued for regeneration.
- The UI shows job status via an HTMX-polled fragment with `aria-live="polite"`; without
  JavaScript the job page still renders full status and a manual refresh control.

---

## 7. Authentication and authorization

### 7.1 LDAP

- Library: `ldap3`; **connections must use LDAPS or StartTLS**. Plaintext bind is refused
  unless `REPOMAN_LDAP_ALLOW_INSECURE=true` is set explicitly (intended for local dev only).
- Two supported bind modes:
  - **Search-then-bind** (default): bind as a service account, search for the user with a
    configurable filter, then re-bind as the user's DN to verify the password.
  - **Direct bind**: format the DN from a template.
- All user-supplied values interpolated into DNs or filters are escaped per RFC 4514/4515.
- Group membership resolution supports both `memberOf` and a reverse group search filter,
  configurable, with optional nested-group expansion.
- Failures distinguish (in logs, not to the user) "bad credentials" from "directory
  unreachable"; the user-facing message is uniform to avoid account enumeration.
- Login is rate-limited per username and per source IP (§10.3).

### 7.2 Sessions

- Server-side sessions stored in the database, referenced by an opaque random cookie
  (256-bit, `secrets.token_urlsafe`).
- Cookie flags: `HttpOnly`, `SameSite=Lax`, `Secure` (unless `REPOMAN_DEV_INSECURE_COOKIES`).
- Idle timeout 8 hours, absolute lifetime 24 hours, both configurable.
- Session ID is rotated on login and destroyed on logout.
- Roles are captured at login; a configurable revalidation interval (default 15 minutes)
  re-checks group membership so revoked access takes effect without waiting for expiry.

### 7.3 CSRF

- All state-changing requests that authenticate via **session cookie** require a CSRF token:
  a per-session secret, rendered as a hidden `_csrf` field in every form and sent by HTMX via
  the `X-CSRF-Token` header. Verified with a constant-time comparison.
- `Origin`/`Referer` are additionally checked against the configured public URL.
- Requests authenticating via **bearer token** are exempt (no ambient credential to abuse),
  and cookie-based credentials are ignored on those routes.

### 7.4 API tokens

- Format: `rmt_<base64url(32 random bytes)>`, shown exactly once at creation.
- Stored as a SHA-256 hash; lookup by a non-secret prefix, then constant-time compare.
- Attributes: owner DN, human label, scopes (`package:read`, `package:write`), an optional
  repository allow-list, an expiry (default 90 days, maximum configurable), `last_used_at`.
- Revocable by the owner or any admin. Revoked and expired tokens are rejected identically.
- **Effective permission = token scopes ∩ owner's current role.** If the owner loses their
  LDAP group, their tokens stop working without needing explicit revocation.
- Token authentication is accepted on `/api/**` only, via `Authorization: Bearer`.

---

## 8. HTTP interface

### 8.1 Web (session-authenticated, HTML)

| Route | Method | Access |
|---|---|---|
| `/` | GET | anonymous — repository list |
| `/repositories/{slug}` | GET | anonymous — overview, client setup snippets, public key |
| `/repositories/{slug}/packages` | GET | anonymous — searchable, paginated package list |
| `/repositories/new` | GET, POST | admin |
| `/repositories/{slug}/settings` | GET, POST | admin |
| `/repositories/{slug}/distributions` | GET, POST, DELETE | admin (APT) |
| `/repositories/{slug}/variants` | GET, POST, DELETE | admin (RPM) |
| `/repositories/{slug}/packages/upload` | GET, POST | maintainer |
| `/repositories/{slug}/packages/{id}/delete` | POST | maintainer |
| `/repositories/{slug}/regenerate` | POST | maintainer |
| `/repositories/{slug}/rescan` | POST | maintainer |
| `/repositories/{slug}/delete` | GET, POST | admin — deregister, with optional purge |
| `/keys` | GET, POST | admin |
| `/jobs`, `/jobs/{id}` | GET | authenticated |
| `/audit` | GET | maintainer (own) / admin (all) |
| `/tokens` | GET, POST, DELETE | authenticated |
| `/login`, `/logout` | GET, POST | anonymous / authenticated |
| `/healthz`, `/readyz` | GET | anonymous |
| `/metrics` | GET | configurable (off by default) |

### 8.2 REST API (token-authenticated, JSON)

Versioned under `/api/v1`. OpenAPI schema and docs are served (docs can be disabled).

```
GET    /api/v1/repositories
GET    /api/v1/repositories/{slug}
GET    /api/v1/repositories/{slug}/packages          ?name= &arch= &distribution= &component= &variant=
POST   /api/v1/repositories/{slug}/packages          multipart upload + target fields
DELETE /api/v1/repositories/{slug}/packages/{id}
POST   /api/v1/repositories/{slug}/regenerate
GET    /api/v1/jobs/{id}
```

- Read endpoints are anonymous, matching the web UI.
- Write endpoints require a token with `package:write` and repository scope.
- Errors use RFC 9457 `application/problem+json`.
- Upload responses include the created package and the enqueued job ID so CI can poll for
  publication rather than guessing.

---

## 9. Data model

SQLAlchemy 2.0 ORM, Alembic migrations. Tables:

- **`repository`** — `id`, `slug` (unique), `name`, `type`, `root_path`, `description`,
  `signing_key_id`, `retention_count` (NOT NULL; `0` = keep all), `origin`, `label`,
  `created_at`, `created_by`, `deregistered_at`.
- **`apt_distribution`** — `id`, `repository_id`, `codename`, `suite`, `description`,
  unique on (`repository_id`, `codename`).
- **`apt_component`** — `id`, `distribution_id`, `name`.
- **`apt_architecture`** — `id`, `distribution_id`, `name`.
- **`rpm_variant`** — `id`, `repository_id`, `name`, `arch`.
- **`package`** — `id`, `repository_id`, `name`, `source_name`, `epoch`, `version`,
  `release`, `architecture`, `relative_path`, `size`, `sha256`, `control_json`,
  `uploaded_at`, `uploaded_by`, `uploaded_via` (`web`|`token`).
- **`package_publication`** — `id`, `package_id`, and the target (`component_id` or
  `variant_id`); allows one pool file to be published to multiple targets.
- **`signing_key`** — `id`, `name`, `fingerprint`, `algorithm`, `public_key_armored`,
  `passphrase_ref`, `created_at`, `created_by`, `expires_at`.
- **`api_token`** — `id`, `owner_dn`, `label`, `prefix`, `token_hash`, `scopes`,
  `repository_scope`, `created_at`, `expires_at`, `last_used_at`, `revoked_at`.
- **`job`** — `id`, `type`, `repository_id`, `state`, `progress`, `log`, `error`, `actor`,
  `created_at`, `started_at`, `finished_at`.
- **`audit_log`** — `id`, `occurred_at`, `actor`, `actor_type`, `action`, `repository_id`,
  `target`, `details_json`, `source_ip`, `outcome`. Append-only; no UI or API deletes.
- **`session`** — `id`, `user_dn`, `display_name`, `role`, `csrf_secret`, `created_at`,
  `last_seen_at`, `expires_at`, `revalidate_after`.

Private key material is **never** stored in the database — it lives in the GnuPG home (§10.5).

---

## 10. Security

### 10.1 Transport and headers

- HSTS (subject to §10.6), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: DENY`,
  `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy` denying unused features.
- Content-Security-Policy with a per-response nonce; no inline scripts or styles without the
  nonce, no `unsafe-inline`, no remote origins. HTMX is vendored and served locally.

### 10.2 Input handling

- All templates auto-escape; no `|safe` on user-controlled values.
- Repository slugs and distribution/component/variant names are validated against a strict
  allow-list pattern (`[a-z0-9][a-z0-9._-]*`, no `..`).
- Uploaded filenames are never trusted; the stored path is derived from parsed package
  metadata.

### 10.3 Rate limiting

- Login: per-username and per-IP, with exponential backoff and a temporary lockout.
- Token authentication failures and upload endpoints: per-token and per-IP limits.
- Implemented in-process (token bucket); documented as per-instance, not cluster-wide.

### 10.4 Filesystem safety

- Every repository root must resolve (after `Path.resolve()`, symlinks followed) inside one
  of the configured `REPOMAN_ALLOWED_ROOTS` prefixes; the check is re-applied on every write.
- No path component is ever taken from user input without validation.
- Writes use create-temp-then-`os.replace` to avoid partially-written indices.
- `O_NOFOLLOW` on writes where available; the process is expected to run as a dedicated
  non-root user owning the repository tree.

### 10.5 Key material

- Keys live in an app-managed `GNUPGHOME` (`0700`, files `0600`) outside the served
  repository roots.
- `gpg` is invoked with `--batch --pinentry-mode loopback` and the passphrase supplied on a
  file descriptor — never on the command line and never in an environment variable visible
  in `/proc`.
- Passphrases are resolved from a secrets file or environment reference at startup, held in
  memory, and excluded from all logs, error pages, and tracebacks.
- Private keys are never exportable through the UI or API. Public keys are freely downloadable.
- Deleting a key is blocked while any repository references it.

### 10.6 Reverse proxy trust

The application terminates plain HTTP and sits behind a reverse proxy that handles TLS
(AD-13). Forwarded headers are security-relevant — the client IP drives rate limiting (§10.3)
and the audit log, and the scheme drives cookie flags — so they are only honoured from
configured sources.

- `REPOMAN_TRUSTED_PROXIES` lists the proxy addresses/CIDRs permitted to set
  `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Prefix`.
  It has **no default**: with it unset, all forwarded headers are ignored and the peer
  address is used directly. An unauthenticated client cannot spoof its source IP to escape
  a rate limit or poison the audit trail.
- The client IP is taken as the right-most `X-Forwarded-For` entry not in the trusted set.
- The `Secure` cookie flag is set when the effective scheme is `https`; the application
  refuses to start in `production` with a `REPOMAN_PUBLIC_URL` of `http://` unless
  `REPOMAN_DEV_INSECURE_COOKIES` is explicitly set.
- HSTS is emitted only when the effective scheme is `https`. Deployments where the proxy
  already sets HSTS can suppress the app's header with `REPOMAN_SEND_HSTS=false`.
- Origin/Referer checks (§7.3) compare against `REPOMAN_PUBLIC_URL`, the externally visible
  origin *including any sub-path*, not the internal listen address.
- The documented nginx reference config (§4.4) includes the matching `proxy_set_header`
  directives, and explicitly strips any inbound `X-Forwarded-*` from the client.

### 10.7 Other

- No secrets in logs; a redaction filter covers passwords, passphrases, tokens, cookies.
- Debug mode and interactive tracebacks are off by default and refuse to enable when
  `REPOMAN_ENV=production`.
- Dependency scanning (`pip-audit`) and static analysis (`ruff`, `bandit`) in CI.

---

## 11. User interface and accessibility

**Target: WCAG 2.2 Level AA**, verified rather than asserted.

- Semantic HTML with correct landmarks (`header`/`nav`/`main`/`footer`), one `h1` per page,
  and a properly nested heading outline.
- A "skip to main content" link is the first focusable element.
- Every control has an accessible name; every input has a `<label>`; validation errors are
  associated via `aria-describedby` and summarised in a focusable error region at the top of
  the form.
- Colour is never the sole carrier of meaning — status uses an icon plus text.
- Contrast ≥ 4.5:1 for text and ≥ 3:1 for UI components and graphical objects, in both themes.
- Focus is always visible and meets the 3:1 focus-appearance requirement.
- Fully keyboard operable; no keyboard traps; logical tab order; no positive `tabindex`.
- HTMX swaps move focus deliberately and announce changes via `aria-live` regions; the
  content of a swap is never the only notification of a result.
- Every flow works with JavaScript disabled (HTMX is progressive enhancement only).
- Theme follows `prefers-color-scheme`, with an explicit Light/Dark/System override persisted
  in a cookie so the server can render the correct theme on first paint (no flash).
  `prefers-reduced-motion` is respected.
- Tables (package lists) use proper `<th scope>`, captions, and accessible sort controls with
  `aria-sort`.
- Long operations expose progress as text, not only as an animation.

**Verification:** automated `axe-core` checks via Playwright over every page in CI, plus a
documented manual pass with a screen reader (Orca on Linux, NVDA on Windows) recorded in
`docs/accessibility.md` per release.

---

## 12. Configuration

Configuration via `pydantic-settings`: environment variables prefixed `REPOMAN_`, optionally
layered over a TOML file at `REPOMAN_CONFIG_FILE`. Secrets may be given by `*_FILE` variants
pointing at files (Docker/Kubernetes secret convention). The application validates
configuration at startup and exits with an actionable message on error.

Key settings:

| Variable | Default | Purpose |
|---|---|---|
| `REPOMAN_DATABASE_URL` | `sqlite+aiosqlite:///./repoman.db` | SQLite or PostgreSQL |
| `REPOMAN_ALLOWED_ROOTS` | *(required)* | Colon-separated path prefixes repositories may live under |
| `REPOMAN_PUBLIC_URL` | *(required)* | External origin **including any sub-path**; used for Origin checks, redirects, and client snippets |
| `REPOMAN_ROOT_PATH` | `""` | Sub-path the app is mounted at, e.g. `/repoman` |
| `REPOMAN_TRUSTED_PROXIES` | *(unset)* | Proxy addresses/CIDRs whose `X-Forwarded-*` headers are honoured; unset = ignore them all |
| `REPOMAN_SEND_HSTS` | `true` | Set false when the reverse proxy already sends HSTS |
| `REPOMAN_DEV_INSECURE_COOKIES` | `false` | Accept a `http://` public URL in `production`; see §10.6 |
| `REPOMAN_GNUPGHOME` | `./gnupg` | App-managed keyring directory |
| `REPOMAN_REPOSITORY_BASE_URL` | `<public_url>/repos` | External URL the repository *trees* are served from (§4.4); client snippets are built from this, not from the application's own URL |
| `REPOMAN_KEY_EMAIL_DOMAIN` | *(public URL's host)* | Email domain used in a generated signing key's UID (§4.3) |
| `REPOMAN_VERIFY_UPLOAD_SIGNATURES` | `false` | Verify an uploaded package's own signature (§5.1) |
| `REPOMAN_LDAP_URL` | *(required)* | `ldaps://…` |
| `REPOMAN_LDAP_BIND_MODE` | `search` | `search` or `direct` |
| `REPOMAN_LDAP_BIND_DN` / `_PASSWORD` | — | Service account for search mode |
| `REPOMAN_LDAP_USER_BASE_DN` / `_FILTER` | — | User lookup |
| `REPOMAN_LDAP_GROUP_ADMIN` / `_MAINTAINER` | *(required)* | Group DNs mapped to roles |
| `REPOMAN_SECRET_KEY` | *(required)* | Session/CSRF signing |
| `REPOMAN_MAX_UPLOAD_BYTES` | `2147483648` | Upload cap |
| `REPOMAN_JOB_CONCURRENCY` | `2` | Worker pool size |
| `REPOMAN_TOKEN_MAX_LIFETIME_DAYS` | `365` | Ceiling on token expiry |
| `REPOMAN_LOG_FORMAT` | `json` | `json` or `console` |
| `REPOMAN_ENV` | `production` | Guards debug features |

`REPOMAN_ALLOW_UNAUTHENTICATED_WRITES` was a temporary setting covering the gap between M2
shipping the write paths and M3 shipping the login meant to guard them. **M3 removed it**,
along with the checks that read it; the role gate in §3 replaces it.

`REPOMAN_ALLOWED_ROOTS`, `REPOMAN_PUBLIC_URL` and `REPOMAN_SECRET_KEY` have no default and
are enforced from M1. `REPOMAN_LDAP_URL`, `REPOMAN_LDAP_GROUP_ADMIN` and
`REPOMAN_LDAP_GROUP_MAINTAINER` were optional until M3, so the M1 skeleton could run without
a directory server; **M3 promoted them to required**, since an instance with no directory has
no way for anyone to sign in and therefore no way to change anything.

Sessions (§7.2) add `REPOMAN_SESSION_IDLE_TIMEOUT_MINUTES` (default `480`),
`REPOMAN_SESSION_ABSOLUTE_LIFETIME_MINUTES` (`1440`) and `REPOMAN_SESSION_REVALIDATE_MINUTES`
(`15`). The remaining `REPOMAN_LDAP_*` settings — bind mode and its DNs, group resolution
mode, nesting, display-name attributes, timeouts — are documented in `docs/deployment.md`.

---

## 13. Packaging, deployment, and operations

### 13.1 Python package

- Name `repository-manager`, build backend `hatchling`, dependencies managed with `uv`.
- Supports Python 3.11–3.14.
- Console script `repository-manager` with subcommands:
  - `serve` — run under uvicorn
  - `db upgrade` / `db revision` — Alembic
  - `check-config` — validate configuration and exit
  - `rescan <slug>` — offline reconciliation
- Templates and static assets are packaged as package data.
- **System dependencies** (documented prominently in the README, since pip cannot install
  them): `createrepo_c`, `gnupg` ≥ 2.2. `createrepo_c` is only required for RPM support;
  the application starts without it and disables RPM repository creation with a clear
  message.

### 13.2 Container image

- Base: `python:3.13-slim-*`; installs `createrepo_c` and `gnupg` from the distro.
- Runs as a non-root user (UID 1000) that owns `/var/lib/repoman` and the GnuPG home.
- Volumes: repository roots, GnuPG home, database (when SQLite).
- Multi-stage build; image published for `linux/amd64` and `linux/arm64`.
- `HEALTHCHECK` hits `/healthz`.

### 13.3 Observability

- Structured JSON logging (`structlog`) with a request ID on every line.
- `/healthz` (liveness: process up) and `/readyz` (readiness: DB reachable, GnuPG usable,
  `createrepo_c` present if RPM repos exist, allowed roots writable).
- Optional Prometheus `/metrics`: request metrics, job queue depth, job durations and
  failures, upload bytes, repository and package counts.

### 13.4 Testing

- `pytest` + `pytest-asyncio`; coverage gate on the metadata-generation and permission layers.
- Unit tests for index generation against golden files.
- LDAP tested with `ldap3`'s mock server for unit tests and a containerised OpenLDAP for
  integration tests.
- **Format-correctness integration tests**: generated repositories are consumed by real
  `apt-get update` / `dnf makecache` inside containers, including signature verification —
  this is the test that actually proves AD-2 is safe.
- Playwright tests covering the no-JavaScript path and running `axe-core` (§11).
- Fixtures include small purpose-built `.deb` and `.rpm` files, including a `noarch`/`all`
  package and a multi-version case.

### 13.5 Reverse proxy and sub-path deployment

The application must work identically at a domain root (`https://host/`) and at a sub-path
(`https://host/repoman/`) — AD-14. The sub-path is expected to be common, since AD-3 puts the
repository tree itself on the same web server.

- The external prefix comes from `REPOMAN_ROOT_PATH` (e.g. `/repoman`), or from
  `X-Forwarded-Prefix` when sent by a trusted proxy (§10.6). It is passed to FastAPI as
  `root_path`, so generated OpenAPI servers and docs URLs are correct too.
- **No URL is ever hard-coded or written as a root-relative literal.** Every link, form
  `action`, redirect, and `hx-get`/`hx-post` target is produced by `request.url_for()` or an
  equivalent helper so the prefix is always applied. This is enforced by a lint check for
  `href="/`, `action="/`, and `hx-*="/` in templates, and by the tests below.
- Static assets are mounted under the prefix and referenced through the same helper.
- The session cookie's `Path` is set to the root path so two applications on the same
  hostname cannot see each other's cookies.
- Redirects are built from the external origin and prefix, never from the internal request
  URL, so a login redirect never leaks the internal listen address.
- The proxy is expected to pass the prefix through (`proxy_pass` without stripping) *or*
  strip it and send `X-Forwarded-Prefix`; both are documented with working nginx snippets.
- `/healthz` and `/readyz` are also reachable under the prefix; the reference config exempts
  them from any authentication the proxy adds.
- Client setup snippets (§4.4) and the public key URL are rendered as absolute URLs from
  `REPOMAN_PUBLIC_URL`, since users copy them into `sources.list` and `.repo` files.

**Testing:** the Playwright suite runs twice in CI — once at `/` and once behind a proxy at
`/repoman/` — asserting that no request 404s and no generated URL omits the prefix. This is
the only reliable way to keep sub-path support from regressing.

### 13.6 Delivery phases

| Phase | Contents |
|---|---|
| **M1 — Skeleton** | Config, database, migrations, layout/theme, accessibility baseline, health endpoints, anonymous repository list, **and sub-path/proxy-header handling with its dual CI run (§13.5)** — retrofitting prefix-correct URL generation later is far more expensive than starting with it. |
| **M2 — APT** | Key management, APT repository creation, upload/remove, pure-Python index generation and signing, job queue, verified against `apt-get`. |
| **M3 — Auth** | LDAP login, sessions, CSRF, role mapping, audit log. |
| **M4 — RPM** | `createrepo_c` integration, variants, `repomd.xml` signing, verified against `dnf`. |
| **M5 — API** | Scoped tokens, REST endpoints, OpenAPI, CI usage documentation. |
| **M6 — Hardening** | Retention enforcement, rescan/drift reporting, rate limiting, metrics, accessibility audit, PyPI + GHCR release. |

Repository scaffolding — `LICENSE`, `pyproject.toml`, `.pre-commit-config.yaml`, and the
GitHub Actions workflows (§14) — lands before M1, so every commit from the first one is
linted, typed, and tested.

---

## 14. Development workflow

### 14.1 Licensing

The project is licensed **GPL-3.0-or-later** (AD-17): the verbatim GPL-3 text in `LICENSE`
at the repository root, copyright held by *Lee*, `license = "GPL-3.0-or-later"` and the
matching classifier in `pyproject.toml`, an "or later" notice in source file headers, and the
licence included in the sdist and wheel.

**Why not MIT.** MIT was the initial preference, but the decision was to keep the natural
libraries for this domain rather than reimplement around them, and their licences settle the
question. Verified from PyPI metadata:

| Dependency | Purpose | Licence | Effect |
|---|---|---|---|
| `python-debian` | `.deb` control parsing (§4.1) | **GPL-2.0-or-later** | Imported into the application, so the distributed combined work is a derived work and must be conveyed under GPL terms. **This is the deciding dependency.** |
| `ldap3` | LDAP client (§7.1) | **LGPL-3** | Used unmodified as an installed dependency; the LGPL imposes no copyleft on our source. Compatible with GPL-3, but *not* with GPL-2-only. |
| `rpmfile` | RPM header reading (§4.2) | MIT | No constraint. |
| `createrepo_c` | RPM metadata (§4.2) | GPL-2+ | Invoked as a **separate process**, not linked. Would impose nothing on its own. |

GPL-**3**-or-later specifically: `python-debian`'s "or later" permits GPL-3, and GPL-3 is the
only version compatible with `ldap3`'s LGPL-3. GPL-2-only would not work.

Consequences to be aware of, since they are easy to overlook for a web application:

- The copyleft obligation triggers on **conveying** — publishing the wheel to PyPI and the
  image to GHCR both count. Running a private instance for your own users does not; the GPL
  has no network-use clause (that would be the AGPL, which is not being adopted here).
- Downstream users may modify and redistribute under the same terms. Anyone embedding this
  code in a larger product inherits the obligation.
- `/healthz` and the UI footer expose the version and a link to the licence and source,
  satisfying the "Appropriate Legal Notices" expectation for an interactive interface.

**Scope: the licence covers this application's source only.** Packages uploaded into managed
repositories are third-party artifacts that retain their own licences entirely; the
application asserts no rights over them, does not relicense them, and does not inspect,
record, gate, or filter uploads on licence grounds — any package is accepted (§5.1).
Proprietary packages may be hosted freely. A managed repository's contents are mere
aggregation, and the packages are separate works served by a separate web server (AD-3). The
`LICENSE` file therefore lives at the *source repository* root and is never written into a
package repository's directory tree, where it would be mistaken for a statement about the
packages served from it. `README` and `CONTRIBUTING.md` state this distinction explicitly.

**CI enforces the boundary**: a licence-scanning step (`pip-licenses` or `reuse`) fails the
build if any dependency's licence falls outside a GPL-3-compatible allow-list. The trap to
catch is a **GPL-2-only** dependency, which cannot be combined with GPL-3; permissive
licences and Apache-2.0 are all fine inbound. This stops an incompatible library entering the
tree unnoticed via a transitive upgrade.

### 14.2 pre-commit

`.pre-commit-config.yaml` at the repository root, installed with `pre-commit install`
(and `--hook-type commit-msg`). Hooks:

| Hook | Purpose |
|---|---|
| `ruff` (`--fix`) | Linting, import sorting, pyupgrade rules |
| `ruff-format` | Formatting — the single source of style truth |
| `mypy` | Static typing; `strict` on the metadata-generation and permission modules |
| `bandit` | Python security linting (§10.7) |
| `djlint` | Jinja2 template linting and formatting |
| `codespell` | Typos in code, templates, and docs |
| `check-yaml`, `check-toml`, `check-json` | Config file syntax |
| `end-of-file-fixer`, `trailing-whitespace`, `mixed-line-ending` | Whitespace hygiene |
| `check-added-large-files` | Blocks accidental commits of `.deb`/`.rpm` fixtures above a size cap |
| `check-merge-conflict`, `detect-private-key` | `detect-private-key` matters here — this project's docs and tests handle GPG material |
| `uv-lock` | Keeps `uv.lock` in sync with `pyproject.toml` |
| **local: `no-absolute-urls`** | Fails on `href="/`, `action="/`, or `hx-*="/` in templates, enforcing §13.5 sub-path correctness |
| **local: `alembic-heads`** | Fails if migrations have more than one head, catching branch-merge mistakes |

Hooks run on changed files locally; CI runs `pre-commit run --all-files` so the two can never
disagree. Fast hooks only at commit time — the test suite is not a pre-commit hook.

### 14.3 GitHub Actions

Workflows under `.github/workflows/`. All use least-privilege permissions
(`contents: read` by default), a `concurrency` group cancelling superseded runs on a branch,
and `uv` with a warm cache.

| Workflow | Trigger | Contents |
|---|---|---|
| `ci.yml` → `lint` | PR, push to `main` | `pre-commit run --all-files`, `mypy`, licence allow-list check (§14.1) |
| `ci.yml` → `test` | PR, push | Unit tests on Python 3.11 / 3.12 / 3.13 / 3.14; coverage uploaded; gate on the metadata and permission modules |
| `ci.yml` → `integration` | PR, push | Containerised OpenLDAP; **real `apt-get update` and `dnf makecache` against generated repositories, with signature verification** (§13.4) |
| `ci.yml` → `e2e` | PR, push | Playwright + `axe-core`, run twice — mounted at `/` and at `/repoman/` (§13.5) — plus the JavaScript-disabled path |
| `security.yml` | PR, push, weekly schedule | `pip-audit`, CodeQL, `dependency-review` on PRs |
| `release.yml` | Tag `v*` | Build sdist + wheel, `twine check`, publish to PyPI via **Trusted Publishing (OIDC)** — no long-lived token — under a protected `pypi` environment |
| `container.yml` | Tag `v*`, push to `main` | `docker/build-push-action` with buildx for `linux/amd64` and `linux/arm64`, pushed to **GHCR**; `main` publishes `:edge`, tags publish `:X.Y.Z` and `:latest`; build provenance attestation enabled |

Notes:

- The `integration` and `e2e` jobs are the ones that actually protect AD-2 and AD-14; they
  are required status checks, not optional.
- Both markers carried no tests before M1 and M2 respectively, and `pytest` exits 5 when it
  collects nothing — indistinguishable from a failure. A guard script treated *only* exit 5
  as a pass until then. It was **deleted in M2**, once `integration` gained real `apt-get`
  verification and `e2e` its browser suite, because leaving it in place would mask a suite
  that had silently stopped collecting.
- `id-token: write` is granted only in `release.yml`, and only in the publish job.
- Dependabot is enabled for `pip`, `github-actions`, and `docker`, grouped into weekly PRs.
- Because CI generates and consumes signed repositories, test signing keys are **generated
  per run** and never stored as secrets.

### 14.4 Repository conventions

- Branch protection on `main`: linear history, required status checks, no direct pushes.
- Conventional Commits, validated by a `commit-msg` hook, feeding an automated changelog.
- Semantic versioning; the version lives in `pyproject.toml` and is exposed at
  `/healthz` and in the footer.
- `CONTRIBUTING.md` documents `uv sync`, `pre-commit install`, and the system dependencies
  (`createrepo_c`, `gnupg`) needed to run the full suite locally.
- Issue and PR templates; a PR checklist item for accessibility impact (§11).

---

## 15. Deferred / open

Deferred to a later version, listed so the v1 data model does not preclude them:

- Per-repository ACLs (the role model is deliberately global for v1).
- Source packages: `Sources` indices, `.dsc`/`.orig.tar.*` handling, SRPMs.
- APT `by-hash` index publication.
- Signing packages themselves (`rpmsign`/`debsign`) — rejected for v1 per AD-10.
- Repository mirroring/sync, and staging→production promotion workflows.
- Module/appstream metadata for RPM, and `.deb` `Translation-*` files.
- Multi-instance deployment (AD-13 fixes v1 at one instance; scaling out requires moving the
  job queue and rate limiter out of process).
- TLS termination inside the application (AD-13 delegates it to the reverse proxy).
- Private or per-repository-visibility repositories (AD-16 makes all read access universal).
- AGPL-style network-use copyleft (GPL-3 was adopted, not AGPL-3 — see §14.1).

**Open questions:**

*None outstanding.* Every decision above is settled; the next step is scaffolding and M1.
