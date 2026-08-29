# Repository Manager

A web interface for managing the contents of Linux package repositories (APT and RPM).

Create repositories, upload and remove packages, and have the indices and GPG signatures
regenerated correctly — without hand-running `apt-ftparchive` or `createrepo_c`.

> **Status: 0.1.0, unreleased.** Every milestone in
> ([`specification.md`](specification.md)) is implemented: configuration, migrations, the
> accessible layout and sub-path handling (M1); APT repositories, signing keys, uploads and
> index generation verified against a real `apt-get` (M2); LDAP login, sessions, CSRF, roles
> and the audit log (M3); RPM repositories with variants and `repomd.xml` signing, verified
> against a real `dnf` (M4); scoped API tokens, a JSON REST API and OpenAPI (M5); and
> retention, rescan, rate limiting, metrics and the release pipeline (M6).
>
> It has not been run in anger anywhere, and one thing the specification asks for has not
> been done: a manual screen-reader pass (see
> [`docs/accessibility.md`](docs/accessibility.md)). Read
> [the changelog's known limitations](CHANGELOG.md) before deploying it.

## Features

- **APT and RPM** repositories, with multiple distributions/components/architectures (APT)
  or variants (RPM) per repository.
- **Correct metadata, always** — indices and signatures regenerate on every change, in a
  locked background job so concurrent edits cannot corrupt them.
- **GPG signing** of repository metadata, with keys imported or generated in-app.
- **LDAP authentication** with group-mapped roles. Reading is open to everyone; changes are
  authenticated and audited.
- **Scoped API tokens** so CI can publish packages without an interactive login — limited to
  chosen repositories, expiring by default, and never able to do more than the account that
  minted them. See [Publishing from CI](docs/api.md).
- **Retention** — keep every version, or the newest few per package, per architecture, per
  target, pruned using each format's own version ordering.
- **Drift detection** — a rescan that re-hashes what is on disk, compares it against the
  database, and reports what differs without changing anything.
- **Operable** — an append-only audit log, background jobs with progress and logs, health
  probes, optional Prometheus metrics, and in-process rate limiting.
- **Accessible** — built to WCAG 2.2 AA and verified with `axe-core` on every commit, works
  without JavaScript, follows your system light/dark preference.

## Requirements

- Python 3.11+
- `gnupg` 2.2+ — for signing repository metadata
- `createrepo_c` — for RPM repositories only; APT works without it

Neither system dependency can be installed by pip, which is why a container image is
provided.

## Installation

```sh
pip install repository-manager
```

> Not yet published to PyPI. Until then, install from a checkout with `uv sync`.

### Running it

Six settings have no default and must be supplied:

```sh
export REPOMAN_ALLOWED_ROOTS=/srv/repositories   # colon-separated, like PATH
export REPOMAN_PUBLIC_URL=https://packages.example.com
export REPOMAN_SECRET_KEY="$(openssl rand -hex 32)"

# Where accounts come from. There is no local user store, so an instance with no
# directory has no way for anyone to sign in.
export REPOMAN_LDAP_URL=ldaps://directory.example.com
export REPOMAN_LDAP_GROUP_ADMIN='cn=repo-admins,ou=groups,dc=example,dc=com'
export REPOMAN_LDAP_GROUP_MAINTAINER='cn=repo-maintainers,ou=groups,dc=example,dc=com'

repository-manager check-config   # validate and print the resolved settings
repository-manager db upgrade     # create or migrate the database
repository-manager serve          # start the application
```

Search-then-bind is the default and also needs `REPOMAN_LDAP_USER_BASE_DN` (plus
`REPOMAN_LDAP_BIND_DN`/`_PASSWORD` if the directory does not allow anonymous search).
See [Authentication](docs/deployment.md#authentication) for direct bind, group resolution
and session lifetimes.

`ldap://` without StartTLS is refused: the bind password would cross the network in clear
text. `REPOMAN_LDAP_ALLOW_INSECURE=true` overrides that for a local development directory,
and is itself refused when `REPOMAN_ENV=production`.

Migrations are never applied implicitly on start; `db upgrade` is always an explicit step.

To mount under a sub-path, set `REPOMAN_ROOT_PATH=/repoman` and make `REPOMAN_PUBLIC_URL`
end with the same prefix — the two must agree, and startup fails if they do not.

If a reverse proxy sits in front, list it in `REPOMAN_TRUSTED_PROXIES` (addresses or CIDRs).
This has **no default**: with it unset, every `X-Forwarded-*` header is ignored so that no
client can spoof its source address.

Or run the container:

```sh
docker run -p 8000:8000 \
  -v /srv/repositories:/srv/repositories \
  -v repoman-data:/var/lib/repoman \
  ghcr.io/errestan/repository-manager:latest
```

## Publishing from a pipeline

```sh
curl --fail-with-body --silent \
  --header "Authorization: Bearer $REPOMAN_TOKEN" \
  --form file=@build/hello_1.0-1_amd64.deb \
  --form distribution=bookworm \
  --form component=main \
  "$REPOMAN_URL/api/v1/repositories/internal/packages"
```

The response carries the package it published and the id of the job rebuilding the
repository metadata, so a pipeline that needs the package to be installable can wait rather
than guess. [`docs/api.md`](docs/api.md) covers tokens, polling, error handling and
ready-made GitHub Actions and GitLab CI steps; each instance also serves its own reference
at `/api/docs` and an OpenAPI schema at `/api/v1/openapi.json`.

## Deployment shape

The application does **not** serve repositories to `apt`/`dnf` clients and does **not**
terminate TLS. Put nginx (or Apache) in front of it: the proxy serves the repository tree as
static files and handles certificates, while this application manages what is in that tree.
It runs happily at a domain root or at a sub-path such as `https://packages.example.com/manage/`.

See [`specification.md`](specification.md) §4.4 and §13.5 for reference configuration, and
[`docs/deployment.md`](docs/deployment.md) for a working nginx file, authentication setup,
retention, rate limiting and metrics.

## Licence

This project is licensed **GPL-3.0-or-later** — see [`LICENSE`](LICENSE).

**That licence covers this application's source only.** Packages you upload into repositories
managed by this application are entirely unaffected: they keep their own licences, this
application asserts no rights over them, and uploads are never inspected or filtered on
licence grounds. Hosting proprietary packages is fine.

(The GPL follows from `python-debian`, which this application imports and which is
GPL-2.0-or-later. See §14.1 of the specification for the full reasoning.)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).
