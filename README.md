# Repository Manager

A web interface for managing the contents of Linux package repositories (APT and RPM).

Create repositories, upload and remove packages, and have the indices and GPG signatures
regenerated correctly — without hand-running `apt-ftparchive` or `createrepo_c`.

> **Status: pre-alpha.** The specification is complete
> ([`specification.md`](specification.md)). **M1 (skeleton) is done**: configuration,
> database and migrations, the accessible layout and theme, health probes, the anonymous
> repository list, and sub-path/proxy handling. There is no authentication and no way to
> upload a package yet — those are M2 and M3. Not usable in production.

## Features

- **APT and RPM** repositories, with multiple distributions/components/architectures (APT)
  or variants (RPM) per repository.
- **Correct metadata, always** — indices and signatures regenerate on every change, in a
  locked background job so concurrent edits cannot corrupt them.
- **GPG signing** of repository metadata, with keys imported or generated in-app.
- **LDAP authentication** with group-mapped roles. Reading is open to everyone; changes are
  authenticated and audited.
- **Scoped API tokens** so CI can publish packages without an interactive login.
- **Accessible** — WCAG 2.2 AA, screen-reader tested, works without JavaScript, follows your
  system light/dark preference.

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

Three settings have no default and must be supplied:

```sh
export REPOMAN_ALLOWED_ROOTS=/srv/repositories   # colon-separated, like PATH
export REPOMAN_PUBLIC_URL=https://packages.example.com
export REPOMAN_SECRET_KEY="$(openssl rand -hex 32)"

repository-manager check-config   # validate and print the resolved settings
repository-manager db upgrade     # create or migrate the database
repository-manager serve          # start the application
```

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

## Deployment shape

The application does **not** serve repositories to `apt`/`dnf` clients and does **not**
terminate TLS. Put nginx (or Apache) in front of it: the proxy serves the repository tree as
static files and handles certificates, while this application manages what is in that tree.
It runs happily at a domain root or at a sub-path such as `https://packages.example.com/manage/`.

See [`specification.md`](specification.md) §4.4 and §13.5 for reference configuration.

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
