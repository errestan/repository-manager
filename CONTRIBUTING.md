# Contributing

## Setup

```sh
# System dependencies (Debian/Ubuntu)
sudo apt-get install -y createrepo-c gnupg dpkg-dev apt-utils

# System dependencies (Fedora)
sudo dnf install -y createrepo_c gnupg2 dpkg-dev

# Project
uv sync --all-extras --dev
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

`createrepo_c` is only needed for RPM work; `dpkg-dev`/`apt-utils` are only needed to run the
integration tests that verify generated repositories against real clients.

## Running checks

```sh
uv run pre-commit run --all-files     # everything CI's lint job runs
uv run pytest -m "not integration and not e2e"
uv run pytest -m integration          # needs the system dependencies above
uv run pytest -m e2e                  # needs: uv run playwright install chromium
```

CI runs the same pre-commit hook set, so a clean local run means a clean lint job.

## Conventions

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/); the
  `commit-msg` hook enforces it and the changelog is generated from it.
- **Formatting and linting** are `ruff`'s job — don't hand-format, and don't argue with it.
- **Typing**: `mypy` runs over everything; the metadata-generation and permission modules are
  `strict`, because a type error there is a correctness or security bug rather than a
  nuisance.
- **Migrations** must leave exactly one Alembic head; a hook checks this.
- **Never write root-relative URLs in templates.** Use `url_for()`. The application must work
  when mounted at a sub-path, and a hook plus a dedicated CI run enforce it.

## Accessibility

WCAG 2.2 AA is a requirement, not an aspiration. Every UI pull request should:

- work with JavaScript disabled,
- be operable by keyboard alone with a visible focus indicator,
- pass the `axe-core` checks in the e2e suite,
- and keep contrast ≥ 4.5:1 in **both** light and dark themes.

The PR template has a checklist item for this.

## Dependency licences

This project is GPL-3.0-or-later, so inbound licensing is permissive — MIT, BSD, Apache-2.0,
LGPL and GPL-3 are all fine. The one thing that cannot be accepted is a **GPL-2-only**
dependency, which is incompatible with GPL-3. `scripts/check_licences.py` runs in CI and will
fail the build; please don't work around it without discussion.
