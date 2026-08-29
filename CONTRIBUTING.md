# Contributing

## Setup

```sh
# System dependencies (Debian/Ubuntu)
sudo apt-get install -y createrepo-c gnupg zstd dpkg-dev apt-utils

# System dependencies (Fedora)
sudo dnf install -y createrepo_c gnupg2 zstd apt

# Project
uv sync --all-extras --all-groups
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

`gnupg` is the only one the unit tests need — repository metadata is signed with it, and
there is no pure-Python substitute worth trusting. `apt` (`apt-get`/`apt-cache`) is what the
integration tests use to judge generated repositories; `createrepo_c` is the same for RPM,
which arrives in M4. `zstd` is needed only to read packages whose control member dpkg
compressed with it, which python-debian handles by shelling out to `unzstd`.

Test packages are built in pure Python (`tests/support/debs.py`), so `dpkg-deb` is not
required to run the suite.

Note `--all-groups` rather than `--dev`: the `e2e` dependency group is separate, and
`--dev` silently omits it.

## Running checks

```sh
uv run pre-commit run --all-files     # everything CI's lint job runs
uv run pytest -m "not integration and not e2e"
uv run pytest -m integration          # needs apt-get/apt-cache on PATH
uv run pytest -m e2e                  # needs: uv run playwright install --with-deps chromium
REPOMAN_ROOT_PATH=/repoman uv run pytest -m e2e   # the same suite under a sub-path (AD-14)
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

## Releasing

The version lives in one place, `src/repository_manager/__about__.py`, and everything else
is checked against it: the release workflow refuses a tag that does not match, and
`tests/test_readme.py` fails if the README badge or the changelog fall behind.

1. Bump `__version__`.
2. Move the `Unreleased` changelog entries under a new `## [x.y.z] — YYYY-MM-DD` heading,
   and update the link definitions at the bottom.
3. Update the version badge at the top of `README.md`. Once the project is on PyPI this
   becomes the self-updating badge instead, and stops needing step 3:

   ```markdown
   [![PyPI](https://img.shields.io/pypi/v/repository-manager)](https://pypi.org/project/repository-manager/)
   ```

4. Commit, then tag: `git tag -s vX.Y.Z && git push --tags`.

The tag triggers `release.yml`, which builds the distributions, publishes to PyPI through
Trusted Publishing (a protected environment, so it waits for a human), and creates the
GitHub Release quoting that version's changelog section. `container.yml` publishes the
image to GHCR on the same tag.

**Pushing a tag publishes.** There is no dry run past that point — PyPI does not allow a
version to be replaced.
