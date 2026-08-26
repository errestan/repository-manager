## What and why

<!-- What changes, and what problem it solves. Link the issue if there is one. -->

## Checklist

- [ ] Tests cover the change (and `pytest -m "not integration and not e2e"` passes)
- [ ] `pre-commit run --all-files` is clean
- [ ] Docs / `specification.md` updated if behaviour or a decision changed
- [ ] No new dependency, or the new dependency is GPL-3-compatible (not GPL-2-only)

### If this touches the UI

- [ ] Works with JavaScript disabled
- [ ] Keyboard operable with a visible focus indicator
- [ ] Contrast ≥ 4.5:1 in both light and dark themes
- [ ] No root-relative URLs — all links built with `url_for()`

### If this touches repository metadata generation

- [ ] Verified against a real client (`apt-get update` / `dnf makecache`), not just unit tests
