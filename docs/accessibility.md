# Accessibility

**Target: WCAG 2.2 Level AA** (specification.md §11), verified rather than asserted.

This document records what has actually been checked, by what, and — just as importantly —
what has not. It is meant to be updated per release, and to be honest enough that somebody
relying on it can tell the difference between "tested" and "believed".

## Status

| | |
|---|---|
| Standard | WCAG 2.2 Level AA |
| Automated conformance | ✅ Passing — `axe-core` over every page, both themes, both mount points, on every commit |
| Structural guarantees | ✅ Enforced by tests (below) |
| Manual screen-reader pass | ❌ **Not yet performed.** See [Outstanding](#outstanding) |
| Last updated | M6 |

The honest summary: the machine-checkable parts of AA are checked continuously and pass. The
parts that need a person listening to a screen reader have not been done, so this is not yet
a conformance claim — it is a statement of what the tests cover.

## What is checked automatically

Every page is loaded in a real browser (Chromium via Playwright) and audited with
`axe-core`. This runs in CI on every commit, twice: once with the application mounted at `/`
and once behind a proxy at `/repoman/`, because prefix handling has broken links before and
a link that 404s is an accessibility failure like any other.

Pages covered:

- The repository list, a repository overview, a package list, the signing keys page, the
  login page and the API reference — anonymous.
- Upload, distributions, variants, repository creation, jobs, a job detail, the audit log,
  the tokens page, repository settings and the deregistration page — signed in.

Beyond `axe-core`, these are asserted directly because they are the failures automated
auditing is worst at catching:

| Property | How it is checked |
|---|---|
| The skip link is the first focusable element and reaches `<main>` | Focus is moved by keyboard and the landing element read back |
| Every page has exactly one `<h1>` | Counted per page |
| No positive `tabindex` anywhere | Attribute values read from the rendered DOM |
| Every input has a label | Every `input`/`select`/`textarea` matched to a `<label>` |
| Errors are summarised, linked and announced | A form is deliberately rejected and the summary's `role`, focusability and links are checked |
| `prefers-reduced-motion` is honoured | Computed transition durations read back from a reduced-motion browser context |
| Colour is not the only carrier | Job and audit state are asserted to contain words, not just classes |
| Every flow works without JavaScript | The whole suite runs a second time in a browser with JavaScript disabled |
| One-time secrets interrupt rather than whisper | The new-token region is asserted to be `role="alert"` |
| Destructive buttons name their target | "Remove" buttons are located by their full accessible name |
| No request 404s while browsing | Every response status collected during a crawl |

The last one matters more than it sounds: the application is served under a configurable
sub-path, and a stylesheet that fails to load takes the entire visual design — including
every contrast ratio — with it.

## Design decisions that follow from the target

**No JavaScript is required for anything.** HTMX is progressive enhancement; every form
submits and every page renders without it. This is why forms re-render server-side with
their errors rather than validating in the browser, and why the error summary is placed
first in the reading order — with no script, nothing can move focus for the user.

**The API reference is rendered by this application** rather than by Swagger UI. Swagger UI
would not load at all under the Content-Security-Policy, and its accessibility is not what
a WCAG 2.2 AA commitment wants even where it does load.

**Long operations report progress as text.** A regeneration job shows a percentage and a log,
not only a spinner, and the job page works with a manual refresh control.

**The theme is decided server-side** from a cookie, so the first paint is already correct.
A client-side toggle would flash the wrong colours before it ran, which is both unpleasant
and, for some vestibular conditions, worse than unpleasant.

## Outstanding

**A manual screen-reader pass has not been performed.** §11 asks for one with Orca on Linux
and NVDA on Windows, recorded here, per release. It has not been done, and nothing in the
automated suite substitutes for it: `axe-core` finds roughly a third of real barriers, and
the ones it misses — a reading order that is technically valid but incomprehensible, an
announcement that is correct but arrives at the wrong moment, a label that is present but
unhelpful — are exactly the ones that decide whether the interface is usable.

Until that pass is done and recorded here, this project should be described as *built to*
WCAG 2.2 AA and *automatically verified against the machine-checkable subset*, not as
conformant.

Specific things a manual pass should look at first, because they are where this interface
does something a little unusual:

1. **The one-time API token.** It is announced with `role="alert"` and cannot be recovered
   if missed. Does it interrupt clearly, and is the token itself readable character by
   character in a screen reader's spelling mode?
2. **The deregistration flow.** The purge warning is a `role="note"` and the confirmation
   field only matters when a checkbox is ticked. Is the relationship between the two
   apparent without sight?
3. **The retention preview table.** It lists packages that a button is about to delete. Is
   the connection between the table and the button clear?
4. **Job progress.** Does a job moving from queued to running to succeeded announce itself
   usefully, or does it either say nothing or say too much?
5. **The upload form's target select.** It is one flat list of `distribution / component`
   pairs rather than two dependent selects. Is that easier or harder to operate by voice?

## Reporting a problem

Accessibility bugs are ordinary bugs and are welcome as issues. A description of what you
were trying to do, what your assistive technology announced, and what you expected is more
useful than a WCAG success-criterion number — though both are welcome.
