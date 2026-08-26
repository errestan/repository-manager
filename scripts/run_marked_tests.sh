#!/usr/bin/env bash
#
# Run the tests carrying a given pytest marker, tolerating the marker having no
# tests yet.
#
# pytest exits 5 when it collects nothing, which is indistinguishable from a
# real failure to CI.  The `integration` and `e2e` markers are declared in
# pyproject.toml from the start but are not populated until M2 and M4
# respectively (specification.md 13.6), so those jobs would fail on every commit
# until then.
#
# This deliberately does NOT swallow anything else: a collection error, an
# import failure or a genuine test failure all still fail the job.  Once the
# milestone lands and tests exist, exit 5 stops occurring and this becomes a
# transparent pass-through -- at which point the guard can be dropped.
#
# Usage: scripts/run_marked_tests.sh <marker> <milestone> [extra pytest args...]

set -uo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <marker> <milestone> [pytest args...]" >&2
    exit 2
fi

marker="$1"
milestone="$2"
shift 2

uv run pytest -m "${marker}" -v "$@"
rc=$?

if [ "${rc}" -eq 5 ]; then
    echo "::notice title=No ${marker} tests yet::The '${marker}' marker matched no"\
         "tests. These arrive in ${milestone} (specification.md 13.6); treating as a pass."
    exit 0
fi

exit "${rc}"
