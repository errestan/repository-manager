"""The integration job must actually have the services it claims.

Every test in :mod:`tests.test_ldap_directory` skips when no directory is
configured, which is right locally and dangerous in CI: a typo in the job's
environment would skip all fifteen and still report success.  This module sits
outside that skip so the omission is loud where it matters.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.integration

#: Set by GitHub Actions, and by most other CI systems.
IN_CI = os.environ.get("CI") == "true"

REQUIRED_FOR_LDAP = (
    "REPOMAN_LDAP_URL",
    "REPOMAN_LDAP_BIND_DN",
    "REPOMAN_LDAP_BIND_PASSWORD",
    "REPOMAN_LDAP_USER_BASE_DN",
)


@pytest.mark.skipif(not IN_CI, reason="only CI promises a directory")
def test_ci_configures_the_directory_the_ldap_tests_need() -> None:
    missing = [name for name in REQUIRED_FOR_LDAP if not os.environ.get(name)]
    assert not missing, (
        f"the integration job is missing {', '.join(missing)}, so every directory "
        "test would skip and the job would pass without exercising authentication"
    )
