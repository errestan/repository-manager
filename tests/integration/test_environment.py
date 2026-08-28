"""The integration job must actually have the services and tools it claims.

Every test in :mod:`tests.integration.test_ldap_directory`,
:mod:`tests.integration.test_apt_client` and
:mod:`tests.integration.test_dnf_client` skips when what it needs is absent,
which is right on a developer's machine and dangerous in CI: a typo in the
job's environment or a dropped package from its install list would skip the lot
and still report success.  That is precisely what happened once -- fifteen
directory tests skipped and the job went green -- so this module sits outside
those skips and makes the omission loud where it matters.
"""

from __future__ import annotations

import os
import shutil

import pytest

pytestmark = pytest.mark.integration

#: Set by GitHub Actions, and by most other CI systems.
IN_CI = os.environ.get("CI") == "true"

in_ci_only = pytest.mark.skipif(not IN_CI, reason="only CI promises these")

REQUIRED_FOR_LDAP = (
    "REPOMAN_LDAP_URL",
    "REPOMAN_LDAP_BIND_DN",
    "REPOMAN_LDAP_BIND_PASSWORD",
    "REPOMAN_LDAP_USER_BASE_DN",
)

#: Every external binary the integration suite verifies a repository against,
#: and what it would silently stop proving if it went missing.
REQUIRED_BINARIES = {
    "apt-get": "APT metadata would never be read by apt",
    "apt-cache": "APT package resolution would never be checked",
    "dpkg-deb": "the .deb fixtures could not be inspected",
    "gpg": "no signature would be produced or verified",
    "createrepo_c": "RPM metadata would never be generated",
    "dnf": "RPM metadata would never be read by dnf",
    "rpmbuild": "the .rpm fixtures would fall back to nothing",
}


@in_ci_only
def test_ci_configures_the_directory_the_ldap_tests_need() -> None:
    missing = [name for name in REQUIRED_FOR_LDAP if not os.environ.get(name)]
    assert not missing, (
        f"the integration job is missing {', '.join(missing)}, so every directory "
        "test would skip and the job would pass without exercising authentication"
    )


@in_ci_only
@pytest.mark.parametrize(("binary", "consequence"), sorted(REQUIRED_BINARIES.items()))
def test_ci_installs_the_tools_the_format_tests_need(binary: str, consequence: str) -> None:
    """One test per binary, so the failure names the package rather than a list."""
    found = shutil.which(binary) or (binary == "dnf" and shutil.which("dnf5"))
    assert found, (
        f"{binary} is not installed in the integration job, so {consequence} -- and the "
        "tests that would have proved it are skipping silently"
    )
