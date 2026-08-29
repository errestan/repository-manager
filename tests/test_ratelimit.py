"""Token buckets and login backoff (specification.md 10.3).

Driven with an injected clock rather than ``sleep``: a limiter whose tests wait
for real seconds is a limiter nobody dares give a realistic lockout.
"""

from __future__ import annotations

import pytest

from repository_manager.security.ratelimit import (
    FailureBackoff,
    Limits,
    TokenBucket,
)


class Clock:
    """A monotonic clock a test advances by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


# ------------------------------------------------------------------ token bucket


def test_a_burst_within_the_capacity_is_admitted(clock: Clock) -> None:
    """A CI job publishing several packages in a row is not abuse."""
    bucket = TokenBucket(5, 1.0, clock=clock)
    assert all(bucket.check("ip:one").allowed for _ in range(5))


def test_the_request_past_the_capacity_is_refused(clock: Clock) -> None:
    bucket = TokenBucket(3, 1.0, clock=clock)
    for _ in range(3):
        bucket.check("ip:one")
    decision = bucket.check("ip:one")
    assert not decision.allowed
    assert decision.retry_after == pytest.approx(1.0)


def test_the_allowance_refills_over_time(clock: Clock) -> None:
    bucket = TokenBucket(2, 1.0, clock=clock)
    bucket.check("ip:one")
    bucket.check("ip:one")
    assert not bucket.check("ip:one").allowed

    clock.advance(1.0)
    assert bucket.check("ip:one").allowed


def test_the_allowance_never_exceeds_the_capacity(clock: Clock) -> None:
    """An idle hour must not buy an hour's worth of burst."""
    bucket = TokenBucket(2, 1.0, clock=clock)
    bucket.check("ip:one")
    clock.advance(3600)
    assert bucket.check("ip:one").allowed
    assert bucket.check("ip:one").allowed
    assert not bucket.check("ip:one").allowed


def test_keys_do_not_share_an_allowance(clock: Clock) -> None:
    bucket = TokenBucket(1, 1.0, clock=clock)
    assert bucket.check("ip:one").allowed
    assert bucket.check("ip:two").allowed
    assert not bucket.check("ip:one").allowed


def test_eviction_discards_refilled_keys_before_live_ones(clock: Clock) -> None:
    """Given a choice, forget the keys whose state means nothing.

    Only a choice: under sustained pressure from more distinct keys than the
    ceiling allows, everything is eventually evicted -- that is what a bound
    *is*. What this asserts is the preference, which is the part that decides
    whether a throttled caller keeps being throttled while idle keys pile up.
    """
    bucket = TokenBucket(2, 1.0, clock=clock, max_keys=10)
    for index in range(9):
        bucket.check(f"ip:idle-{index}")

    # Long enough that every idle key is back at capacity and so carries no
    # state worth keeping.
    clock.advance(100.0)

    for _ in range(3):
        bucket.check("ip:throttled")
    assert not bucket.check("ip:throttled").allowed

    # One key over the ceiling: the eviction it triggers has nine refilled
    # candidates to choose from and no reason to take the live one.
    bucket.check("ip:newcomer")

    assert bucket.tracked <= 10
    assert not bucket.check("ip:throttled").allowed


def test_the_key_space_is_bounded(clock: Clock) -> None:
    """The key is chosen by the caller, so it must not be able to grow forever."""
    bucket = TokenBucket(2, 0.01, clock=clock, max_keys=50)
    for index in range(500):
        bucket.check(f"ip:{index}")
    assert bucket.tracked <= 50


def test_retry_after_is_never_reported_as_zero(clock: Clock) -> None:
    bucket = TokenBucket(1, 1000.0, clock=clock)
    bucket.check("ip:one")
    decision = bucket.check("ip:one")
    assert not decision.allowed
    assert decision.retry_after < 1
    assert decision.retry_after_seconds == 1


# ------------------------------------------------------------------ login backoff


def test_a_first_attempt_is_never_delayed(clock: Clock) -> None:
    backoff = FailureBackoff(clock=clock)
    assert backoff.check("user:mo").allowed


def test_the_first_few_failures_cost_nothing(clock: Clock) -> None:
    """A typo corrected on the next try must not be told to wait."""
    backoff = FailureBackoff(base_delay=1.0, free_attempts=2, max_attempts=10, clock=clock)
    for _ in range(2):
        backoff.record_failure("user:mo")
    assert backoff.check("user:mo").allowed


def test_each_failure_past_the_grace_costs_more_than_the_last(clock: Clock) -> None:
    backoff = FailureBackoff(base_delay=1.0, free_attempts=2, max_attempts=10, clock=clock)
    waits = []
    for _ in range(6):
        waits.append(backoff.record_failure("user:mo").retry_after)
    assert waits == pytest.approx([0.0, 0.0, 1.0, 2.0, 4.0, 8.0])


def test_the_delay_has_to_actually_pass(clock: Clock) -> None:
    backoff = FailureBackoff(base_delay=2.0, free_attempts=0, clock=clock)
    backoff.record_failure("user:mo")
    assert not backoff.check("user:mo").allowed
    clock.advance(2.0)
    assert backoff.check("user:mo").allowed


def test_enough_failures_become_a_lockout(clock: Clock) -> None:
    backoff = FailureBackoff(base_delay=1.0, max_attempts=3, lockout=900.0, clock=clock)
    for _ in range(3):
        backoff.record_failure("user:mo")
    decision = backoff.check("user:mo")
    assert not decision.allowed
    assert decision.retry_after == pytest.approx(900.0)


def test_the_lockout_ends(clock: Clock) -> None:
    backoff = FailureBackoff(max_attempts=2, lockout=60.0, clock=clock)
    backoff.record_failure("user:mo")
    backoff.record_failure("user:mo")
    clock.advance(60.0)
    assert backoff.check("user:mo").allowed


def test_success_clears_the_record(clock: Clock) -> None:
    """Only *consecutive* failures count: a slip this morning is not a debt."""
    backoff = FailureBackoff(base_delay=5.0, free_attempts=0, clock=clock)
    backoff.record_failure("user:mo")
    backoff.reset("user:mo")
    assert backoff.check("user:mo").allowed


def test_failures_are_tracked_per_key(clock: Clock) -> None:
    backoff = FailureBackoff(base_delay=5.0, free_attempts=0, clock=clock)
    backoff.record_failure("user:mo")
    assert backoff.check("user:ada").allowed


def test_the_failure_key_space_is_bounded(clock: Clock) -> None:
    backoff = FailureBackoff(clock=clock, max_keys=50)
    for index in range(500):
        backoff.record_failure(f"user:{index}")
    assert backoff.tracked <= 50


# ------------------------------------------------------------------ the facade


def test_a_locked_out_username_cannot_be_escaped_by_moving_address(clock: Clock) -> None:
    """A botnet spreading across addresses to attack one account (10.3)."""
    limits = Limits(login_max_attempts=2, login_lockout_seconds=60, clock=clock)
    for address in ("10.0.0.1", "10.0.0.2"):
        limits.login_failed(username="mo", client=address)
    assert not limits.login_allowed(username="mo", client="10.0.0.99").allowed


def test_a_locked_out_address_cannot_be_escaped_by_changing_username(clock: Clock) -> None:
    """One address spraying many accounts (10.3)."""
    limits = Limits(login_max_attempts=2, login_lockout_seconds=60, clock=clock)
    for username in ("mo", "ada"):
        limits.login_failed(username=username, client="10.0.0.1")
    assert not limits.login_allowed(username="someone-else", client="10.0.0.1").allowed


def test_an_unrelated_account_from_elsewhere_is_unaffected(clock: Clock) -> None:
    limits = Limits(login_max_attempts=2, login_lockout_seconds=60, clock=clock)
    for _ in range(3):
        limits.login_failed(username="mo", client="10.0.0.1")
    assert limits.login_allowed(username="ada", client="10.0.0.2").allowed


def test_signing_in_clears_both_keys(clock: Clock) -> None:
    limits = Limits(login_max_attempts=5, clock=clock)
    limits.login_failed(username="mo", client="10.0.0.1")
    limits.login_succeeded(username="mo", client="10.0.0.1")
    assert limits.login_allowed(username="mo", client="10.0.0.1").allowed
    assert limits.login_allowed(username="ada", client="10.0.0.1").allowed


def test_uploads_and_rejected_credentials_have_separate_allowances(clock: Clock) -> None:
    """A guesser must not be able to exhaust a pipeline's budget, or the reverse."""
    limits = Limits(upload_burst=1, credential_burst=1, clock=clock)

    assert limits.credential_failure_allowed(client="10.0.0.1", prefix="rmt_a").allowed
    assert not limits.credential_failure_allowed(client="10.0.0.1", prefix="rmt_a").allowed

    # Same address, exhausted on credentials, and still able to publish.
    assert limits.upload_allowed(client="10.0.0.1", actor="uid=mo").allowed


def test_switching_the_limiter_off_admits_everything(clock: Clock) -> None:
    limits = Limits(enabled=False, login_max_attempts=1, upload_burst=1, clock=clock)
    for _ in range(50):
        limits.login_failed(username="mo", client="10.0.0.1")
        assert limits.login_allowed(username="mo", client="10.0.0.1").allowed
        assert limits.upload_allowed(client="10.0.0.1", actor="uid=mo").allowed
