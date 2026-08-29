"""In-process rate limiting (specification.md 10.3).

Two different problems, so two different mechanisms.

A **token bucket** bounds a rate that is legitimate in bursts: a CI job that
publishes twenty packages in a row is not abuse, and a limiter that refused the
third one would be worse than none.  Capacity is the burst; the refill rate is
the sustained ceiling.

**Exponential backoff with a lockout** is for guessing.  A password guesser is
not trying to go fast, it is trying to go *often*, and the right answer is to
make each successive attempt cost more and then to stop answering for a while.
Applied per username and per source address at once, because either alone is
evadable: a botnet spreads across addresses to attack one account, and one
address sprays many accounts.

Both are **per instance**, not cluster-wide, which the deployment
documentation states plainly.  Sharing counters between processes needs a store
they all reach, and a Redis dependency for this would be a large piece of
operational surface bought for a modest gain — two instances behind a proxy
mean an attacker gets two buckets, not unlimited ones.

The state is bounded.  A limiter keyed by client address is keyed by something
an attacker chooses, so an unbounded dictionary would be the denial of service
it was added to prevent.  A bucket that has refilled completely carries no
information and is dropped; if that is not enough, the least recently touched
entries go.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

#: Failures allowed before backoff starts delaying anything.  A person who
#: mistypes a password and immediately retries should not be told to wait: the
#: delay is aimed at a program trying thousands of guesses, and two free
#: attempts cost such a program nothing while sparing everyone else the friction.
FREE_ATTEMPTS = 2

#: Ceiling on tracked keys per limiter.  Comfortably more than any real
#: deployment sees and small enough that the worst case is a few megabytes.
MAX_TRACKED_KEYS = 10_000

Clock = Callable[[], float]


@dataclass(frozen=True)
class Decision:
    """Whether to serve this request, and what to tell the caller if not."""

    allowed: bool
    #: Seconds until the caller may reasonably try again; the ``Retry-After``
    #: header and the message a person is shown are both built from it.
    retry_after: float = 0.0

    @property
    def retry_after_seconds(self) -> int:
        """Rounded up, because answering "retry after 0 seconds" is a lie."""
        return max(1, int(self.retry_after + 0.999))


ALLOWED = Decision(allowed=True)


@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBucket:
    """A rate with an allowance for bursts, keyed by whatever the caller passes.

    ``capacity`` requests may be made at once; after that they are admitted at
    ``per_second``.  A key that has been idle long enough to refill completely
    is indistinguishable from one that has never been seen, which is what makes
    the state bounded without any sweeping timer.
    """

    def __init__(
        self,
        capacity: float,
        per_second: float,
        *,
        clock: Clock = time.monotonic,
        max_keys: int = MAX_TRACKED_KEYS,
    ) -> None:
        if capacity <= 0 or per_second <= 0:  # pragma: no cover - defensive
            raise ValueError("capacity and per_second must both be positive")
        self.capacity = float(capacity)
        self.per_second = float(per_second)
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: dict[str, _Bucket] = {}

    def _refilled(self, key: str, now: float) -> _Bucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            return _Bucket(tokens=self.capacity, updated=now)
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.per_second)
        bucket.updated = now
        return bucket

    def check(self, key: str, *, cost: float = 1.0) -> Decision:
        """Consume one unit if there is one, and say so.

        Consumes on the way past rather than offering a separate ``consume``:
        a check that does not consume is a check every caller has to remember
        to follow up, and forgetting is silent.
        """
        now = self._clock()
        bucket = self._refilled(key, now)
        if bucket.tokens >= cost:
            bucket.tokens -= cost
            self._remember(key, bucket, now)
            return ALLOWED
        wait = (cost - bucket.tokens) / self.per_second
        self._remember(key, bucket, now)
        return Decision(allowed=False, retry_after=wait)

    def _remember(self, key: str, bucket: _Bucket, now: float) -> None:
        if bucket.tokens >= self.capacity:
            # Full: identical to never having been seen, so keep nothing.
            self._buckets.pop(key, None)
            return
        self._buckets[key] = bucket
        if len(self._buckets) > self._max_keys:
            self._evict(now)

    def _evict(self, now: float) -> None:
        """Drop a tenth of the keys, least recently touched first."""
        del now
        surplus = max(1, len(self._buckets) // 10)
        for stale in sorted(self._buckets, key=lambda name: self._buckets[name].updated)[:surplus]:
            del self._buckets[stale]

    def forget(self, key: str) -> None:
        self._buckets.pop(key, None)

    @property
    def tracked(self) -> int:
        return len(self._buckets)


@dataclass
class _Failures:
    count: int = 0
    #: When the next attempt becomes permissible.
    blocked_until: float = 0.0
    updated: float = field(default=0.0)


class FailureBackoff:
    """Consecutive-failure tracking with exponential delay and a lockout (10.3).

    Successes cost nothing and clear the record, so a person who mistypes a
    password twice and then gets it right is not slowed down at all the next
    day.  Only failures accumulate, and only consecutively.
    """

    def __init__(
        self,
        *,
        base_delay: float = 1.0,
        free_attempts: int = FREE_ATTEMPTS,
        max_attempts: int = 5,
        lockout: float = 900.0,
        clock: Clock = time.monotonic,
        max_keys: int = MAX_TRACKED_KEYS,
    ) -> None:
        self.base_delay = base_delay
        self.free_attempts = free_attempts
        self.max_attempts = max_attempts
        self.lockout = lockout
        self._clock = clock
        self._max_keys = max_keys
        self._failures: dict[str, _Failures] = {}

    def check(self, key: str) -> Decision:
        """Whether this key may attempt now.  Does not itself count anything."""
        record = self._failures.get(key)
        if record is None:
            return ALLOWED
        now = self._clock()
        if now >= record.blocked_until:
            return ALLOWED
        return Decision(allowed=False, retry_after=record.blocked_until - now)

    def record_failure(self, key: str) -> Decision:
        """Count a failure and return when this key may try again.

        The first :data:`FREE_ATTEMPTS` are counted without any delay, so the
        common case -- a typo, corrected on the next try -- costs nothing.
        """
        now = self._clock()
        record = self._failures.get(key) or _Failures()
        record.count += 1
        record.updated = now
        if record.count >= self.max_attempts:
            # Past the threshold: stop answering for a while rather than
            # continuing to double a delay nobody is waiting out honestly.
            record.blocked_until = now + self.lockout
        elif record.count > self.free_attempts:
            record.blocked_until = now + self.base_delay * (
                2 ** (record.count - self.free_attempts - 1)
            )
        else:
            # Still inside the grace: counted, but not yet slowed.
            record.blocked_until = 0.0
        self._failures[key] = record
        if len(self._failures) > self._max_keys:
            self._evict()
        # Reports the state *after* counting, so a failure inside the grace
        # answers "still allowed, no wait" rather than a negative delay.
        wait = max(0.0, record.blocked_until - now)
        return Decision(allowed=wait <= 0.0, retry_after=wait)

    def reset(self, key: str) -> None:
        """Forget a key's failures, because it just succeeded."""
        self._failures.pop(key, None)

    def _evict(self) -> None:
        """Drop the least recently failed keys, down to nine tenths of the ceiling.

        Unlike the token bucket there is no "carries no information" case to
        prefer here: a record exists only because something failed, and it goes
        on success or by the caller.  This is a bound on memory and nothing
        more, and it favours the oldest because those are closest to having
        served their delay anyway.
        """
        target = max(1, self._max_keys * 9 // 10)
        ordered = sorted(self._failures, key=lambda name: self._failures[name].updated)
        for stale in ordered[: len(self._failures) - target]:
            del self._failures[stale]

    @property
    def tracked(self) -> int:
        return len(self._failures)


class Limits:
    """Every limiter this application applies, built from settings (10.3).

    Held on the application rather than constructed per request -- the counters
    *are* the state -- and switched off wholesale by
    ``REPOMAN_RATE_LIMIT_ENABLED=false``, which is there for a development
    machine and for anyone whose reverse proxy already does this better.
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        login_max_attempts: int = 5,
        login_lockout_seconds: float = 900.0,
        upload_burst: int = 20,
        upload_per_minute: float = 60.0,
        credential_burst: int = 10,
        credential_per_minute: float = 30.0,
        clock: Clock = time.monotonic,
    ) -> None:
        self.enabled = enabled
        self.login = FailureBackoff(
            max_attempts=login_max_attempts, lockout=login_lockout_seconds, clock=clock
        )

        self.uploads = TokenBucket(upload_burst, upload_per_minute / 60.0, clock=clock)
        #: Rejected bearer tokens.  Bounded separately from uploads because a
        #: credential guesser and a busy pipeline are different traffic and
        #: should not be able to exhaust each other's allowance.
        self.credentials = TokenBucket(credential_burst, credential_per_minute / 60.0, clock=clock)

    # -- login (10.3) -----------------------------------------------------

    def login_allowed(self, *, username: str, client: str | None) -> Decision:
        """Whether this login attempt may reach the directory at all.

        Both keys are consulted and the longer wait wins, so an attacker cannot
        escape a locked-out username by changing address, nor a locked-out
        address by changing username.
        """
        if not self.enabled:
            return ALLOWED
        worst = ALLOWED
        for key in self._login_keys(username, client):
            decision = self.login.check(key)
            if not decision.allowed and decision.retry_after > worst.retry_after:
                worst = decision
        return worst

    def login_failed(self, *, username: str, client: str | None) -> None:
        if not self.enabled:
            return
        for key in self._login_keys(username, client):
            self.login.record_failure(key)

    def login_succeeded(self, *, username: str, client: str | None) -> None:
        for key in self._login_keys(username, client):
            self.login.reset(key)

    @staticmethod
    def _login_keys(username: str, client: str | None) -> list[str]:
        keys = [f"user:{username.strip().lower()[:255]}"]
        if client:
            keys.append(f"ip:{client}")
        return keys

    # -- credentials and uploads (10.3) -----------------------------------

    def credential_failure_allowed(self, *, client: str | None, prefix: str = "") -> Decision:
        """Whether to keep answering rejected tokens from this source."""
        if not self.enabled:
            return ALLOWED
        worst = ALLOWED
        for key in (f"ip:{client}" if client else "", f"token:{prefix}" if prefix else ""):
            if not key:
                continue
            decision = self.credentials.check(key)
            if not decision.allowed and decision.retry_after > worst.retry_after:
                worst = decision
        return worst

    def upload_allowed(self, *, client: str | None, actor: str = "") -> Decision:
        """Whether this uploader may publish another package right now."""
        if not self.enabled:
            return ALLOWED
        worst = ALLOWED
        for key in (f"ip:{client}" if client else "", f"actor:{actor}" if actor else ""):
            if not key:
                continue
            decision = self.uploads.check(key)
            if not decision.allowed and decision.retry_after > worst.retry_after:
                worst = decision
        return worst
