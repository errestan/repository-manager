"""Authentication and authorization (specification.md 7).

Split from ``web`` on purpose: nothing in here knows about HTTP.  The directory
client, the session lifecycle and the CSRF primitives are all callable and
testable without a request, which is what makes the permission rules cheap
enough to test exhaustively.
"""


def is_local_path(candidate: str) -> bool:
    """Whether a redirect target is a path on this site and nothing else.

    Rejects anything a browser might resolve to another origin.  ``//host`` is
    the obvious protocol-relative form; ``/\\host`` is the one that gets missed,
    because it looks like an ordinary path and several browsers normalise the
    backslash to a slash before resolving it.  Both are refused here, along with
    anything that is not rooted at all -- which covers ``javascript:`` and every
    other scheme by construction.
    """
    return candidate.startswith("/") and not candidate.startswith(("//", "/\\"))
