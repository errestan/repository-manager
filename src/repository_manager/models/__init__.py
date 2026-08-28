"""SQLAlchemy models (specification.md 9).

Importing this package registers every mapped class, which is what lets the
string-based relationship targets ("Repository", "PackagePublication") resolve.
Alembic's autogenerate and the drift test both depend on it importing the
complete set, so new model modules belong here as soon as they exist.
"""

from repository_manager.models.auth import (
    ActorType,
    AuditAction,
    AuditLog,
    AuditOutcome,
    Role,
    UserSession,
)
from repository_manager.models.base import Base, RepositoryType, UtcDateTime, utcnow
from repository_manager.models.job import Job, JobState, JobType
from repository_manager.models.key import (
    FINGERPRINT_PATTERN,
    KEY_NAME_PATTERN,
    KeyAlgorithm,
    SigningKey,
)
from repository_manager.models.package import (
    Package,
    PackagePublication,
    UploadSource,
)
from repository_manager.models.repository import (
    NAME_PATTERN,
    SLUG_PATTERN,
    AptArchitecture,
    AptComponent,
    AptDistribution,
    Repository,
    RpmVariant,
)
from repository_manager.models.token import (
    TOKEN_BYTES,
    TOKEN_PREFIX,
    TOKEN_PREFIX_LENGTH,
    ApiToken,
    TokenScope,
    decode_scopes,
    encode_scopes,
)

__all__ = [
    "FINGERPRINT_PATTERN",
    "KEY_NAME_PATTERN",
    "NAME_PATTERN",
    "SLUG_PATTERN",
    "TOKEN_BYTES",
    "TOKEN_PREFIX",
    "TOKEN_PREFIX_LENGTH",
    "ActorType",
    "ApiToken",
    "AptArchitecture",
    "AptComponent",
    "AptDistribution",
    "AuditAction",
    "AuditLog",
    "AuditOutcome",
    "Base",
    "Job",
    "JobState",
    "JobType",
    "KeyAlgorithm",
    "Package",
    "PackagePublication",
    "Repository",
    "RepositoryType",
    "Role",
    "RpmVariant",
    "SigningKey",
    "TokenScope",
    "UploadSource",
    "UserSession",
    "UtcDateTime",
    "decode_scopes",
    "encode_scopes",
    "utcnow",
]
