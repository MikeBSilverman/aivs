"""The ways inbound STIX content is refused.

Every class here is a ``ValueError``, so a caller translating validation failure
into HTTP 400 can catch one family. They live apart from ``builders`` so that
the per-type policy module can raise them without importing ``stix2``.
"""

from __future__ import annotations

__all__ = [
    "BundleValidationError",
    "ExtensionValidationError",
    "ObjectPolicyError",
    "UnknownExtensionError",
]


class ExtensionValidationError(ValueError):
    """An object's AIVS extension body failed schema validation."""


class ObjectPolicyError(ExtensionValidationError):
    """An object breaks a rule AIVS holds for its type, extension or no extension.

    A subclass of :class:`ExtensionValidationError` so every caller that already
    turns that into a 400 does the same here: an indicator with no expiry is the
    submitter's error exactly as a malformed extension body is.
    """


class BundleValidationError(ValueError):
    """An inbound bundle was structurally malformed.

    Distinct from the per-object errors, and a ``ValueError`` subclass so that a
    caller translating validation failures into HTTP 400 catches one family
    rather than having to enumerate ``ValueError`` and ``TypeError`` separately.
    """


class UnknownExtensionError(ValueError):
    """An object carried an extension AIVS does not recognise.

    Raised rather than ignored: silently dropping an unrecognised extension
    would change the meaning of content that a member may have relied on, and
    silently keeping it would redistribute unvalidated data.
    """
