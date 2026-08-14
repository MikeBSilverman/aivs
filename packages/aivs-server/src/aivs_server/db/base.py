"""Declarative base, naming conventions, and shared column helpers.

The naming convention matters more than it looks: Alembic's autogenerate
compares constraint *names*, so without a fixed convention every migration
review is polluted by spurious drop/create pairs and a genuine change is easy to
miss in the noise.
"""

from __future__ import annotations

import datetime as dt
import uuid
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, Enum as SAEnum, MetaData, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = ["Base", "TimestampMixin", "pg_enum", "utc_now", "uuid_pk"]

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base for all ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def utc_now() -> dt.datetime:
    """Return an aware UTC timestamp.

    Used only where a value must be computed in Python; columns prefer
    ``server_default=func.now()`` so that a skewed application clock cannot
    reorder rows relative to the database's own view of time. This distinction
    is load-bearing for embargo release -- see ``services.embargo``.
    """
    return dt.datetime.now(dt.UTC)


def pg_enum(enum_cls: type[StrEnum], name: str) -> SAEnum:
    """Build a native PostgreSQL enum type from a Python ``StrEnum``.

    ``values_callable`` is essential: without it SQLAlchemy persists the enum
    *member name* (``OWN_PRODUCT``) rather than its *value* (``own_product``),
    which silently diverges from the JSON the API emits.
    """
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=True,
        create_type=True,
        validate_strings=True,
        values_callable=lambda e: [member.value for member in e],
    )


def uuid_pk() -> Mapped[uuid.UUID]:
    """Standard surrogate primary key: database-generated UUIDv4."""
    return mapped_column(
        primary_key=True,
        server_default=func.gen_random_uuid(),
        default=uuid.uuid4,
    )


class TimestampMixin:
    """``created_at`` / ``updated_at``, both database-generated."""

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


def json_column_kwargs() -> dict[str, Any]:
    """Keyword arguments shared by every JSONB column."""
    return {"nullable": False}
