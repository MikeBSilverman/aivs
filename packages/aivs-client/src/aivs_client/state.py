"""Persistent polling cursors.

A member's collector runs on a schedule and must not re-ingest what it already
has, nor skip what arrived between runs. The cursor is the ``date_added`` of the
last object collected from a given collection, stored per instance and per
collection.

Written atomically: a cursor file truncated by a crash mid-write would, on the
next run, either re-deliver everything (noisy) or -- worse -- be read as a
partial timestamp that silently skips content. Write to a temporary file in the
same directory and rename over the target, which is atomic on POSIX.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

__all__ = ["CursorStore"]


class CursorStore:
    """Per-collection polling cursors for one AIVS instance."""

    def __init__(self, state_dir: Path, instance_url: str) -> None:
        self._path = state_dir / f"{self._instance_key(instance_url)}.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _instance_key(instance_url: str) -> str:
        """Derive a filesystem-safe key from an instance URL.

        Restricted rather than escaped: the URL comes from configuration, but a
        value that walked out of the state directory would be a surprising way
        to overwrite a file.
        """
        safe = "".join(char if char.isalnum() or char in "-." else "_" for char in instance_url)
        return safe.strip("_")[:120] or "instance"

    def _read(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # A corrupt cursor file is recoverable by re-collecting; refusing to
            # run would leave a member with no feed at all.
            return {}
        return data if isinstance(data, dict) else {}

    def get(self, collection_id: str) -> str | None:
        """Return the stored cursor for a collection, if any."""
        value = self._read().get(collection_id)
        return value if isinstance(value, str) else None

    def _write(self, data: dict[str, Any]) -> None:
        """Replace the cursor file atomically.

        Temporary file in the same directory, fsynced, then renamed over the
        target. A crash mid-write therefore leaves either the old file or the
        new one, never a truncated timestamp that would silently skip content.
        """
        # mkstemp rather than NamedTemporaryFile: the descriptor is handed over
        # explicitly, so the file survives the close and the rename is the only
        # thing that publishes it.
        descriptor, temporary_name = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            Path(temporary_name).replace(self._path)
        except BaseException:
            Path(temporary_name).unlink(missing_ok=True)
            raise

    def set(self, collection_id: str, date_added: str) -> None:
        """Record a new cursor."""
        data = self._read()
        data[collection_id] = date_added
        self._write(data)

    def clear(self, collection_id: str | None = None) -> None:
        """Forget one cursor, or all of them, forcing a full re-collection."""
        if collection_id is None:
            self._path.unlink(missing_ok=True)
            return
        data = self._read()
        data.pop(collection_id, None)
        self._write(data)
