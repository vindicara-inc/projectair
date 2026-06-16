"""Standard-library compatibility for Python 3.10.

Project AIR supports Python 3.10 and newer. Two names the codebase relies on
were only added to the standard library in 3.11: ``datetime.UTC`` and
``enum.StrEnum``. To keep every module version-agnostic, import these from here
rather than from the standard library directly. On 3.11+ they are the real
stdlib objects; on 3.10, ``UTC`` is ``timezone.utc`` (identical, and present on
every supported version) and ``StrEnum`` is a faithful backport.

This module is the single source of truth for version compatibility. Do not
import ``UTC`` or ``StrEnum`` from the standard library anywhere else.
"""
from __future__ import annotations

import sys
from datetime import timezone

# ``datetime.UTC`` (3.11+) is an alias for ``timezone.utc``, which exists on 3.10.
UTC = timezone.utc

if sys.version_info >= (3, 11):
    from enum import StrEnum as StrEnum
else:  # pragma: no cover - exercised only on Python 3.10 interpreters
    from enum import Enum

    class StrEnum(str, Enum):
        """Backport of ``enum.StrEnum`` for Python 3.10.

        Members are real ``str`` instances, and ``str()`` / ``format()`` return
        the member's value (not ``Class.NAME``), matching CPython 3.11. The
        codebase declares explicit string values for every member, so faithful
        value semantics are all that is required.
        """

        def __str__(self) -> str:
            return str(self.value)

        __format__ = str.__format__  # type: ignore[assignment]


__all__ = ["UTC", "StrEnum"]
