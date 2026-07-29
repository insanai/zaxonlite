"""Row objects returned by zxlite cursors.

`Row` mirrors the standard library's `sqlite3.Row`: index access,
case-insensitive column-name access, length, iteration, equality, and
`keys()`.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .dbapi import Cursor

__all__ = ["Row"]


class Row:
    """One materialized result row with index and name access."""

    __slots__ = ("_columns", "_values")

    def __init__(self, cursor: Cursor, values: tuple[Any, ...]) -> None:
        """Capture the cursor's column names and one value tuple."""
        description = cursor.description
        if description is None:
            columns: tuple[str, ...] = ()
        else:
            columns = tuple(entry[0] for entry in description)
        self._columns = columns
        self._values = tuple(values)

    def keys(self) -> list[str]:
        """Return the column names in result order."""
        return list(self._columns)

    def __getitem__(self, key: int | str | slice) -> Any:
        """Return a value by integer index, slice, or column name.

        Name lookup is case-insensitive, matching `sqlite3.Row`.
        """
        if isinstance(key, (int, slice)):
            return self._values[key]
        if isinstance(key, str):
            folded = key.lower()
            for name, value in zip(self._columns, self._values, strict=True):
                if name.lower() == folded:
                    return value
            raise IndexError(f"no such column: {key!r}")
        raise TypeError(
            f"indices must be integers, slices, or strings, not {type(key).__name__}"
        )

    def __len__(self) -> int:
        """Return the number of columns."""
        return len(self._values)

    def __iter__(self) -> Iterator[Any]:
        """Iterate over the values in column order."""
        return iter(self._values)

    def __eq__(self, other: object) -> bool:
        """Compare column names and values against another Row."""
        if isinstance(other, Row):
            return self._columns == other._columns and self._values == other._values
        return NotImplemented

    def __hash__(self) -> int:
        """Hash the column names and values."""
        return hash((self._columns, self._values))

    def __repr__(self) -> str:
        """Return a debugging representation with names and values."""
        pairs = ", ".join(
            f"{name}={value!r}"
            for name, value in zip(self._columns, self._values, strict=True)
        )
        return f"<zxlite.Row {pairs}>"
