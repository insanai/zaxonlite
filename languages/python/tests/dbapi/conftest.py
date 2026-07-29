"""Shared fixtures: every connection gets its own node directory."""

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import zxlite


@pytest.fixture
def make_connection(
    tmp_path: Path,
) -> Iterator[Callable[..., zxlite.Connection]]:
    """Return a factory that opens connections on fresh directories."""
    created: list[zxlite.Connection] = []
    counter = 0

    def factory(**kwargs: Any) -> zxlite.Connection:
        nonlocal counter
        counter += 1
        connection = zxlite.connect(tmp_path / f"node-{counter}", **kwargs)
        created.append(connection)
        return connection

    yield factory
    for connection in created:
        try:
            connection.close()
        except zxlite.Error:
            pass


@pytest.fixture
def conn(
    make_connection: Callable[..., zxlite.Connection],
) -> zxlite.Connection:
    """Return one default connection on a fresh node directory."""
    return make_connection()
