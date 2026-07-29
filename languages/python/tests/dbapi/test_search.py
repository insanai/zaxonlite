"""Typed search: lexical FTS5 branch and validation errors."""

import pytest

import zxlite


@pytest.fixture
def corpus(conn: zxlite.Connection) -> zxlite.Connection:
    conn.executescript(
        """
        create virtual table docs using fts5(body);
        insert into docs(body) values ('paxos replicates sqlite');
        insert into docs(body) values ('unrelated text entirely');
        insert into docs(body) values ('sqlite is an embedded database');
        """
    )
    return conn


def test_lexical_search_returns_cursor(corpus: zxlite.Connection) -> None:
    cursor = corpus.search(fts_table="docs", text="paxos")
    assert isinstance(cursor, zxlite.Cursor)
    assert cursor.description is not None
    rows = cursor.fetchall()
    assert len(rows) == 1


def test_lexical_search_k_limits_results(
    corpus: zxlite.Connection,
) -> None:
    cursor = corpus.search(fts_table="docs", text="sqlite", k=1)
    assert len(cursor.fetchall()) == 1


def test_search_supports_row_factory(corpus: zxlite.Connection) -> None:
    corpus.row_factory = zxlite.Row
    row = corpus.search(fts_table="docs", text="paxos").fetchone()
    assert isinstance(row, zxlite.Row)


def test_search_identifier_validation(corpus: zxlite.Connection) -> None:
    with pytest.raises(zxlite.ProgrammingError) as info:
        corpus.search(fts_table="docs; drop table docs", text="paxos")
    assert info.value.category == "validation"


def test_search_invalid_k(corpus: zxlite.Connection) -> None:
    with pytest.raises(zxlite.ProgrammingError) as info:
        corpus.search(fts_table="docs", text="paxos", k=0)
    assert info.value.category == "validation"


def test_search_requires_a_branch(corpus: zxlite.Connection) -> None:
    with pytest.raises(zxlite.ProgrammingError):
        corpus.search(text="paxos")
    with pytest.raises(zxlite.ProgrammingError):
        corpus.search()


def test_search_rejects_remote_read_options(
    corpus: zxlite.Connection,
) -> None:
    with pytest.raises(zxlite.ProgrammingError):
        corpus.search(fts_table="docs", text="paxos", read_level="linearizable")
    with pytest.raises(zxlite.ProgrammingError):
        corpus.search(fts_table="docs", text="paxos", freshness_ms=10)


def test_search_validates_python_types(corpus: zxlite.Connection) -> None:
    with pytest.raises(zxlite.ProgrammingError):
        corpus.search(fts_table="docs", text="paxos", fusion="max")
    with pytest.raises(zxlite.ProgrammingError):
        corpus.search(fts_table="docs", text=123)
    with pytest.raises(zxlite.ProgrammingError):
        corpus.search(vec_table="v", embedding="not-bytes")
    with pytest.raises(zxlite.ProgrammingError):
        corpus.search(fts_table="docs", text="paxos", k="ten")


def test_search_embedding_shape_validated_natively(
    corpus: zxlite.Connection,
) -> None:
    # A bytes embedding reaches the native validator, which rejects a
    # missing vec table / bad shape without executing SQL.
    with pytest.raises(zxlite.Error):
        corpus.search(vec_table="missing_vec", embedding=b"\x00" * 12)
