"""SQLAlchemy dialect acceptance: Core, ORM, savepoints, and URLs."""

import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote

import pytest

sqlalchemy = pytest.importorskip("sqlalchemy")

from sqlalchemy.orm import (  # noqa: E402
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
)
from sqlalchemy.pool import NullPool, StaticPool  # noqa: E402

import zxlite  # noqa: E402
from sqlalchemy import (  # noqa: E402 - after importorskip
    Column,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    delete,
    exc,
    insert,
    inspect,
    select,
    text,
    update,
)
from zxlite.sqlalchemy import ZxLiteDialect  # noqa: E402


@pytest.fixture
def engine(tmp_path: Path) -> Iterator["sqlalchemy.Engine"]:
    engine = create_engine(f"zxlite:///{tmp_path}/sa-node")
    yield engine
    engine.dispose()


class Base(DeclarativeBase):
    pass


class Item(Base):
    __tablename__ = "item"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True)
    weight: Mapped[int] = mapped_column(Integer, default=0)


def test_engine_create_and_dispose(tmp_path: Path) -> None:
    engine = create_engine(f"zxlite:///{tmp_path}/basic-node")
    assert isinstance(engine.dialect, ZxLiteDialect)
    assert engine.dialect.name == "zxlite"
    with engine.connect() as connection:
        assert connection.execute(text("select 1")).scalar() == 1
    engine.dispose()


def test_local_engine_uses_nullpool_and_gate_c(tmp_path: Path) -> None:
    engine = create_engine(f"zxlite:///{tmp_path}/pool-node")
    try:
        assert engine.pool.__class__ is NullPool.__class__ or isinstance(
            engine.pool, NullPool
        )
        with engine.connect() as connection:
            raw = connection.connection.dbapi_connection
            assert isinstance(raw, zxlite.Connection)
            assert raw._transactional is True
    finally:
        engine.dispose()


def test_metadata_create_all_and_reflection(engine) -> None:
    metadata = MetaData()
    table = Table(
        "widget",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("label", String(40)),
    )
    metadata.create_all(engine)
    names = inspect(engine).get_table_names()
    assert "widget" in names
    columns = {entry["name"] for entry in inspect(engine).get_columns("widget")}
    assert columns == {"id", "label"}
    metadata.drop_all(engine)
    assert "widget" not in inspect(engine).get_table_names()
    del table


def test_core_crud_with_returning(engine) -> None:
    metadata = MetaData()
    table = Table(
        "entry",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("body", String(80)),
    )
    metadata.create_all(engine)
    with engine.begin() as connection:
        result = connection.execute(
            insert(table).values(body="first").returning(table.c.id)
        )
        assert result.scalar() == 1
        connection.execute(
            insert(table),
            [{"body": "second"}, {"body": "third"}],
        )
    with engine.connect() as connection:
        rows = connection.execute(select(table.c.body).order_by(table.c.id)).all()
        assert [row[0] for row in rows] == ["first", "second", "third"]
    with engine.begin() as connection:
        updated = connection.execute(
            update(table).where(table.c.body == "third").values(body="revised")
        )
        assert updated.rowcount == 1
        connection.execute(delete(table).where(table.c.body == "first"))
    with engine.connect() as connection:
        remaining = connection.execute(select(table.c.body).order_by(table.c.id)).all()
        assert [row[0] for row in remaining] == ["second", "revised"]


def test_bound_parameters(engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("create table b(v text)"))
        connection.execute(text("insert into b values (:v)"), {"v": "bound"})
        found = connection.execute(
            text("select v from b where v = :v"), {"v": "bound"}
        ).scalar()
        assert found == "bound"


def test_orm_unit_of_work(engine) -> None:
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Item(name="anvil", weight=10))
        session.add(Item(name="feather", weight=1))
        session.commit()
        anvil = session.query(Item).filter_by(name="anvil").one()
        assert anvil.id is not None  # autoincrement pk came back
        anvil.weight = 11
        session.commit()
    with Session(engine) as session:
        weights = {item.name: item.weight for item in session.query(Item)}
        assert weights == {"anvil": 11, "feather": 1}


def test_orm_rollback(engine) -> None:
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Item(name="kept"))
        session.commit()
        session.add(Item(name="discarded"))
        session.flush()
        session.rollback()
        names = [item.name for item in session.query(Item)]
        assert names == ["kept"]


def test_orm_nested_transaction_savepoint(engine) -> None:
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Item(name="outer"))
        session.flush()
        nested = session.begin_nested()
        session.add(Item(name="inner"))
        session.flush()
        nested.rollback()
        session.commit()
    with Session(engine) as session:
        names = [item.name for item in session.query(Item)]
        assert names == ["outer"]


def test_savepoint_release_path(engine) -> None:
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        with session.begin_nested():
            session.add(Item(name="released"))
        session.commit()
    with Session(engine) as session:
        names = [item.name for item in session.query(Item)]
        assert names == ["released"]


def test_integrity_error_mapping(engine) -> None:
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Item(name="dup"))
        session.commit()
        session.add(Item(name="dup"))
        with pytest.raises(exc.IntegrityError):
            session.commit()
        session.rollback()


def test_second_engine_on_same_directory_raises(tmp_path: Path) -> None:
    url = f"zxlite:///{tmp_path}/locked-node"
    first = create_engine(url)
    second = create_engine(url)
    try:
        with first.connect() as held:
            held.execute(text("select 1"))
            with pytest.raises(exc.OperationalError):
                with second.connect() as other:
                    other.execute(text("select 1"))
    finally:
        first.dispose()
        second.dispose()


def test_remote_url_requires_autocommit() -> None:
    url = "zxlite:///?seed=127.0.0.1%3A9901"
    with pytest.raises(exc.ArgumentError, match="AUTOCOMMIT"):
        create_engine(url)  # defaults to no isolation override


def test_remote_url_translation() -> None:
    dialect = ZxLiteDialect()
    dialect.isolation_level = "AUTOCOMMIT"
    url = sqlalchemy.make_url(
        "zxlite:///?seed=db1.example%3A9901&seed=db2.example%3A9901"
        "&read_level=any&freshness_ms=250"
    )
    (dsn,), connect_args = dialect.create_connect_args(url)
    assert connect_args == {}
    assert dsn.startswith("zxlite:///?")
    assert "seed=db1.example%3A9901" in dsn
    assert "seed=db2.example%3A9901" in dsn
    assert "read_level=any" in dsn
    assert "freshness_ms=250" in dsn


def test_local_url_shapes_rejected() -> None:
    dialect = ZxLiteDialect()
    with pytest.raises(exc.ArgumentError, match="data directory"):
        dialect.create_connect_args(sqlalchemy.make_url("zxlite://"))
    with pytest.raises(exc.ArgumentError, match="host"):
        dialect.create_connect_args(sqlalchemy.make_url("zxlite://host:1/db"))


@pytest.mark.skipif(os.name == "nt", reason="unix sockets are POSIX-only")
def test_remote_engine_against_unix_server(tmp_path: Path) -> None:
    sock_dir = Path(tempfile.mkdtemp(prefix="zx-sa-sock-"))
    sock = sock_dir / "sa.sock"
    try:
        with zxlite.start_server(
            directory=tmp_path / "node",
            node_id=1,
            members=[zxlite.Member(1, f"unix:{sock}")],
        ):
            seed = quote(f"unix:{sock}", safe="")
            engine = create_engine(
                f"zxlite:///?seed={seed}",
                isolation_level="AUTOCOMMIT",
            )
            try:
                assert isinstance(engine.pool, StaticPool)
                with engine.connect() as connection:
                    raw = connection.connection.dbapi_connection
                    assert isinstance(raw, zxlite.RemoteConnection)
                    connection.execute(
                        text("create table r(id integer primary key, v text)")
                    )
                    connection.execute(
                        text("insert into r(v) values (:v)"),
                        {"v": "remote"},
                    )
                    value = connection.execute(text("select v from r")).scalar()
                    assert value == "remote"
            finally:
                engine.dispose()
    finally:
        shutil.rmtree(sock_dir, ignore_errors=True)
