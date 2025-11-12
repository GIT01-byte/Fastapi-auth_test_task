from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase


class Base(DeclarativeBase):
    pass


engine = create_engine('sqlite:///task.db', echo=False)

new_session = sessionmaker(engine, expire_on_commit=False)


def get_session():
    with new_session() as session:
        yield session


def create_table():
    Base.metadata.create_all(engine)


def delete_table():
    Base.metadata.drop_all(engine)
