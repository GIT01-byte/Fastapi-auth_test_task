from sqlalchemy import select, update

from models.users import UsersOrm
from db.database import Base, async_session_factory, async_engine


class UsersRepo():
    @staticmethod
    async def create_tables():
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    @staticmethod
    async def insert_user(payload: dict) -> UsersOrm:
        async with async_session_factory() as session:
            created_user = UsersOrm(**payload)
            session.add(created_user)

            await session.flush()
            await session.commit()
            await session.refresh(created_user)
            
            return created_user

    @staticmethod
    async def select_user_by_user_id(user_id: int) -> UsersOrm | None:
        async with async_session_factory() as session:
            query = (
                select(UsersOrm)
                .where(UsersOrm.id == user_id)
            )
            result = await session.execute(query)
            user = result.scalars().first()
            return user

    @staticmethod
    async def select_user_by_username(username: str) -> UsersOrm | None:
        async with async_session_factory() as session:
            query = (
                select(UsersOrm)
                .where(UsersOrm.username == username)
            )
            result = await session.execute(query)
            user = result.scalars().first()
            return user
