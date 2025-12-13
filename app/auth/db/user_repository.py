from typing import Optional
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from models.users import Users
from db.database import Base, async_session_factory, async_engine

from utils.logging import logger


class UsersRepo():
    @staticmethod
    async def create_tables():
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    @staticmethod
    async def insert_user(payload: dict) -> Optional[Users]:
        async with async_session_factory() as session:
            new_user = Users(**payload)
            session.add(new_user)
        
            try:
                await session.flush()
                await session.commit()
                await session.refresh(new_user)
                return new_user
            except IntegrityError as ex:
                # Если возникла ошибка целостности (например, уникальный ключ),
                # выводим сообщение и откатываем транзакцию
                logger.error(f"Ошибка вставки пользователя: {ex}")
                await session.rollback()
                return None


    @staticmethod
    async def select_user_by_user_id(user_id: int) -> Users | None:
        async with async_session_factory() as session:
            query = (
                select(Users)
                .where(Users.id == user_id)
            )
            result = await session.execute(query)
            user = result.scalars().first()
            return user

    @staticmethod
    async def select_user_by_login(username: str) -> Users | None:
        async with async_session_factory() as session:
            query = (
                select(Users)
                .where(Users.username == username)
            )
            result = await session.execute(query)
            user = result.scalars().first()
            return user
