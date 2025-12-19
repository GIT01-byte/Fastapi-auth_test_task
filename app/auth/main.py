from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models.user_admin import setup_admin
from db.db_manager import db_manager
from models.base import Base
from api.api import api_routers

from utils.logging import logger

import tracemalloc

# Включаем отслеживание памяти, для дебага ошибок с ассинхронными функциями
tracemalloc.start()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info('Запуск приложения...')

    async with db_manager.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        # await conn.run_sync(Base.metadata.create_all)
        print(Base.metadata.tables.keys())
    print("Database is droped")

    yield

    logger.info('Выключение...')

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_routers)

setup_admin(app, db_manager.engine)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(f"{__name__}:app", reload=True)
