from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models.user_admin import setup_admin
from db.database import async_engine
from db.user_repository import UsersRepo
from api.api import api_routers

# TODO Сменить логирование на loguru
# Настройка корневово логгера
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

# Добавление обработчика вывода в консоль
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter('%(levelname)s:    %(asctime)s - %(name)s - %(message)s')
console_handler.setFormatter(console_formatter)
root_logger.addHandler(console_handler)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # await UsersRepo.create_tables()
    root_logger.info('Запуск приложения...')
    root_logger.debug('База перезапущена')
    yield
    root_logger.info('Выключение...')


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_routers)

setup_admin(app, async_engine)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(f'{__name__}:app', reload=True)
