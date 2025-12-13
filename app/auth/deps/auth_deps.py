from typing import Any, Callable, Coroutine

from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from jwt import DecodeError, ExpiredSignatureError

from fastapi import Depends, Form

from exceptions.exceptions import (
    InvalidCredentialsError,
    MalformedTokenError,
    InvalidTokenPayload,
    UserInactiveError,
    ValidateAuthUserFailedError,
)
from schemas.users import UserInDB
from utils.security import (
    TOKEN_TYPE_FIELD,
    check_password, 
    REFRESH_TOKEN_TYPE,
    ACCESS_TOKEN_TYPE,
    decode_jwt,
    )
from db.user_repository import UsersRepo

from utils.logging import logger


http_bearer = HTTPBearer(auto_error=False)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl='/users/login/'
    )


async def validate_auth_user(
    username: str = Form(),
    password: str = Form(),
) -> UserInDB:
    """
    Валидирует учетные данные пользователя для входа.
    """
    try:
        logger.debug(f"Получение пользователя по имени '{username}'...")
        user_data_from_db = await UsersRepo.select_user_by_login(username)
        
        if not user_data_from_db:
            logger.warning(f"Пользователь '{username}' не найден!")
            raise InvalidCredentialsError(detail='invalid username or password')
        
        logger.debug(f"Полученный пользователь: {user_data_from_db}")
        
        if not check_password(password=password, hashed_password=user_data_from_db.hashed_password):
            logger.warning(f"Неверный пароль для пользователя '{username}'")
            raise InvalidCredentialsError(detail='invalid username or password')
        
        if not user_data_from_db.is_active:
            logger.info(f"Пользователь '{username}' неактивен.")
            raise UserInactiveError()
        
        logger.debug(f"Возвращаю данные пользователя: {user_data_from_db}")
        return UserInDB(
            id=user_data_from_db.id,
            username=user_data_from_db.username,
            email=user_data_from_db.email,
            hashed_password=user_data_from_db.hashed_password,
            is_active=user_data_from_db.is_active,
        )
    except Exception as ex:
        logger.error(f"Ошибка при проверке учетных данных пользователя: {ex}")
        raise ValidateAuthUserFailedError()

def get_current_token_payload(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    """
    Декодирует JWT-токен и возвращает его полезную нагрузку.
    """
    try:
        logger.debug(f'Начинаю декодировать токен: {token}')
        payload: dict[str, Any] = decode_jwt(token=token)
        logger.debug(f"Декодированный токен: {payload}")
        return payload
    except (DecodeError, ExpiredSignatureError) as ex:
        logger.error(f"Ошибка декодирования окена: {ex}")
        raise MalformedTokenError(detail='invalid token')

def validate_token_type(
    payload: dict[str, Any],
    token_type: str,
) -> bool:
    """
    Проверяет тип токена в полезной нагрузке.
    """
    current_token_type = payload.get(TOKEN_TYPE_FIELD)
    if current_token_type == token_type:
        logger.debug(f"Тип токена подтвержден: {token_type}.")
        return True
    else:
        logger.error(f"Тип токена неверен: ожидается '{token_type}', получен '{current_token_type}'.")
        raise MalformedTokenError()

async def get_user_by_token_sub(
    payload: dict[str, Any]
) -> UserInDB:
    """
    Извлекает пользователя из базы данных по 'sub' (user_id) из полезной нагрузки токена.
    """
    user_id = payload.get('sub')
    if user_id:
        logger.debug(f"Ищу пользователя с ID={user_id}...")
        user_data_from_db = await UsersRepo.select_user_by_user_id(int(user_id))
        if not user_data_from_db:
            logger.warning(f"Пользователь с ID={user_id} не найден!")
            raise InvalidCredentialsError(detail='invalid username or password')
        logger.debug(f"Найденный пользователь: {user_data_from_db}")
        return UserInDB(
            id=user_data_from_db.id,
            username=user_data_from_db.username,
            email=user_data_from_db.email,
            hashed_password=user_data_from_db.hashed_password,
            is_active=user_data_from_db.is_active,
        )
    else:
        logger.error("Нет поля 'sub' в токене.")
        raise InvalidTokenPayload()

# Фабричная функция для создания зависимостей, проверяющих тип токена
def get_auth_user_from_token_of_type(token_type: str) -> Callable[[dict[str, Any]], Coroutine[Any, Any, UserInDB]]:
    """
    Фабрика зависимостей, которая возвращает асинхронную функцию для получения
    аутентифицированного пользователя определенного типа токена.
    """
    async def get_auth_user_from_token(
        payload: dict[str, Any] = Depends(get_current_token_payload)
    ) -> UserInDB:
        logger.debug(f"Валидация токена типа '{token_type}'...")
        validate_token_type(payload, token_type)
        return await get_user_by_token_sub(payload)
    return get_auth_user_from_token

# Создаем конкретные зависимости, используя фабрику
get_current_auth_user = get_auth_user_from_token_of_type(ACCESS_TOKEN_TYPE)
get_current_auth_user_for_refresh = get_auth_user_from_token_of_type(REFRESH_TOKEN_TYPE)

async def get_current_active_auth_user(
    user: UserInDB = Depends(get_current_auth_user)
) -> UserInDB:
    """
    Возвращает текущего активного аутентифицированного пользователя.
    """
    logger.info(f"Авторизация пользователя: {user.id=}, {user.username=}")
    if user.is_active:
        return user
    raise UserInactiveError()
