from typing import Any, Callable, Coroutine

from jwt import InvalidTokenError

from fastapi import Depends, Form, HTTPException, Request, Response, status

from exceptions.exceptions import (
    CookieMissingTokenError,
    InvalidCredentialsError,
    MalformedTokenError,
    InvalidTokenPayload,
    UserInactiveError,
)
from schemas.users import UserInDB
from utils.security import check_password, decode_jwt
from db.user_repository import UsersRepo
from services.jwt_tokens import TOKEN_TYPE_FIELD, ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE

from utils.logging import logger


async def validate_auth_user(
    username: str = Form(),
    password: str = Form(),
) -> UserInDB:
    """
    Валидирует учетные данные пользователя для входа.
    """
    try:
        logger.debug(f"Получение пользователя по имени '{username}'...")
        user_data_from_db = await UsersRepo.select_user_by_username(username)
        
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
    except Exception as e:
        logger.error(f"Ошибка при проверке учетных данных пользователя: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="internal server error")

def get_tokens_by_cookie(request: Request) -> dict[str, str]:
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    
    if access_token and refresh_token:
        logger.debug("Токены успешно извлечены из cookies.")
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
        }
    
    logger.warning("Отсутствуют необходимые cookie с токенами.")
    raise CookieMissingTokenError()

def clear_cookie_with_tokens(response: Response) -> Response:
    # Удаляем куки токенов
    response.delete_cookie(ACCESS_TOKEN_TYPE)
    response.delete_cookie(REFRESH_TOKEN_TYPE)

    return response

def get_current_access_token_payload(
    tokens: dict[str, str] = Depends(get_tokens_by_cookie),
) -> dict[str, Any]:
    """
    Декодирует Access JWT-токен и возвращает его полезную нагрузку.
    """
    try:
        logger.debug("Начинаю декодирование токена...")
        payload = decode_jwt(token=tokens['access_token'])
        logger.debug(f"Декодированный токен: {payload}")
        return payload
    except InvalidTokenError as e:
        logger.error(f"Недействительный токен: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f'invalid token error: {e}')

def get_current_refresh_token_payload(
    tokens: dict[str, str] = Depends(get_tokens_by_cookie),
) -> dict[str, Any]:
    """
    Декодирует Refresh JWT-токен и возвращает его полезную нагрузку.
    """
    try:
        logger.debug("Начинаю декодирование токена обновления...")
        payload = decode_jwt(token=tokens['refresh_token'])
        logger.debug(f"Декодированный токен обновления: {payload}")
        return payload
    except InvalidTokenError as e:
        logger.error(f"Недействительный токен обновления: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f'invalid token error: {e}')

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
        payload: dict[str, Any] = Depends(get_current_access_token_payload)
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
    logger.info(f"Авторизация пользователя: {user}")
    if user.is_active:
        return user
    raise UserInactiveError()
