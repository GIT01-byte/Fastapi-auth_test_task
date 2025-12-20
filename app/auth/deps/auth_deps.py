from typing import Annotated, Any

from fastapi import Depends, Request, Response

from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError as JWTInvalidTokenError

from db.users_repository import UsersRepo
from schemas.users import TokenResponse, UserInDB
from db.db_manager import db_manager
from sqlalchemy.ext.asyncio import AsyncSession
from app_redis.client import get_redis_client
from exceptions.exceptions import (
    CookieMissingTokenError,
    InvalidTokenError,
    SetCookieFailedError,
    TokenRevokedError,
    UserInactiveError,
    UserNotFoundError,
)
from utils.security import (
    REFRESH_TOKEN_TYPE,
    ACCESS_TOKEN_TYPE,
    decode_jwt,
)

from utils.logging import logger

SessionDep = Annotated[AsyncSession, Depends(db_manager.session_getter)]


http_bearer = HTTPBearer(auto_error=False)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl='/users/login/'
)


def get_current_token_payload(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    """
    Декодирует JWT-токен и возвращает его полезную нагрузку.
    """
    try:
        logger.debug(f'Начинаю декодировать токен: {token}')
        payload: dict[str, Any] = decode_jwt(token=token)
        logger.debug(f"Декодированный токен: {payload}")
        return payload
    except JWTInvalidTokenError as ex:
        logger.error(f"Ошибка декодирования токена: {ex}")
        raise InvalidTokenError(detail='invalid token')


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
    response.delete_cookie(ACCESS_TOKEN_TYPE)
    response.delete_cookie(REFRESH_TOKEN_TYPE)

    return response


def set_tokens_cookie(
    key: str,
    value: str,
    max_age: int,
    response: Response,
):
    # Устанавливаем куки, включая настройки безопасности
    try:
        response.set_cookie(
            key=key,
            value=value,
            httponly=True,          # Доступно только через HTTP
            secure=True,            # Только по HTTPS (важно для безопастности)
            samesite="lax",         # Защита от CSRF
            max_age=max_age * 60 if isinstance(max_age, int) else None,
        )
        logger.info(
            f'Установка куки успешно произошла. Ключ: {key!r}, значение: {value!r}, время жизни: {max_age!r} минут')
    except:
        logger.error(
            f'Установка куки произошла с ошибкой. Ключ: {key!r}, значение: {value!r}, время жизни: {max_age!r} минут')
        raise SetCookieFailedError()

# TODO fix token dep
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    redis = Depends(get_redis_client),
) -> UserInDB:
    """

    """
    try:
        payload = get_current_token_payload(token)

        user_id: int | None = int(payload.get("sub")) # type: ignore
        jti: str | None = payload.get("jti")

        if not user_id or not jti:
            raise InvalidTokenError("Missing required claims: sub or jti")

        # Проверка чёрного списка Redis
        if await redis.exists(f"blacklist:access:{jti}"):
            raise TokenRevokedError()

        user_data_from_db = await UsersRepo.select_user_by_user_id(user_id)

        # Проверяем полученного user'а
        if not user_data_from_db:
            raise UserNotFoundError()

        # Преобразуем данные из репозитория в Pydantic модель
        user = UserInDB(
            id=user_data_from_db.id,
            username=user_data_from_db.username,
            email=user_data_from_db.email,
            hashed_password=user_data_from_db.hashed_password,
            is_active=user_data_from_db.is_active,
        )

        return user
    
    except JWTInvalidTokenError:
        raise InvalidTokenError()


async def get_current_active_user(
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    if not current_user.is_active:
        raise UserInactiveError()
    return current_user
