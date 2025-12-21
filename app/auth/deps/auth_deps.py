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
    decode_access_token,
)

from utils.logging import logger

SessionDep = Annotated[AsyncSession, Depends(db_manager.session_getter)]


http_bearer = HTTPBearer(auto_error=False)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl='/users/login/'
)


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


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    redis = Depends(get_redis_client),
) -> dict:
    """

    """
    try:
        payload = decode_access_token(token)

        jti: str | None = payload.get("jti")
        user_id: int | None = int(payload.get("sub")) # type: ignore
        iat: int | None = payload.get("iat")

        if not user_id or not jti:
            raise InvalidTokenError("Missing required claims: sub or jti")

        # Проверка чёрного списка Redis
        if await redis.exists(f"blacklist:access:{jti}"):
            raise TokenRevokedError()

        user = await UsersRepo.select_user_by_user_id(user_id)

        # Проверяем полученного user'а
        if not user:
            raise UserNotFoundError()

        return {
            'jti': jti,
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'iat': iat
        }
    
    except JWTInvalidTokenError:
        raise InvalidTokenError()


async def get_current_active_user(
    current_user: Annotated[dict, Depends(get_current_user)],
):
    if current_user["is_active"] == True:
        return current_user
    raise UserInactiveError()

