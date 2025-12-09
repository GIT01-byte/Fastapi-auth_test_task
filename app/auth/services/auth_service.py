from fastapi import Response

from schemas.users import UserInDB
from config import settings
from services.jwt_tokens import (
    REFRESH_TOKEN_TYPE,
    ACCESS_TOKEN_TYPE,
    create_access_token,
    create_refresh_token,
    )
from exceptions.exceptions import (
    CookieMissingTokenError,
    UserNotFoundError,
    InvalidPasswordError,
    UserInactiveError,
    )
from utils.security import check_password, hash_password
from db.user_repository import UsersRepo
from deps.auth_deps import get_current_refresh_token_payload


async def authenticate_user(
    username: str,
    password: str,
) -> Response:
    user_data_from_db = await UsersRepo.select_user_by_username(username)

    # Проверяем полученного user'а
    if not user_data_from_db:
        raise UserNotFoundError()
    
    if not check_password(
        password=password,
        hashed_password=user_data_from_db.hashed_password
        ):
        raise InvalidPasswordError()
    
    if not user_data_from_db.is_active:
        raise UserInactiveError()

    # Преобразуем данные из репозитория в Pydantic модель
    user = UserInDB(
        id=user_data_from_db.id,
        username=user_data_from_db.username,
        email=user_data_from_db.email,
        hashed_password=user_data_from_db.hashed_password,
        is_active=user_data_from_db.is_active,
    )

    # Генерируем токены
    user_id = str(user_data_from_db.id) # Обязательно делаем строчкой, для избежания ошибки "InvalidSubjectError: Subject must be a string"
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)

    # Создаем Response и устанавливаем куки
    response = Response(
        content=user.model_dump_json(), # Тело ответа - данные пользователя (без пароля)
        status_code=200,
        media_type="application/json",
    )

    # Устанавливаем куки, включая настройки безопасности
    response.set_cookie(
        key=ACCESS_TOKEN_TYPE,
        value=access_token,
        httponly=True,          # Доступно только через HTTP
        secure=True,            # Только по HTTPS (важно для продакшена)
        samesite="lax",         # Защита от CSRF
        max_age=60 * settings.jwt_auth.access_token_expire_minutes # Время жизни куки
    )
    response.set_cookie(
        key=REFRESH_TOKEN_TYPE,
        value=refresh_token,
        httponly=True,
        secure=True,            # Только по HTTPS
        samesite="lax",         # Защита от CSRF
        max_age=60 * 60 * 24 * settings.jwt_auth.refresh_token_expire_days # Время жизни куки
    )
    
    return response # Возвращаем готовый Response


async def register_user_to_db(payload: dict, password: str) -> str:
    # Хешируем пароль и добавляем в payload
    hashed_password = hash_password(password)
    full_payload = {**payload, 'hashed_password': hashed_password}
    
    # Добавляем пользователя в бд
    created_user_in_db = await UsersRepo.insert_user(full_payload)
    new_username = created_user_in_db.username
    
    return new_username


def refresh_user_tokens(refresh_token: str) -> Response:
    if refresh_token:
        # Извлекаем из refresh токена user id и еще проверяем токен на свежесть при помощи декодирования
        refresh_payload = get_current_refresh_token_payload()
        # TODO add logging(exp handle)
        user_id = str(refresh_payload.get('sub'))
        # Создаем Response
        response = Response(
            content="{message: 'refresh access token succesfully'}",
            status_code=200,
            media_type="application/json",
        )

        # Удаляем куки старого access
        response.delete_cookie(ACCESS_TOKEN_TYPE)

        # Генерируем новый access
        new_access_token = create_access_token(user_id)

        # Устанавливаем куки с новым access
        response.set_cookie(
            key=ACCESS_TOKEN_TYPE,
            value=new_access_token,
            httponly=True,          # Доступно только через HTTP
            secure=True,            # Только по HTTPS (важно для продакшена)
            samesite="lax",         # Защита от CSRF
            max_age=60 * settings.jwt_auth.access_token_expire_minutes # Время жизни куки
        )
        # TODO add logging(exp handle)

        return response # Возвращаем готовый Response
    else:
        raise CookieMissingTokenError(detail='refresh token reqired in cookie')


def logout_user() -> Response:
    # Создаем Response
    response = Response(
        content="{message: 'logout succesfully'}", # Тело ответа - статус выхода пользователя
        status_code=200,
        media_type="application/json",
    )   

    # Удаляем куки токенов
    response.delete_cookie(ACCESS_TOKEN_TYPE)
    response.delete_cookie(REFRESH_TOKEN_TYPE)

    return response # Возвращаем готовый Response
