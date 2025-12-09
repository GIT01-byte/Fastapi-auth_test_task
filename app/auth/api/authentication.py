from fastapi import APIRouter, Depends, HTTPException, status

from exceptions.exceptions import (
    InvalidCredentialsError,
    PasswordRequiredError,
    RegistrationFailedError,
    UserAlreadyExistsError,
    UserAlreadyLoggedgError,
    )
from schemas.users import (
    LoginRequest,
    RegisterRequest,
    UserInDB,
    )
from services.auth_service import authenticate_user, logout_user, refresh_user_tokens, register_user_to_db
from deps.auth_deps import (
    get_tokens_by_cookie,
    get_current_access_token_payload,
    get_current_active_auth_user,
)

import logging
# Настройка логгера
logger = logging.getLogger(__name__)

router = APIRouter()


@router.post('/login')
async def login_user(
    request: LoginRequest,
):
    if not request.password:
        raise PasswordRequiredError()
    user = await authenticate_user(request.username, request.password)
    if not user:
        raise InvalidCredentialsError()
    return user


@router.post('/register')
async def register_user(request: RegisterRequest):
    try:
        # Подготавливаем payload без пароля (он хешируется внутри)
        payload = {
            'username': request.username,
            'email': request.email,
            'profile': request.profile,
        }
        new_user = await register_user_to_db(payload, request.password)
        return {'message': f'Register user: {new_user!r} is successfuly!'}
    
    # Ловим уникальность и прочие ошибки # TODO fix this exc 
    except ValueError as e:
        err_msg = str(e)
        if "UniqueViolationError" in err_msg:
            raise UserAlreadyExistsError() 
        logger.error(f'Registration error, exc_info="{err_msg}"')
        raise RegistrationFailedError(detail=err_msg)
    except Exception as e:
        err_msg = str(e)
        if "UniqueViolationError" in err_msg:
            raise UserAlreadyExistsError()
        logger.error(f'Registration error, exc_info="{err_msg}"')
        raise RegistrationFailedError()


@router.post('/refresh/')
async def auth_refresh_jwt(
    tokens: dict = Depends(get_tokens_by_cookie),
):
    refresh_token = tokens['refresh_token']
    user = refresh_user_tokens(refresh_token) # TODO fix dep sub error
    return user


@router.get('/me/')
async def auth_user_check_self_info(
    payload: dict = Depends(get_current_access_token_payload),
    user: UserInDB = Depends(get_current_active_auth_user),
):
    iat = payload.get('iat')
    return {
        'username': user.username,
        'email': user.email,
        'logged_in_at': iat,
    }


@router.post("/logout/")
async def logout():
    result = logout_user()
    return result


@router.get("/get-current-cookie/")
async def get_cookie(
    result: dict = Depends(get_tokens_by_cookie)
):
    return result
