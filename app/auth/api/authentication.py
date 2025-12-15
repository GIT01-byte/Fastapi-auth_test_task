from fastapi import APIRouter, Depends

from utils.security import create_access_token, create_refresh_token
from exceptions.exceptions import (
    RegistrationFailedError,
    UserAlreadyExistsError,
)
from schemas.users import (
    RegisterRequest,
    TokenResponse,
    UserInDB,
)
from services.auth_service import (
    logout_user,
    register_user_to_db
)
from deps.auth_deps import (
    get_current_token_payload,
    http_bearer,
    get_current_active_auth_user,
    get_current_auth_user_for_refresh,
    validate_auth_user,
)

from utils.logging import logger


auth = APIRouter(
    dependencies=[Depends(http_bearer)],
)
auth_usage = APIRouter()
dev_usage = APIRouter()


@auth.post('/login/')
def auth_user_issue_jwt(
    user: UserInDB = Depends(validate_auth_user),
):
    user_id = str(user.id)
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@auth.post('/register')
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

    # Ловим уникальность и прочие ошибки
    except ValueError as e:
        err_msg = str(e)
        if "already exists" in err_msg:
            raise UserAlreadyExistsError()
        logger.error(f'Registration error, exc_info="{err_msg}"')
        raise RegistrationFailedError(detail=err_msg)
    except Exception as e:
        err_msg = str(e)
        if "already exists" in err_msg:
            raise UserAlreadyExistsError()
        logger.error(f'Registration error, exc_info="{err_msg}"')
        raise RegistrationFailedError()


@auth.post(
    '/refresh/',
    response_model=TokenResponse,
    response_model_exclude_none=True,
)
def auth_refresh_jwt(
    user: UserInDB = Depends(get_current_auth_user_for_refresh)
):
    user_id = str(user.id)
    access_token = create_access_token(user_id)
    return TokenResponse(
        access_token=access_token,
    )


@auth.post("/logout/")
async def logout():
    result = logout_user()
    return result


@auth_usage.get('/me/')
async def auth_user_check_self_info(
    payload: dict = Depends(get_current_token_payload),
    user: UserInDB = Depends(get_current_active_auth_user),
):
    iat = payload.get('iat')
    return {
        'username': user.username,
        'email': user.email,
        'logged_in_at': iat,
    }
