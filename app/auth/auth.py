from time import time
from typing import Annotated, Any
import secrets
import uuid

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from db.repository import UsersRepo


auth_router = APIRouter(
    prefix='/test_task/v1',
    tags=['Auth'],
    )

security = HTTPBasic()


def get_auth_user_username(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)],
    ) -> str:
    unauthed_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid username or password',
        headers={'WWW-Authenticate': 'Basic'},
    )
    user = UsersRepo.select_user_by_username(credentials.username)
    if user:
        correct_password = user.password
    else:
        raise unauthed_exc
    
    if not secrets.compare_digest(
        credentials.password.encode('utf-8'),
        correct_password.encode('utf-8'),
    ):
        raise unauthed_exc
    
    return credentials.username


COOKIES: dict[str, dict[str, Any]] = {}
COOKIE_SESSION_ID_KEY = 'web-app-session-id'


def generate_session_id() -> str:
    return uuid.uuid4().hex

def get_session_data(
    session_id: str = Cookie(alias=COOKIE_SESSION_ID_KEY),
    ):
    unauthed_exc = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail='not authenticated',
    headers={'WWW-Authenticate': 'Cookie-auth'},
    )
    if session_id not in COOKIES:
        raise unauthed_exc
    return COOKIES[session_id]


@auth_router.post('/login-cookie')
def auth_login_set_cookie(
    responce: Response,
    username: str = Depends(get_auth_user_username),
    ):
    # UsersRepo.add_user(
    # username=user.username,
    # password=user.password,
    # )
    session_id = generate_session_id()
    COOKIES[session_id] = {
        'username': username,
        'login_at': int(time()),
    }
    responce.set_cookie(COOKIE_SESSION_ID_KEY, session_id)
    return {
        'message': f'Hi, {username}',
        'login-statuc': 'ok'
    }


@auth_router.get('/login-cookie/')
def auth_check_cookie(
    responce: Response,
    user_session_data: dict = Depends(get_session_data),
    ):
    username = user_session_data['username']
    return {
        'message': f'Hi, {username}',
    }


@auth_router.get('/logout-cookie/')
def auth_logout_cookie(
    responce: Response,
    session_id: str = Cookie(alias=COOKIE_SESSION_ID_KEY),
    user_session_data: dict = Depends(get_session_data),
    ):
    COOKIES.pop(session_id)
    responce.delete_cookie(COOKIE_SESSION_ID_KEY)
    username = user_session_data['username']
    return {
        'message': f'Bye, {username}',
    }

