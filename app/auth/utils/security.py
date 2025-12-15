from typing import Any
import bcrypt

from datetime import timedelta, datetime, timezone

import jwt

from config import settings


TOKEN_TYPE_FIELD = 'type'
ACCESS_TOKEN_TYPE = 'access_token'
REFRESH_TOKEN_TYPE = 'refresh_token'


def create_jwt(
    token_type: str,
    token_data: dict,
    expire_minutes: int = settings.jwt_auth.access_token_expire_minutes,
    expire_timedelta: timedelta | None = None,
) -> str:
    jwt_payload = {
        TOKEN_TYPE_FIELD: token_type,
    }
    jwt_payload.update(token_data)
    return encode_jwt(
        payload=jwt_payload,
        expire_minutes=expire_minutes,
        expire_timedelta=expire_timedelta,
    )


def create_access_token(user_id: str) -> str:
    jwt_payload = {
        'sub': user_id,
    }
    return create_jwt(
        token_type=ACCESS_TOKEN_TYPE,
        token_data=jwt_payload,
        expire_minutes=settings.jwt_auth.access_token_expire_minutes,
    )


def create_refresh_token(user_id: str) -> str:
    jwt_payload = {
        'sub': user_id,
    }
    return create_jwt(
        token_type=REFRESH_TOKEN_TYPE,
        token_data=jwt_payload,
        expire_timedelta=timedelta(
            days=settings.jwt_auth.refresh_token_expire_days),
    )


def hash_password(
    password: str,
) -> bytes:
    salt = bcrypt.gensalt()
    pwd_bytes: bytes = password.encode()
    return bcrypt.hashpw(pwd_bytes, salt)


def check_password(
    password: str,
    hashed_password: bytes,
) -> bool:
    return bcrypt.checkpw(
        password=password.encode(),
        hashed_password=hashed_password,
    )


def encode_jwt(
    payload: dict,
    private_key: str = settings.jwt_auth.private_key_path.read_text(),
    algorithm: str = settings.jwt_auth.algorithm,
    expire_minutes: int = settings.jwt_auth.access_token_expire_minutes,
    expire_timedelta: timedelta | None = None,
) -> str:
    to_encode = payload.copy()
    now = datetime.now(timezone.utc)
    if expire_timedelta:
        expire = now + expire_timedelta
    else:
        expire = now + timedelta(minutes=expire_minutes)
    to_encode.update(
        exp=expire,
        iat=now,
    )
    encoded = jwt.encode(
        to_encode,
        private_key,
        algorithm=algorithm
    )
    return encoded


def decode_jwt(
    token: str | bytes,
    public_key: str = settings.jwt_auth.public_key_path.read_text(),
    algorithm: str = settings.jwt_auth.algorithm,
) -> dict[str, Any]:
    decoded = jwt.decode(
        token,
        public_key,
        algorithms=[algorithm]
    )
    return decoded
