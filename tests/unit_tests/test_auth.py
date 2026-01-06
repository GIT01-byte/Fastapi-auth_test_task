import fastapi
import pytest
from httpx import AsyncClient, ASGITransport
from contextlib import nullcontext as does_not_raise

from backend.auth.utils.security import create_refresh_token, hash_token
from backend.auth.core.schemas import JWTPayload
from backend.auth.main import app


class TestTokens:
    def test_create_refresh_token(self):
        token, hashed_token = create_refresh_token()
        assert isinstance(token, str)
        assert isinstance(hashed_token, str)

class TestApi:
    @pytest.mark.asyncio
    async def test_unauthorize_user(self):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://127.0.0.1:8080"
        ) as ac:
            response = await ac.get("/users/me/")
            assert response.status_code == 401