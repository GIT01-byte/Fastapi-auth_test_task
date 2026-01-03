import pytest

# from pydantic import EmailStr

# from backend.auth.core.schemas import RegisterRequest
# from backend.auth.services import auth_service
from backend.auth.utils.security import create_refresh_token

# @pytest.fixture
# def users_to_reqister():
#     users_to_reqister = [
#         RegisterRequest(username='Test', email='test@email.com', profile={'test': 'test'}, password='test_pwd'),
#         RegisterRequest(username='Test1', email='test1@email.com', password='test_pwd1'),
#     ]


# def test_register_user(users_to_reqister):

class TestTokens:
    def test_create_refresh_token(self):
        token, hashed_token = create_refresh_token()
        assert isinstance(token, str)
        assert isinstance(hashed_token, str)
