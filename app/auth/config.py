from pathlib import Path

from pydantic import BaseModel, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).parent.parent


class JwtAuth(BaseModel):
    model_config = ConfigDict(strict=True)

    private_key_path: Path = BASE_DIR / 'auth' / 'certs' / 'private_key.pem'
    public_key_path: Path = BASE_DIR / 'auth' / 'certs' / 'public_key.pem'
    algorithm: str = 'EdDSA'
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 60 * 24 * 30


class DatabaseSettings(BaseSettings):
    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASS: str
    DB_NAME: str

    @property
    def DATABASE_URL_asyncpg(self):
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASS}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    model_config = SettingsConfigDict(env_file='.env')


class Settings(BaseSettings):
    jwt_auth: JwtAuth = JwtAuth()
    db_settings: DatabaseSettings = DatabaseSettings()  # type: ignore


settings = Settings()  # type: ignore
