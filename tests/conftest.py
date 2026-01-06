import time
import pytest

from backend.auth.core.models import Base

from backend.auth.core.settings import settings
from backend.auth.core.db.db_manager import db_manager


@pytest.fixture(scope="session", autouse=True)
async def setup_db():
    print(f"{settings.db.name=}")
    assert settings.mode == 'TEST'
    async with db_manager.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
