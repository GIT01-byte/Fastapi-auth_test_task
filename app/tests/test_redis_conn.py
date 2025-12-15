import asyncio
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from auth.redis.client import get_redis_client


async def test_redis_conn():
    conn = await get_redis_client()
    print(conn)

if __name__ == "__main__":
    asyncio.run(test_redis_conn())
