from typing import Optional
from pydantic import BaseModel


class EmpoloyeeScheme(BaseModel):
    id: int


class EmpoloyeeAddScheme(BaseModel):
    name: str
    last_name: str
    phone: int
    image_url: Optional[str | None]

