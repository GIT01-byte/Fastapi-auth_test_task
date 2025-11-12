from pydantic import BaseModel


class UserScheme(BaseModel):
    username: str
    password: str
