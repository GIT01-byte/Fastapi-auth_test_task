from pydantic import BaseModel


class UserScheme(BaseModel):
    username: str
    password: str


class UserLoginSchema(BaseModel):
    username: str
    password: str
