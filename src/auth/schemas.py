from pydantic import BaseModel, EmailStr

class SessionLoginRequest(BaseModel):
    email: EmailStr
    password: str