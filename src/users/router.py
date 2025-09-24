from typing import Annotated
from argon2 import PasswordHasher
import time
import os
import jwt

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status,
    Response
)

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db
from src.users.errors import EmailAlreadyExistsException, InvalidSessionException, UnauthenticatedException, BadAuthorizationHeaderException, InvalidTokenException

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
ALGORITHM = "HS256"
ph = PasswordHasher()
user_router = APIRouter(prefix="/users", tags=["users"])

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:

    new_id = len(user_db)+1
    
    for user in user_db:        
        if request.email == user["email"]:
            raise EmailAlreadyExistsException()
    
    hashed = ph.hash(request.password)

    user_db.append({
        "user_id": new_id,
        "name": request.name,
        "email": request.email,
        "hashed_password": hashed,
        "phone_number": request.phone_number,
        "height": request.height,
        "bio": request.bio
    })
    
    # new_bio = request.bio
    # if new_bio is not None:
    #     user_db[new_id]["bio"] = new_bio

    return UserResponse(user_id=new_id,
                        name=request.name, 
                        email=request.email,
                        phone_number=request.phone_number,
                        height=request.height,
                        bio=request.bio)

@user_router.get("/me", status_code=status.HTTP_200_OK)
def get_user_info(
    response: Response,
    sid: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None)
    ) -> UserResponse:
    
    if sid is None and authorization is None:
        raise UnauthenticatedException()
    

    if sid is not None:
        sess = session_db.get(sid)
        if sess is None:
            raise InvalidSessionException()
        
        now = time.time()
        if now >= sess["expires_at"]:
            raise InvalidSessionException()
        
        new_expires = now + LONG_SESSION_LIFESPAN * 60
        sess["expires_at"] = new_expires

        
        response.set_cookie(
            key="sid",
            value=sid,
            max_age=LONG_SESSION_LIFESPAN * 60,
            httponly=True,
            samesite="lax",
            path="/",
        )

        uid = int(sess["user_id"])
        user = next((u for u in user_db if int(u["user_id"]) == uid), None)
        if not user:
            raise InvalidSessionException()

        return UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            phone_number=user["phone_number"],
            height=user["height"],
            bio=user.get("bio"),
        )
    

    if authorization is not None:
        parts = authorization.split()
        if len(parts) != 2 or parts[0] != "Bearer":
            raise BadAuthorizationHeaderException()
        refresh_token = parts[1]

        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        except jwt.PyJWTError:
            InvalidTokenException()
        
        sub = payload.get("sub")
        original_exp = payload.get("exp")
        if sub is None or original_exp is None:
            raise InvalidTokenException()

        uid = int(sub)
        user = next((u for u in user_db if int(u["user_id"]) == uid), None)
        if user is None:
            raise InvalidTokenException()
        
        return UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            phone_number=user["phone_number"],
            height=user["height"],
            bio=user.get("bio"),
        )

