from fastapi import APIRouter
from fastapi import Depends, Cookie, Response, status, Header

import secrets
import time
from argon2 import PasswordHasher
import jwt
import os

from src.common.database import blocked_token_db, session_db, user_db
from src.auth.schemas import SessionLoginRequest
from src.users.errors import InvalidAccountException, UnauthenticatedException, BadAuthorizationHeaderException, InvalidTokenException

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
ALGORITHM = "HS256"
ph = PasswordHasher()

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

@auth_router.post("/token", status_code=status.HTTP_200_OK)
def issue_token(request: SessionLoginRequest, response: Response):
    user = None
    for u in user_db:
        if u["email"] == request.email:
            user = u
    
    if user is None:
        raise InvalidAccountException()
    
    try:
        ph.verify(user["hashed_password"], request.password)
    except Exception:
        raise InvalidAccountException()
    
    access_payload = {
        "sub": str(user["user_id"]),
        "exp": int(time.time()) + SHORT_SESSION_LIFESPAN*60
    }
    refresh_payload = {
        "sub": str(user["user_id"]),
        "exp": int(time.time()) + LONG_SESSION_LIFESPAN*60
    }

    access_token = jwt.encode(access_payload, SECRET_KEY, algorithm=ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }

@auth_router.post("/token/refresh", status_code=status.HTTP_200_OK)
def refresh_tokens(authorization: str | None = Header(default=None)):
    if authorization is None:
        raise UnauthenticatedException
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0] != "Bearer":
        raise BadAuthorizationHeaderException
    refresh_token = parts[1]

    if refresh_token in blocked_token_db:
        raise InvalidTokenException()

    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise InvalidTokenException()
    
    sub = payload.get("sub")
    original_exp = payload.get("exp")
    if sub is None or original_exp is None:
        raise InvalidTokenException()
    
    blocked_token_db[refresh_token] = original_exp

    access_payload = {
        "sub": str(sub),
        "exp": int(time.time()) + SHORT_SESSION_LIFESPAN*60
    }
    refresh_payload = {
        "sub": str(sub),
        "exp": int(time.time()) + LONG_SESSION_LIFESPAN*60
    }

    access_token = jwt.encode(access_payload, SECRET_KEY, algorithm=ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


@auth_router.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(authorization: str | None = Header(default=None)):
    if authorization is None:
        raise UnauthenticatedException
    
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
    
    blocked_token_db[refresh_token] = original_exp

    return


@auth_router.post("/session", status_code=status.HTTP_200_OK)
def create_session(request: SessionLoginRequest, response: Response):

    user = None
    for u in user_db:
        if u["email"] == request.email:
            user = u
    
    if user is None:
        raise InvalidAccountException()
    
    try:
        ph.verify(user["hashed_password"], request.password)
    except Exception:
        raise InvalidAccountException()

    sid = secrets.token_urlsafe(32)
    expires_at = time.time() + (LONG_SESSION_LIFESPAN * 60)
    session_db[sid] = {
        "user_id": user["user_id"],
        "expires_at": expires_at
    }

    response.set_cookie(
        key="sid",
        value=sid,
        max_age = LONG_SESSION_LIFESPAN*60,
        httponly=True,
        samesite="lax",
        path="/"
    )

    return response

@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(response: Response, sid: str | None = Cookie(default=None)):
    response.delete_cookie(key="sid", path="/")

    if sid is not None:
        session_db.pop(sid, None)

    return response