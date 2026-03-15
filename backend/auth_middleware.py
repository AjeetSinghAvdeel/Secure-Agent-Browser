from __future__ import annotations

from typing import Callable

from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel

try:
    from auth import SUPPORTED_ROLES, decode_access_token, get_user_by_id
except Exception:  # pragma: no cover - package import fallback
    from .auth import SUPPORTED_ROLES, decode_access_token, get_user_by_id  # type: ignore


class AuthenticatedUser(BaseModel):
    id: str
    email: str
    role: str


def get_current_user(authorization: str | None = Header(default=None)) -> AuthenticatedUser:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )

    token = authorization.split(" ", 1)[1].strip()
    claims = decode_access_token(token)
    user_id = str(claims.get("user_id", "")).strip()
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    role = str(user.get("role", "user"))
    if role not in SUPPORTED_ROLES:
        role = "user"

    return AuthenticatedUser(
        id=user_id,
        email=str(user.get("email", "")),
        role=role,
    )


def require_roles(*roles: str) -> Callable[[AuthenticatedUser], AuthenticatedUser]:
    allowed = {role for role in roles if role in SUPPORTED_ROLES}

    def role_dependency(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return role_dependency
