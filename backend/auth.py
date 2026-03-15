from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Literal
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, status
import bcrypt
from jose import JWTError, jwt
from pydantic import BaseModel

try:
    from firebase_client import db
except Exception:  # pragma: no cover - optional in local/dev setups
    try:
        from .firebase_client import db  # type: ignore
    except Exception:
        db = None

try:
    from firebase_admin import auth as firebase_auth
except Exception:  # pragma: no cover - optional in local/dev setups
    firebase_auth = None

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
JWT_SECRET = os.getenv("SECUREAGENT_JWT_SECRET", "secureagent-dev-secret-change-me")
SUPPORTED_ROLES = {"user", "admin", "researcher"}

router = APIRouter(prefix="/auth", tags=["auth"])


class UserOut(BaseModel):
    id: str
    email: str
    role: Literal["user", "admin", "researcher"]
    created_at: str


class RegisterRequest(BaseModel):
    email: str
    password: str
    role: Literal["user", "admin", "researcher"] = "user"


class LoginRequest(BaseModel):
    email: str
    password: str


class GoogleLoginRequest(BaseModel):
    id_token: str
    role: Literal["user", "admin", "researcher"] = "user"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


def _require_db() -> Any:
    if db is None:
        raise HTTPException(status_code=500, detail="Firestore is not configured")
    return db


def _validate_password_length(password: str) -> None:
    encoded = password.encode("utf-8")
    if len(encoded) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if len(encoded) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password is too long. Use 8 to 72 characters.",
        )


def hash_password(password: str) -> str:
    _validate_password_length(password)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    if len(password.encode("utf-8")) > 72:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(user: Dict[str, Any]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {
        "user_id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "exp": expire,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc


def _user_from_doc(doc: Any) -> Dict[str, Any]:
    data = doc.to_dict() or {}
    return {
        "id": doc.id,
        "email": data.get("email", ""),
        "password_hash": data.get("password_hash", ""),
        "role": data.get("role", "user"),
        "created_at": data.get("created_at", ""),
    }


def get_user_by_email(email: str) -> Dict[str, Any] | None:
    firestore_db = _require_db()
    query = (
        firestore_db.collection("users")
        .where("email", "==", email.lower().strip())
        .limit(1)
        .stream()
    )
    for doc in query:
        return _user_from_doc(doc)
    return None


def get_user_by_id(user_id: str) -> Dict[str, Any] | None:
    firestore_db = _require_db()
    doc = firestore_db.collection("users").document(user_id).get()
    if not doc.exists:
        return None
    return _user_from_doc(doc)


def serialize_user(user: Dict[str, Any]) -> UserOut:
    role = str(user.get("role", "user"))
    if role not in SUPPORTED_ROLES:
        role = "user"
    return UserOut(
        id=str(user["id"]),
        email=str(user["email"]),
        role=role,  # type: ignore[arg-type]
        created_at=str(user.get("created_at") or ""),
    )


def _require_public_role(role: str) -> str:
    normalized = str(role or "user").strip().lower()
    if normalized != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin and researcher accounts must be provisioned by an administrator",
        )
    return "user"


@router.post("/register", response_model=TokenResponse)
def register(payload: RegisterRequest) -> TokenResponse:
    firestore_db = _require_db()
    email = payload.email.lower().strip()
    password = payload.password.strip()
    role = _require_public_role(payload.role)

    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    _validate_password_length(password)
    if get_user_by_email(email):
        raise HTTPException(status_code=409, detail="User already exists")

    created_at = datetime.now(timezone.utc).isoformat()
    user_id = str(uuid4())
    user_doc = {
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "created_at": created_at,
    }
    firestore_db.collection("users").document(user_id).set(user_doc)

    user = {"id": user_id, **user_doc}
    return TokenResponse(access_token=create_access_token(user), user=serialize_user(user))


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    email = payload.email.lower().strip()
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    user = get_user_by_email(email)
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return TokenResponse(access_token=create_access_token(user), user=serialize_user(user))


@router.post("/google", response_model=TokenResponse)
def google_login(payload: GoogleLoginRequest) -> TokenResponse:
    firestore_db = _require_db()
    _require_public_role(payload.role)

    if firebase_auth is None:
        raise HTTPException(status_code=500, detail="Firebase authentication is not configured")

    try:
        claims = firebase_auth.verify_id_token(payload.id_token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google sign-in token",
        ) from exc

    email = str(claims.get("email", "")).lower().strip()
    email_verified = bool(claims.get("email_verified"))
    if not email or not email_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google account email must be verified",
        )

    existing_user = get_user_by_email(email)
    if existing_user:
        return TokenResponse(
            access_token=create_access_token(existing_user),
            user=serialize_user(existing_user),
        )

    created_at = datetime.now(timezone.utc).isoformat()
    user_id = str(uuid4())
    user_doc = {
        "email": email,
        "password_hash": "",
        "role": "user",
        "created_at": created_at,
        "auth_provider": "google",
    }
    firestore_db.collection("users").document(user_id).set(user_doc)

    user = {"id": user_id, **user_doc}
    return TokenResponse(access_token=create_access_token(user), user=serialize_user(user))


@router.get("/me", response_model=UserOut)
def me(authorization: str | None = Header(default=None)) -> UserOut:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip() if authorization.startswith("Bearer ") else ""
    claims = decode_access_token(token)
    user = get_user_by_id(str(claims.get("user_id", "")))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return serialize_user(user)
