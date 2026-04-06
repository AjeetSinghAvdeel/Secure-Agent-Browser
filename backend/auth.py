from __future__ import annotations

import os
import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Literal
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, status
import bcrypt
import requests
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
DEFAULT_JWT_SECRET = "secureagent-dev-secret-change-me"
JWT_SECRET = os.getenv("SECUREAGENT_JWT_SECRET", DEFAULT_JWT_SECRET)
SUPPORTED_ROLES = {"user", "admin", "researcher"}
AUTH_OPERATION_TIMEOUT_SECONDS = float(os.getenv("SECUREAGENT_AUTH_TIMEOUT_SECONDS", "4"))
LOCAL_AUTH_STORE = Path(__file__).resolve().parent / "local_auth_users.json"
AUTH_EXECUTOR = ThreadPoolExecutor(max_workers=4)
FIREBASE_WEB_API_KEY = os.getenv(
    "SECUREAGENT_FIREBASE_API_KEY",
    "AIzaSyDYMtSJE8zDJxeu5RXHbtXT1loyNfLcKyk",
)

router = APIRouter(prefix="/auth", tags=["auth"])


if (
    os.getenv("SECUREAGENT_ENV", "development").strip().lower() in {"production", "staging"}
    and JWT_SECRET == DEFAULT_JWT_SECRET
):
    raise RuntimeError(
        "SECUREAGENT_JWT_SECRET must be configured for production or staging deployments"
    )


class UserOut(BaseModel):
    id: str
    email: str
    role: Literal["user", "admin", "researcher"]
    created_at: str
    auth_provider: str | None = None
    has_password: bool = False


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


class SetPasswordRequest(BaseModel):
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


def _require_db() -> Any:
    if db is None:
        raise HTTPException(status_code=500, detail="Firestore is not configured")
    return db


def _run_with_timeout(fn, *args, **kwargs):
    future = AUTH_EXECUTOR.submit(fn, *args, **kwargs)
    try:
        return future.result(timeout=AUTH_OPERATION_TIMEOUT_SECONDS)
    except FuturesTimeoutError as exc:
        future.cancel()
        raise TimeoutError("Authentication storage timed out") from exc


def _load_local_users() -> Dict[str, Dict[str, Any]]:
    if not LOCAL_AUTH_STORE.exists():
        return {}
    try:
        payload = json.loads(LOCAL_AUTH_STORE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    users = payload.get("users", {})
    return users if isinstance(users, dict) else {}


def _save_local_users(users: Dict[str, Dict[str, Any]]) -> None:
    LOCAL_AUTH_STORE.write_text(
        json.dumps({"users": users}, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _find_local_user_by_email(email: str) -> Dict[str, Any] | None:
    normalized = email.lower().strip()
    for user_id, data in _load_local_users().items():
        if str(data.get("email", "")).lower().strip() == normalized:
            return {"id": user_id, **data}
    return None


def _find_local_user_by_id(user_id: str) -> Dict[str, Any] | None:
    data = _load_local_users().get(user_id)
    if not data:
        return None
    return {"id": user_id, **data}


def _write_local_user(user_id: str, user_doc: Dict[str, Any]) -> Dict[str, Any]:
    users = _load_local_users()
    users[user_id] = user_doc
    _save_local_users(users)
    return {"id": user_id, **user_doc}


def _verify_google_token_via_rest(id_token: str) -> Dict[str, Any]:
    if not FIREBASE_WEB_API_KEY:
        raise RuntimeError("Firebase web API key is not configured")

    response = requests.post(
        f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={FIREBASE_WEB_API_KEY}",
        json={"idToken": id_token},
        timeout=8,
    )
    response.raise_for_status()
    payload = response.json()
    users = payload.get("users", [])
    if not users:
        raise ValueError("No Firebase user found for Google token")
    user = users[0]
    return {
        "email": str(user.get("email", "")).lower().strip(),
        "email_verified": bool(user.get("emailVerified")),
    }


def _verify_google_token(id_token: str) -> Dict[str, Any]:
    admin_error: Exception | None = None

    if firebase_auth is not None:
        try:
            return dict(firebase_auth.verify_id_token(id_token))
        except Exception as exc:
            admin_error = exc

    try:
        return _verify_google_token_via_rest(id_token)
    except Exception as rest_exc:
        detail = str(admin_error or rest_exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google sign-in token: {detail}",
        ) from rest_exc


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
        "auth_provider": data.get("auth_provider", "password"),
    }


def get_user_by_email(email: str) -> Dict[str, Any] | None:
    normalized = email.lower().strip()
    try:
        firestore_db = _require_db()

        def _query():
          query = (
              firestore_db.collection("users")
              .where("email", "==", normalized)
              .limit(1)
              .stream()
          )
          for doc in query:
              return _user_from_doc(doc)
          return None

        return _run_with_timeout(_query)
    except Exception:
        return _find_local_user_by_email(normalized)


def get_user_by_id(user_id: str) -> Dict[str, Any] | None:
    try:
        firestore_db = _require_db()

        def _query():
            doc = firestore_db.collection("users").document(user_id).get()
            if not doc.exists:
                return None
            return _user_from_doc(doc)

        return _run_with_timeout(_query)
    except Exception:
        return _find_local_user_by_id(user_id)


def serialize_user(user: Dict[str, Any]) -> UserOut:
    role = str(user.get("role", "user"))
    if role not in SUPPORTED_ROLES:
        role = "user"
    return UserOut(
        id=str(user["id"]),
        email=str(user["email"]),
        role=role,  # type: ignore[arg-type]
        created_at=str(user.get("created_at") or ""),
        auth_provider=str(user.get("auth_provider") or "password"),
        has_password=bool(user.get("password_hash")),
    )


def _update_user_credentials(user_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    try:
        firestore_db = _require_db()

        def _update():
            ref = firestore_db.collection("users").document(user_id)
            ref.update(fields)
            doc = ref.get()
            if not doc.exists:
                raise HTTPException(status_code=404, detail="User not found")
            return _user_from_doc(doc)

        return _run_with_timeout(_update)
    except HTTPException:
        raise
    except Exception:
        local_user = _find_local_user_by_id(user_id)
        if not local_user:
            raise HTTPException(status_code=404, detail="User not found")
        updated = {**local_user, **fields}
        user_doc = {
            "email": updated["email"],
            "password_hash": updated.get("password_hash", ""),
            "role": updated.get("role", "user"),
            "created_at": updated.get("created_at", ""),
            "auth_provider": updated.get("auth_provider", "password"),
        }
        return _write_local_user(user_id, user_doc)


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
        "auth_provider": "password",
    }
    try:
        firestore_db = _require_db()
        _run_with_timeout(firestore_db.collection("users").document(user_id).set, user_doc)
        user = {"id": user_id, **user_doc}
    except Exception:
        user = _write_local_user(user_id, user_doc)
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
    _require_public_role(payload.role)
    claims = _verify_google_token(payload.id_token)

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
    try:
        firestore_db = _require_db()
        _run_with_timeout(firestore_db.collection("users").document(user_id).set, user_doc)
        user = {"id": user_id, **user_doc}
    except Exception:
        user = _write_local_user(user_id, user_doc)
    return TokenResponse(access_token=create_access_token(user), user=serialize_user(user))


@router.post("/set-password", response_model=TokenResponse)
def set_password(
    payload: SetPasswordRequest,
    authorization: str | None = Header(default=None),
) -> TokenResponse:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1].strip()
    claims = decode_access_token(token)
    user_id = str(claims.get("user_id", "")).strip()
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    password = payload.password.strip()
    _validate_password_length(password)

    auth_provider = str(user.get("auth_provider") or "password").strip().lower()
    next_provider = "password"
    if auth_provider == "google":
        next_provider = "google+password"
    elif auth_provider in {"google+password", "password"}:
        next_provider = auth_provider

    updated_user = _update_user_credentials(
        user_id,
        {
            "password_hash": hash_password(password),
            "auth_provider": next_provider,
        },
    )
    return TokenResponse(
        access_token=create_access_token(updated_user),
        user=serialize_user(updated_user),
    )


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
