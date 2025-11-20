import os
import time
import hmac
import base64
import hashlib
import secrets
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

from database import db, create_document, get_documents

app = FastAPI(title="TradeGlass API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========= Utility helpers ========= #
AUTH_SECRET = os.getenv("AUTH_SECRET", "dev-secret-change-me")
TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sign_token(payload: str) -> str:
    sig = hmac.new(AUTH_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")


def generate_token(email: str) -> str:
    iat = int(time.time())
    exp = iat + TOKEN_TTL_SECONDS
    payload = f"sub={email}|iat={iat}|exp={exp}"
    signature = sign_token(payload)
    token_raw = f"{payload}|sig={signature}"
    return base64.urlsafe_b64encode(token_raw.encode("utf-8")).decode("utf-8")


# ========= Schemas ========= #
class BasicOk(BaseModel):
    ok: bool = True


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ========= Routes ========= #
@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = getattr(db, 'name', '✅ Connected')
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


@app.post("/auth/register", response_model=BasicOk)
def register(payload: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    # Check if account exists
    existing = db["account"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    salt = secrets.token_hex(16)
    password_hash = sha256_hex(salt + payload.password)

    doc = {
        "email": payload.email,
        "name": payload.name or payload.email.split("@")[0],
        "password_hash": password_hash,
        "salt": salt,
        "provider": "password",
        "is_active": True,
    }
    create_document("account", doc)
    return BasicOk()


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    acc = db["account"].find_one({"email": payload.email})
    if not acc:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    expected = sha256_hex(acc["salt"] + payload.password)
    if expected != acc.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = generate_token(payload.email)
    return TokenResponse(access_token=token)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
