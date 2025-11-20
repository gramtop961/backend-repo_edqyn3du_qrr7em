import os
import hashlib
from typing import Optional, Dict, Any
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from pydantic import BaseModel, Field, EmailStr

from database import db, create_document, get_documents

app = FastAPI(title="TradeGlass API", version="0.1.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Optional HTTPS enforcement (set ENFORCE_HTTPS=true to enable)
if os.getenv("ENFORCE_HTTPS", "false").lower() == "true":
    app.add_middleware(HTTPSRedirectMiddleware)

ALPHA_KEY = os.getenv("ALPHAVANTAGE_API_KEY", "demo")
TWELVE_KEY = os.getenv("TWELVEDATA_API_KEY", "demo")
FINNHUB_KEY = os.getenv("FINNHUB_API_KEY", "")
FMP_KEY = os.getenv("FMP_API_KEY", "demo")
COINAPI_KEY = os.getenv("COINAPI_KEY", "")


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SignalRequest(BaseModel):
    symbol: str = Field(..., description="Ticker symbol, e.g. AAPL")
    interval: str = Field("1day")
    threshold: float = Field(0.6, ge=0.0, le=1.0)


class BasicOk(BaseModel):
    ok: bool


def _hash_password(pw: str) -> str:
    salt = os.getenv("PASSWORD_SALT", "tradeglass")
    return hashlib.sha256((salt + pw).encode()).hexdigest()


def _fetch(url: str, params: Dict[str, Any] | None = None, headers: Dict[str, str] | None = None) -> Dict[str, Any]:
    try:
        r = requests.get(url, params=params, headers=headers, timeout=30)
        if not r.ok:
            raise HTTPException(status_code=r.status_code, detail=f"Upstream error: {r.text[:200]}")
        data = r.json()
        return data
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Network error: {str(e)}")


@app.get("/")
def root():
    return {"message": "TradeGlass API running"}


@app.get("/test")
def test_database():
    resp = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            resp["connection_status"] = "Connected"
            try:
                resp["collections"] = db.list_collection_names()[:10]
                resp["database"] = "✅ Connected & Working"
            except Exception as e:
                resp["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
        else:
            resp["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        resp["database"] = f"❌ Error: {str(e)[:80]}"
    return resp


# ---------------------- Auth (simplified) ----------------------

@app.post("/auth/register", response_model=BasicOk)
def register(payload: RegisterRequest):
    existing = db.user.find_one({"email": payload.email}) if db else None
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    doc = {
        "name": payload.name,
        "email": str(payload.email),
        "password_hash": _hash_password(payload.password),
        "mfa_enabled": False,
        "webauthn_credentials": [],
    }
    create_document("user", doc)
    return {"ok": True}


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db.user.find_one({"email": payload.email}) if db else None
    if not user or user.get("password_hash") != _hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = _hash_password(payload.email + "|" + payload.password)[:48]
    return TokenResponse(access_token=token)


# ---------------------- Market/TA proxies ----------------------

@app.get("/market/overview")
def market_overview(symbol: str = "AAPL"):
    # Use Alpha Vantage GLOBAL_QUOTE as quick overview
    url = "https://www.alphavantage.co/query"
    params = {"function": "GLOBAL_QUOTE", "symbol": symbol, "apikey": ALPHA_KEY}
    data = _fetch(url, params)
    return data


@app.get("/ta/macd")
def ta_macd(symbol: str = "AAPL", interval: str = "daily"):
    url = "https://www.alphavantage.co/query"
    params = {"function": "MACD", "symbol": symbol, "interval": interval, "apikey": ALPHA_KEY}
    return _fetch(url, params)


@app.get("/ta/rsi")
def ta_rsi(symbol: str = "AAPL", interval: str = "1day"):
    url = "https://api.twelvedata.com/rsi"
    params = {"symbol": symbol, "interval": interval, "apikey": TWELVE_KEY}
    return _fetch(url, params)


@app.get("/ta/bbands")
def ta_bbands(symbol: str = "AAPL", interval: str = "1day"):
    url = "https://api.twelvedata.com/bbands"
    params = {"symbol": symbol, "interval": interval, "apikey": TWELVE_KEY}
    return _fetch(url, params)


@app.get("/timeseries")
def time_series(symbol: str = "AAPL", interval: str = "1h", outputsize: str = "100"):
    url = "https://api.twelvedata.com/time_series"
    params = {"symbol": symbol, "interval": interval, "outputsize": outputsize, "apikey": TWELVE_KEY}
    return _fetch(url, params)


@app.get("/patterns/dojistar")
def candles_dojistar(symbol: str = "AAPL", interval: str = "daily"):
    url = "https://www.alphavantage.co/query"
    params = {"function": "CDL_DOJISTAR", "symbol": symbol, "interval": interval, "apikey": ALPHA_KEY}
    return _fetch(url, params)


@app.get("/fundamentals/overview")
def fundamentals_overview(symbol: str = "AAPL"):
    url = "https://www.alphavantage.co/query"
    params = {"function": "OVERVIEW", "symbol": symbol, "apikey": ALPHA_KEY}
    return _fetch(url, params)


@app.get("/fundamentals/twelvedata")
def fundamentals_twelvedata(symbol: str = "AAPL"):
    url = "https://api.twelvedata.com/fundamentals"
    params = {"symbol": symbol, "apikey": TWELVE_KEY}
    return _fetch(url, params)


@app.get("/news/sentiment")
def news_sentiment(symbol: str = "AAPL"):
    if not FINNHUB_KEY:
        raise HTTPException(status_code=400, detail="FINNHUB_API_KEY not set")
    url = "https://finnhub.io/api/v1/news-sentiment"
    params = {"symbol": symbol, "token": FINNHUB_KEY}
    return _fetch(url, params)


@app.get("/news/forex")
def news_forex(limit: int = 50):
    url = "https://financialmodelingprep.com/api/v3/forex_news"
    params = {"apikey": FMP_KEY, "limit": limit}
    return _fetch(url, params)


@app.get("/calendar/economic")
def economic_calendar(from_date: Optional[str] = None, to_date: Optional[str] = None):
    url = "https://financialmodelingprep.com/api/v3/economic_calendar"
    params: Dict[str, Any] = {"apikey": FMP_KEY}
    if from_date:
        params["from"] = from_date
    if to_date:
        params["to"] = to_date
    return _fetch(url, params)


@app.get("/exchanges")
def exchanges(country: Optional[str] = None):
    url = "https://api.twelvedata.com/exchanges"
    params: Dict[str, Any] = {"apikey": TWELVE_KEY}
    if country:
        params["country"] = country
    return _fetch(url, params)


@app.get("/orderbook/kraken")
def orderbook_kraken(pair: str = "XBTUSD", count: int = 20):
    url = "https://api.kraken.com/0/public/Depth"
    params = {"pair": pair, "count": count}
    return _fetch(url, params)


@app.get("/orderbook/coinapi/{symbol_id}")
def orderbook_coinapi(symbol_id: str):
    if not COINAPI_KEY:
        raise HTTPException(status_code=400, detail="COINAPI_KEY not set")
    url = f"https://rest.coinapi.io/v1/orderbooks/{symbol_id}/latest"
    headers = {"X-CoinAPI-Key": COINAPI_KEY}
    return _fetch(url, headers=headers)


# ---------------------- Signals (simple demo) ----------------------

@app.post("/signals/generate")
def generate_signal(req: SignalRequest):
    macd = ta_macd(req.symbol)
    rsi = ta_rsi(req.symbol)
    bb = ta_bbands(req.symbol)

    # Simplified scoring using latest available values
    try:
        macd_series = macd.get("Technical Analysis: MACD", {})
        macd_latest_key = next(iter(macd_series))
        macd_val = float(macd_series[macd_latest_key]["MACD"])
    except Exception:
        macd_val = 0.0

    try:
        rsi_values = rsi.get("values") or []
        rsi_val = float(rsi_values[0]["rsi"]) if rsi_values else 50.0
    except Exception:
        rsi_val = 50.0

    try:
        bb_values = bb.get("values") or []
        price_pos = 0.5
        if bb_values:
            v = bb_values[0]
            upper = float(v["upper_band"]) ; lower = float(v["lower_band"]) ; price = float(v.get("real_lower_band", lower))
            if upper != lower:
                price_pos = (price - lower) / (upper - lower)
    except Exception:
        price_pos = 0.5

    # Normalize
    macd_score = 0.5 + max(-1.0, min(1.0, macd_val)) / 2.0
    rsi_score = 1 - abs(50 - rsi_val) / 50  # closer to 50 -> neutral; we invert for trendiness
    bb_score = 1 - abs(0.5 - price_pos) * 2

    confidence = max(0.0, min(1.0, (0.4 * macd_score + 0.3 * rsi_score + 0.3 * bb_score)))
    side = "buy" if macd_val > 0 and rsi_val > 50 else "sell" if macd_val < 0 and rsi_val < 50 else "neutral"

    record = {
        "symbol": req.symbol,
        "interval": req.interval,
        "side": side,
        "confidence": round(confidence * 100, 2),
    }
    try:
        create_document("signal", record)
    except Exception:
        pass

    return record
