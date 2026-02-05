from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import bcrypt
import os
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
import uuid
import urllib.parse
import re

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import models
from database import engine, get_db

# Create tables
models.Base.metadata.create_all(bind=engine)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["id.psx", "localhost", "127.0.0.1"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://*.psx", "http://localhost"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")

# CONFIGURATION
SECRET_KEY = os.getenv("SECRET_KEY", "dead-internet-secret-key-change-me")
SYSTEM_SECRET = os.getenv("SYSTEM_SECRET", "system-master-secret-key")

if SECRET_KEY == "dead-internet-secret-key-change-me" or SYSTEM_SECRET == "system-master-secret-key":
    # In production, this should block startup. For this simulation, we'll warn loudly 
    # but strictly speaking, the review requested we fail fast.
    if os.getenv("ENV") == "production":
        raise RuntimeError("CRITICAL: Default secrets in use. Set SECRET_KEY and SYSTEM_SECRET.")
    else:
        print("WARNING: Default secrets in use. This is insecure.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 43200 # 30 Days

# OAuth2 Storage (In-memory for simulation)
# code -> {user_id: str}
AUTH_CODES = {}

def verify_password(plain_password, hashed_password):
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=14)).decode('utf-8')

def validate_password(password: str) -> bool:
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"\d", password): return False
    return True

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_from_cookie(request: Request, db: Session):
    token = request.cookies.get("id_session")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return db.query(models.User).filter(models.User.username == username).first()
    except JWTError:
        return None

@app.get("/docs", response_class=HTMLResponse)
async def documentation(request: Request):
    return templates.TemplateResponse("docs.html", {"request": request})

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, db: Session = Depends(get_db)):
    user = get_user_from_cookie(request, db)
    if user:
        return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, username: str = Form(...), password: str = Form(...), user_type: str = Form("human"), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()
    if user:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Username already taken"})
    
    if not validate_password(password):
        return templates.TemplateResponse("register.html", {"request": request, "error": "Password weak: 8+ chars, 1 upper, 1 lower, 1 digit required."})

    hashed_password = get_password_hash(password)
    new_user = models.User(username=username, hashed_password=hashed_password, user_type=user_type)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return RedirectResponse(url="/?success=registered", status_code=303)

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/login")
@limiter.limit("10/minute")
async def login(response: Response, request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
         return templates.TemplateResponse("index.html", {"request": request, "error": "Invalid credentials"})
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    next_url = request.query_params.get("next") or "/"
    response = RedirectResponse(url=next_url, status_code=303)
    response.set_cookie(
        key="id_session",
        value=access_token,
        httponly=True,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    return response

@app.get("/logout")
async def logout(response: Response):
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="id_session")
    return response

# --- OAUTH2 ENDPOINTS ---

@app.get("/authorize")
async def authorize(request: Request, client_id: str, redirect_uri: str, response_type: str = "code", state: Optional[str] = None, scope: Optional[str] = None, db: Session = Depends(get_db)):
    if client_id == "psx-grid-mcp":
        return RedirectResponse(url=f"/authorize/agent?{urllib.parse.urlencode(request.query_params)}")
    
    user = get_user_from_cookie(request, db)
    if not user:
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type
        }
        if state: params["state"] = state
        if scope: params["scope"] = scope
        
        login_url = f"/login?next={urllib.parse.quote('/authorize?' + urllib.parse.urlencode(params))}"
        return RedirectResponse(url=login_url)

    code = str(uuid.uuid4())
    AUTH_CODES[code] = {
        "username": user.username,
        "client_id": client_id
    }
    
    parsed_url = urllib.parse.urlparse(redirect_uri)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    query_params['code'] = [code]
    if state:
        query_params['state'] = [state]
    
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    callback_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
    
    return RedirectResponse(url=callback_url)

@app.get("/authorize/agent")
async def authorize_agent(request: Request, client_id: str, redirect_uri: str, response_type: str = "code", state: Optional[str] = None, scope: Optional[str] = None):
    return templates.TemplateResponse("agent_login.html", {
        "request": request,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scope,
        "response_type": response_type
    })

@app.post("/authorize/agent")
async def handle_authorize_agent(
    request: Request, 
    username: str = Form(...), 
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    response_type: str = Form("code"),
    state: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("agent_login.html", {
            "request": request,
            "error": "Invalid agent credentials",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "response_type": response_type
        })
    
    code = str(uuid.uuid4())
    AUTH_CODES[code] = {
        "username": user.username,
        "client_id": client_id
    }
    
    parsed_url = urllib.parse.urlparse(redirect_uri)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    query_params['code'] = [code]
    if state:
        query_params['state'] = [state]
    
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    callback_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
    
    return RedirectResponse(url=callback_url)

@app.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
    base_url = f"{request.url.scheme}://{request.url.netloc}"
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize/agent",
        "token_endpoint": f"{base_url}/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "registration_endpoint": f"{base_url}/register_client",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"]
    }

@app.post("/register_client")
async def register_client(request: Request):
    return {
        "client_id": "psx-grid-mcp",
        "client_secret": "simulated-secret",
        "client_id_issued_at": int(datetime.utcnow().timestamp()),
        "client_name": "PSX Grid MCP Client"
    }

@app.get("/.well-known/oauth-authorization-server")
async def oauth_configuration(request: Request):
    return await openid_configuration(request)

@app.get("/userinfo")
async def userinfo(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401)
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user: raise HTTPException(status_code=401)
        return {
            "sub": user.username,
            "name": user.username,
            "preferred_username": user.username,
            "email": f"{user.username}@mail.psx",
            "user_type": user.user_type
        }
    except JWTError:
        raise HTTPException(status_code=401)

@app.post("/token")
async def token_endpoint(request: Request, grant_type: str = Form(...), code: Optional[str] = Form(None), username: Optional[str] = Form(None), password: Optional[str] = Form(None), db: Session = Depends(get_db)):
    if grant_type == "authorization_code":
        if not code: raise HTTPException(status_code=400, detail="Missing code")
        data = AUTH_CODES.get(code)
        if not data:
            raise HTTPException(status_code=400, detail="Invalid or expired code")
        del AUTH_CODES[code]
        username = data["username"]
        client_id = data["client_id"]
    elif grant_type == "password":
        if not username or not password: raise HTTPException(status_code=400, detail="Missing username or password")
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        client_id = "direct_access"
    else:
        raise HTTPException(status_code=400, detail="Invalid grant_type")
    
    base_url = f"{request.url.scheme}://{request.url.netloc}"
    now = datetime.utcnow()
    
    user = db.query(models.User).filter(models.User.username == username).first()
    u_type = user.user_type if user else "human"

    id_token_payload = {
        "iss": base_url,
        "sub": username,
        "aud": client_id,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "name": username,
        "preferred_username": username,
        "user_type": u_type
    }
    id_token = jwt.encode(id_token_payload, SECRET_KEY, algorithm=ALGORITHM)
    access_token = create_access_token(data={"sub": username})
    
    return {
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@app.post("/api/system/token")
def api_system_token(username: str, secret: str, db: Session = Depends(get_db)):
    if secret != SYSTEM_SECRET:
        raise HTTPException(status_code=403)
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404)
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token}

@app.get("/api/verify")
def api_verify(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid user")
        return {"username": user.username, "id": user.id, "active": user.is_active, "user_type": user.user_type}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/api/register")
def api_register(username: str, password: str, user_type: str = "agent", db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(password)
    new_user = models.User(username=username, hashed_password=hashed_password, user_type=user_type)
    db.add(new_user)
    db.commit()
    return {"username": username, "status": "created", "type": user_type}

@app.post("/api/login")
def api_login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}