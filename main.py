import os
import uuid
import time
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import socketio
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, String, Text, Float
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jose import JWTError, jwt
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────

SECRET_KEY = os.getenv("SECRET_KEY", "caddsjghquoiw@#@1234124234233432434765642")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 72

# Two hardcoded users — change these to your actual credentials
PASSWORDS = {
    "rishikesh": os.getenv("PASSWORD_ME", "pass_me"),
    "sandhya": os.getenv("PASSWORD_GF", "pass_gf"),
}

# Hash passwords at startup using bcrypt directly (no passlib)
USERS: dict[str, str] = {}
for _username, _raw in PASSWORDS.items():
    USERS[_username] = bcrypt.hashpw(_raw.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ─────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────

DATABASE_URL = "sqlite:///./chat.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Message(Base):
    __tablename__ = "messages"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sender = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(Float, nullable=False, default=time.time)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─────────────────────────────────────────────
#  AUTH HELPERS
# ─────────────────────────────────────────────

def create_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


# ─────────────────────────────────────────────
#  FASTAPI APP
# ─────────────────────────────────────────────

app = FastAPI(title="DM App")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://rishicollinz.com","https://www.rishicollinz.com"],  # tighten this to your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> str:
    username = decode_token(credentials.credentials)
    if not username or username not in USERS:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return username


# ─────────────────────────────────────────────
#  REST — AUTH
# ─────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
def login(body: LoginRequest):
    user_hash = USERS.get(body.username)
    if not user_hash or not verify_password(body.password, user_hash):
        raise HTTPException(status_code=401, detail="Wrong username or password")
    return {
        "token": create_token(body.username),
        "username": body.username,
    }


@app.get("/auth/me")
def me(username: str = Depends(get_current_user)):
    return {"username": username}


# ─────────────────────────────────────────────
#  REST — MESSAGES
# ─────────────────────────────────────────────

@app.get("/messages")
def get_messages(
    limit: int = 50,
    before: Optional[float] = None,        # unix timestamp for pagination
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),    # auth required, user not needed here
):
    q = db.query(Message).order_by(Message.timestamp.desc())
    if before:
        q = q.filter(Message.timestamp < before)
    messages = q.limit(limit).all()
    messages.reverse()                      # return oldest-first
    return [
        {
            "id": m.id,
            "sender": m.sender,
            "content": m.content,
            "timestamp": m.timestamp,
        }
        for m in messages
    ]


# ─────────────────────────────────────────────
#  SOCKET.IO — SETUP
# ─────────────────────────────────────────────

# async_mode="asgi" lets us mount sio alongside FastAPI
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins="*",   # tighten in production
)

# Map socket_id → username (for connected clients)
connected: dict[str, str] = {}


def get_socket_id_for(username: str) -> Optional[str]:
    for sid, uname in connected.items():
        if uname == username:
            return sid
    return None


# ─────────────────────────────────────────────
#  SOCKET.IO — AUTH MIDDLEWARE
# ─────────────────────────────────────────────

@sio.event
async def connect(sid, environ, auth):
    token = (auth or {}).get("token")
    if not token:
        # Also try query string for browser fallback
        query = environ.get("QUERY_STRING", "")
        for part in query.split("&"):
            if part.startswith("token="):
                token = part[6:]
                break

    username = decode_token(token) if token else None
    if not username or username not in USERS:
        await sio.disconnect(sid)
        return False   # reject connection

    connected[sid] = username
    print(f"[socket] {username} connected ({sid})")

    # Tell this user who else is online
    online = list(set(connected.values()))
    await sio.emit("online_users", online, to=sid)

    # Tell everyone this user came online
    await sio.emit("user_online", username, skip_sid=sid)


@sio.event
async def disconnect(sid):
    username = connected.pop(sid, None)
    if username:
        print(f"[socket] {username} disconnected ({sid})")
        await sio.emit("user_offline", username)


# ─────────────────────────────────────────────
#  SOCKET.IO — CHAT
# ─────────────────────────────────────────────

@sio.event
async def send_message(sid, data):
    username = connected.get(sid)
    if not username:
        return

    content = (data.get("content") or "").strip()
    if not content:
        return

    # Persist to DB
    db = SessionLocal()
    try:
        msg = Message(
            id=str(uuid.uuid4()),
            sender=username,
            content=content,
            timestamp=time.time(),
        )
        db.add(msg)
        db.commit()
        db.refresh(msg)
        payload = {
            "id": msg.id,
            "sender": msg.sender,
            "content": msg.content,
            "timestamp": msg.timestamp,
        }
    finally:
        db.close()

    # Broadcast to ALL connected clients (including sender for confirmation)
    await sio.emit("new_message", payload)


# ─────────────────────────────────────────────
#  SOCKET.IO — WEBRTC SIGNALING
#
#  The server is just a relay. No media ever touches it.
#  Flow:
#    caller  → call_offer    → server → callee
#    callee  → call_answer   → server → caller
#    either  → ice_candidate → server → other side
#    either  → end_call      → server → other side
# ─────────────────────────────────────────────

@sio.event
async def call_offer(sid, data):
    """
    data = { "sdp": <RTCSessionDescription> }
    Forwards offer to the other user.
    """
    caller = connected.get(sid)
    if not caller:
        return

    callee = _other_user(caller)
    callee_sid = get_socket_id_for(callee) if callee else None

    if not callee_sid:
        await sio.emit("call_error", {"reason": "Other user is offline"}, to=sid)
        return

    await sio.emit("call_offer", {"from": caller, "sdp": data.get("sdp")}, to=callee_sid)


@sio.event
async def call_answer(sid, data):
    """
    data = { "sdp": <RTCSessionDescription> }
    Forwards answer back to the caller.
    """
    answerer = connected.get(sid)
    if not answerer:
        return

    caller = _other_user(answerer)
    caller_sid = get_socket_id_for(caller) if caller else None

    if caller_sid:
        await sio.emit("call_answer", {"from": answerer, "sdp": data.get("sdp")}, to=caller_sid)


@sio.event
async def ice_candidate(sid, data):
    """
    data = { "candidate": <RTCIceCandidate> }
    Forwards ICE candidate to the other peer.
    """
    sender = connected.get(sid)
    if not sender:
        return

    other = _other_user(sender)
    other_sid = get_socket_id_for(other) if other else None

    if other_sid:
        await sio.emit("ice_candidate", {"candidate": data.get("candidate")}, to=other_sid)


@sio.event
async def end_call(sid, _data=None):
    """Tells the other peer the call ended."""
    sender = connected.get(sid)
    if not sender:
        return

    other = _other_user(sender)
    other_sid = get_socket_id_for(other) if other else None

    if other_sid:
        await sio.emit("call_ended", {}, to=other_sid)


def _other_user(username: str) -> Optional[str]:
    """Since there are only two users, return whoever isn't this person."""
    for u in USERS:
        if u != username:
            return u
    return None


# ─────────────────────────────────────────────
#  MOUNT SOCKET.IO ON FASTAPI
# ─────────────────────────────────────────────

# This single ASGI app handles both HTTP (FastAPI) and WS (Socket.IO)
socket_app = socketio.ASGIApp(sio, other_asgi_app=app)


# ─────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:socket_app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )