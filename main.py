import os
import re
import json
import time
import uuid
import random
import shutil
import hashlib
import smtplib
from email.message import EmailMessage
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Query, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="AEGIS CLOUD")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_ROOT = os.path.join(BASE_DIR, "cloud_storage")
FRONTEND_FILE = os.path.join(BASE_DIR, "frontend", "index.html")
USERS_FILE = os.path.join(BASE_DIR, "users_db.json")
os.makedirs(STORAGE_ROOT, exist_ok=True)

STORAGE_LIMIT_BYTES = 500 * 1024 * 1024  # 500 MB per user
ACTIVE_SESSIONS = {}  # token -> username
ACTIVE_OTPS = {}      # username -> {"code": str, "expires": float}
SHARE_TOKENS = {}     # token -> {"username": str, "filename": str, "expires": float}

# Optional global SMTP settings for sending real password-reset emails to any user
SMTP_EMAIL = os.getenv("AEGIS_SMTP_EMAIL", "")
SMTP_APP_PASSWORD = os.getenv("AEGIS_SMTP_PASSWORD", "")

def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def load_users() -> dict:
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def get_user_dir(username: str) -> str:
    safe_user = re.sub(r"[^a-zA-Z0-9_-]", "", username.lower())
    user_dir = os.path.join(STORAGE_ROOT, safe_user)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def get_current_user(token: str) -> str:
    username = ACTIVE_SESSIONS.get(token)
    if not username:
        raise HTTPException(status_code=401, detail="Session expired or unauthorized. Please log in.")
    return username

def send_real_email_otp(recipient: str, username: str, code: str) -> bool:
    if not SMTP_EMAIL or not SMTP_APP_PASSWORD:
        return False
    msg = EmailMessage()
    msg["Subject"] = "AEGIS CLOUD - Account Password Reset OTP"
    msg["From"] = SMTP_EMAIL
    msg["To"] = recipient
    msg.set_content(f"Hello {username},\n\nYour AEGIS CLOUD 6-digit password reset OTP is: {code}\n\nThis code expires in 5 minutes.")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
        server.send_message(msg)
    return True

def format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str = ""
    mobile: str = ""

class LoginRequest(BaseModel):
    username: str
    password: str

class RecoveryUpdateRequest(BaseModel):
    email: str
    mobile: str

class PasswordChangeRequest(BaseModel):
    new_password: str

class OtpRequest(BaseModel):
    username: str
    contact: str

class OtpResetRequest(BaseModel):
    username: str
    otp: str
    new_password: str

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    if os.path.exists(FRONTEND_FILE):
        with open(FRONTEND_FILE, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AEGIS CLOUD Multi-User API Online</h1>"

@app.post("/register")
def register(data: RegisterRequest):
    username = data.username.strip().lower()
    if not re.match(r"^[a-z0-9_-]{3,20}$", username):
        raise HTTPException(status_code=400, detail="Username must be 3-20 characters (letters, numbers, _ or -).")
    if len(data.password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters.")

    users = load_users()
    if username in users:
        raise HTTPException(status_code=409, detail="Username already taken. Choose another.")

    users[username] = {
        "password_hash": hash_pw(data.password.strip()),
        "email": data.email.strip(),
        "mobile": data.mobile.strip(),
        "created_at": datetime.now().strftime("%d %b %Y")
    }
    save_users(users)
    get_user_dir(username)
    return {"status": "registered", "username": username}

@app.post("/login")
def login(data: LoginRequest):
    username = data.username.strip().lower()
    users = load_users()
    user = users.get(username)
    if not user or user["password_hash"] != hash_pw(data.password.strip()):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = uuid.uuid4().hex
    ACTIVE_SESSIONS[token] = username
    return {
        "status": "logged_in",
        "token": token,
        "username": username,
        "email": user.get("email", ""),
        "mobile": user.get("mobile", "")
    }

@app.post("/logout")
def logout(x_token: str = Header(...)):
    ACTIVE_SESSIONS.pop(x_token, None)
    return {"status": "logged_out"}

@app.post("/save-recovery")
def save_recovery(data: RecoveryUpdateRequest, x_token: str = Header(...)):
    username = get_current_user(x_token)
    users = load_users()
    users[username]["email"] = data.email.strip()
    users[username]["mobile"] = data.mobile.strip()
    save_users(users)
    return {"status": "recovery_saved"}

@app.post("/change-password")
def change_password(data: PasswordChangeRequest, x_token: str = Header(...)):
    username = get_current_user(x_token)
    if len(data.new_password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters.")
    users = load_users()
    users[username]["password_hash"] = hash_pw(data.new_password.strip())
    save_users(users)
    return {"status": "password_updated"}

@app.post("/request-otp")
def request_otp(data: OtpRequest):
    username = data.username.strip().lower()
    contact = data.contact.strip().lower()
    users = load_users()
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    saved_email = user.get("email", "").strip().lower()
    saved_mobile = user.get("mobile", "").strip()
    if not contact or contact not in [saved_email, saved_mobile]:
        raise HTTPException(status_code=401, detail="Email or mobile does not match this account.")

    code = str(random.randint(100000, 999999))
    ACTIVE_OTPS[username] = {"code": code, "expires": time.time() + 300}
    emailed = False
    if contact == saved_email:
        try:
            emailed = send_real_email_otp(saved_email, username, code)
        except Exception as e:
            print(f"[SMTP ERROR] {e}")

    print(f"\n[AEGIS CLOUD OTP] User '{username}' ({data.contact.strip()}): {code} (valid 5 mins)\n")
    msg = "OTP sent to your registered email!" if emailed else "6-digit OTP generated! Check server console."
    return {"status": "otp_sent", "message": msg}

@app.post("/reset-password-otp")
def reset_password_otp(data: OtpResetRequest):
    username = data.username.strip().lower()
    otp_record = ACTIVE_OTPS.get(username)
    if not otp_record or time.time() > otp_record["expires"]:
        raise HTTPException(status_code=400, detail="OTP expired or not requested.")
    if data.otp.strip() != otp_record["code"]:
        raise HTTPException(status_code=401, detail="Invalid OTP.")
    if len(data.new_password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters.")

    users = load_users()
    users[username]["password_hash"] = hash_pw(data.new_password.strip())
    save_users(users)
    ACTIVE_OTPS.pop(username, None)
    return {"status": "password_reset_complete"}

@app.post("/share/{filename}")
def create_share_link(filename: str, request: Request, x_token: str = Header(...)):
    username = get_current_user(x_token)
    file_path = os.path.join(get_user_dir(username), os.path.basename(filename))
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    share_id = uuid.uuid4().hex[:16]
def create_share_link(filename: str, request: Request, x_token: str = Header(...)):
    username = get_current_user(x_token)
    file_path = os.path.join(get_user_dir(username), os.path.basename(filename))
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    share_id = uuid.uuid4().hex[:16]
    SHARE_TOKENS[share_id] = {"username": username, "filename": os.path.basename(filename), "expires": time.time() + 3600}
    base_url = str(request.base_url).rstrip("/")
    return {"share_url": f"{base_url}/s/{share_id}", "expires_in": "1 hour"}