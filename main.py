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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_ROOT = os.path.join(BASE_DIR, "cloud_storage")
FRONTEND_FILE = os.path.join(BASE_DIR, "index.html")
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
    brevo_key = os.getenv("BREVO_API_KEY", "").strip()
    if not brevo_key:
        return False
    import urllib.request
    payload = json.dumps({
        "sender": {"name": "AEGIS CLOUD", "email": "avinashreddy8106583398@gmail.com"},
        "to": [{"email": recipient, "name": username}],
        "subject": "AEGIS CLOUD - Account Password Reset OTP",
        "textContent": f"Hello {username},\n\nYour AEGIS CLOUD 6-digit password reset OTP is: {code}\n\nThis code expires in 5 minutes."
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=payload,
        headers={
            "accept": "application/json",
            "api-key": brevo_key,
            "content-type": "application/json"
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return 200 <= resp.status < 300
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

LOGIN_HISTORY = []  # stores {"username": str, "time": str}

@app.post("/login")
def login(data: LoginRequest):
    username = data.username.strip().lower()
    users = load_users()
    user = users.get(username)
    if not user or user["password_hash"] != hash_pw(data.password.strip()):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    from datetime import timezone, timedelta
    ist_now = datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%d %b %Y, %I:%M %p IST")
    user["login_count"] = user.get("login_count", 0) + 1
    user["last_login"] = ist_now
    users[username] = user
    save_users(users)
    LOGIN_HISTORY.insert(0, {"username": username, "time": ist_now})
    del LOGIN_HISTORY[100:]

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
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(key: str = Query("")):
    admin_secret = os.getenv("ADMIN_KEY", "avinash123")
    if key != admin_secret:
        return """
        <html><body style="background:#0f172a;color:#f8fafc;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;">
        <form method="get" action="/admin" style="background:#1e293b;padding:28px;border-radius:10px;width:320px;">
            <h2 style="color:#38bdf8;margin-top:0;">AEGIS CLOUD Admin</h2>
            <input type="password" name="key" placeholder="Enter Admin Password" required style="width:100%;padding:10px;margin-bottom:12px;border-radius:6px;border:1px solid #334155;box-sizing:border-box;">
            <button type="submit" style="width:100%;padding:10px;background:#38bdf8;color:#0f172a;font-weight:bold;border:none;border-radius:6px;cursor:pointer;">View Users & History</button>
        </form></body></html>
        """
    users = load_users()
    user_rows = "".join(
        f"<tr><td>{u}</td><td>{d.get('email') or '-'}</td><td>{d.get('mobile') or '-'}</td><td>{d.get('created_at','-')}</td><td>{d.get('login_count',0)}</td><td>{d.get('last_login','Never')}</td></tr>"
        for u, d in users.items()
    ) or "<tr><td colspan='6'>No registered users yet</td></tr>"
    log_rows = "".join(
        f"<tr><td>{item['username']}</td><td>{item['time']}</td></tr>"
        for item in LOGIN_HISTORY
    ) or "<tr><td colspan='2'>No logins recorded in this session yet</td></tr>"
    return f"""
    <html><head><title>AEGIS CLOUD Admin</title>
    <style>
        body {{ font-family: Arial; background: #0f172a; color: #f8fafc; max-width: 900px; margin: 30px auto; padding: 0 16px; }}
        h1, h2 {{ color: #38bdf8; }}
        .stats {{ display: flex; gap: 16px; margin-bottom: 24px; }}
        .box {{ background: #1e293b; padding: 16px 22px; border-radius: 10px; flex: 1; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; margin-bottom: 28px; }}
        th, td {{ padding: 10px 14px; border-bottom: 1px solid #334155; text-align: left; font-size: 14px; }}
        th {{ background: #0284c7; color: #fff; }}
    </style></head><body>
    <h1>AEGIS CLOUD — Admin Monitor</h1>
    <div class="stats">
        <div class="box"><strong>Total Registered Users:</strong><h2>{len(users)}</h2></div>
        <div class="box"><strong>Active Online Sessions:</strong><h2>{len(ACTIVE_SESSIONS)}</h2></div>
        <div class="box"><strong>Recent Logins Recorded:</strong><h2>{len(LOGIN_HISTORY)}</h2></div>
    </div>
    <h2>Registered Users</h2>
    <table><tr><th>Username</th><th>Email</th><th>Mobile</th><th>Joined</th><th>Total Logins</th><th>Last Login</th></tr>{user_rows}</table>
    <h2>Recent Login History</h2>
    <table><tr><th>Username</th><th>Login Time (IST)</th></tr>{log_rows}</table>
    </body></html>
    """
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
