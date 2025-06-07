from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Request, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.background import BackgroundTasks
from pathlib import Path
from datetime import datetime, timedelta
import shutil
import os
import mimetypes
import json
import hmac
import hashlib
import base64
from dotenv import load_dotenv
load_dotenv()

# === CONFIGURATION ===
UPLOAD_DIR = Path("storage")
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
TOKEN = os.getenv("TOKEN")
SIGNING_KEY = os.getenv("SIGNING_KEY").encode()
FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "").split(",")
EXPIRATION_DAYS = 60
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
METADATA_FILE = UPLOAD_DIR / ".metadata.json"
RATE_LIMIT_FILE = UPLOAD_DIR / ".ratelimit.json"
MAX_UPLOADS_PER_IP_PER_DAY = 100

app = FastAPI()

# === MIDDLEWARE CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === SECURITY ===
auth_scheme = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    if credentials.credentials != TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")

# === MIDDLEWARE FILE SIZE ===
@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    if request.headers.get("content-length") and int(request.headers["content-length"]) > MAX_FILE_SIZE:
        return JSONResponse(status_code=413, content={"detail": "File too large"})
    return await call_next(request)

# === METADATA HANDLING ===
def load_metadata():
    if METADATA_FILE.exists():
        return json.loads(METADATA_FILE.read_text())
    return {}

def save_metadata(metadata):
    METADATA_FILE.write_text(json.dumps(metadata, indent=2))

# === RATE LIMIT HANDLING ===
def load_ratelimit():
    if RATE_LIMIT_FILE.exists():
        return json.loads(RATE_LIMIT_FILE.read_text())
    return {}

def save_ratelimit(data):
    RATE_LIMIT_FILE.write_text(json.dumps(data, indent=2))

# === PRESIGNED URL ===
def generate_signature(filename: str, expires: int) -> str:
    payload = f"{filename}:{expires}"
    signature = hmac.new(SIGNING_KEY, payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode()

@app.post("/generate-upload-url")
def generate_upload_url(filename: str, credentials: HTTPAuthorizationCredentials = Depends(verify_token)):
    ext = filename.split(".")[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Invalid file type")

    expires = int((datetime.utcnow() + timedelta(minutes=1)).timestamp())
    sig = generate_signature(filename, expires)
    return {"upload_url": f"/upload?filename={filename}&expires={expires}&sig={sig}"}

# === FILE UPLOAD ===
@app.post("/upload")
def upload_file(request: Request, file: UploadFile = File(...)):
    filename = request.query_params.get("filename")
    expires = request.query_params.get("expires")
    sig = request.query_params.get("sig")

    if not filename or not expires or not sig:
        raise HTTPException(status_code=400, detail="Missing parameters")

    expected_sig = generate_signature(filename, int(expires))
    if sig != expected_sig:
        raise HTTPException(status_code=403, detail="Invalid signature")

    if datetime.utcnow().timestamp() > int(expires):
        raise HTTPException(status_code=403, detail="Signature expired")

    ext = filename.split(".")[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type not allowed")

    client_ip = request.client.host
    ratelimit = load_ratelimit()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    if today not in ratelimit:
        ratelimit[today] = {}
    if client_ip not in ratelimit[today]:
        ratelimit[today][client_ip] = 0
    if ratelimit[today][client_ip] >= MAX_UPLOADS_PER_IP_PER_DAY:
        raise HTTPException(status_code=429, detail="Upload limit reached for today")

    UPLOAD_DIR.mkdir(exist_ok=True)
    file_path = UPLOAD_DIR / filename
    with file_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    metadata = load_metadata()
    metadata[filename] = {"last_access": datetime.utcnow().isoformat()}
    save_metadata(metadata)

    ratelimit[today][client_ip] += 1
    save_ratelimit(ratelimit)

    return {"url": f"/files/{filename}"}

# === FILE DOWNLOAD (UPDATES LAST ACCESS) ===
@app.get("/files/{filename}")
def get_file(filename: str, request: Request):
    file_path = UPLOAD_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    metadata = load_metadata()
    if filename in metadata:
        metadata[filename]["last_access"] = datetime.utcnow().isoformat()
        save_metadata(metadata)

    mime_type, _ = mimetypes.guess_type(filename)
    return FileResponse(file_path, media_type=mime_type)

# === LIST FILES ===
@app.get("/list")
def list_files(credentials: HTTPAuthorizationCredentials = Depends(verify_token)):
    metadata = load_metadata()
    files = []
    for file in UPLOAD_DIR.iterdir():
        if file.is_file() and not file.name.startswith("."):
            last_access = metadata.get(file.name, {}).get("last_access")
            files.append({
                "filename": file.name,
                "url": f"/files/{file.name}",
                "last_access": last_access,
                "size": file.stat().st_size
            })
    return files

# === DELETE FILE ===
@app.post("/delete")
def delete_file(filename: str = Form(...), credentials: HTTPAuthorizationCredentials = Depends(verify_token)):
    file_path = UPLOAD_DIR / filename
    if file_path.exists():
        file_path.unlink()
    metadata = load_metadata()
    metadata.pop(filename, None)
    save_metadata(metadata)
    return {"detail": f"{filename} deleted"}

# === AUTO DELETE FILES (OLDER THAN 30 DAYS INACTIVITY) ===
@app.on_event("startup")
def cleanup_old_files():
    metadata = load_metadata()
    now = datetime.utcnow()
    changed = False
    for filename, info in list(metadata.items()):
        last_access = datetime.fromisoformat(info.get("last_access"))
        if now - last_access > timedelta(days=EXPIRATION_DAYS):
            file_path = UPLOAD_DIR / filename
            if file_path.exists():
                file_path.unlink()
            del metadata[filename]
            changed = True
    if changed:
        save_metadata(metadata)
