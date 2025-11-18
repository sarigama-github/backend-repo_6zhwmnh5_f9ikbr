import os
import hashlib
import secrets
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User as UserSchema, BlogPost as BlogPostSchema, ContactMessage as ContactSchema

app = FastAPI(title="SaaS Starter API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Utilities ----------

def _hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    import hashlib as _hash
    hashed = _hash.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return hashed.hex(), salt


def _serialize_doc(doc: dict) -> dict:
    if not doc:
        return doc
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    # convert datetime to isoformat if present
    from datetime import datetime
    for k, v in list(d.items()):
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


# ---------- Models (requests/responses) ----------

class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    token: str
    name: str
    email: EmailStr


# ---------- Routes ----------

@app.get("/")
def read_root():
    return {"message": "SaaS Starter Backend is running"}


@app.post("/api/auth/signup", response_model=AuthResponse)
def signup(payload: SignupRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    # check existing
    existing = db["user"].find_one({"email": str(payload.email).lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash, salt = _hash_password(payload.password)
    new_user = UserSchema(
        name=payload.name,
        email=str(payload.email).lower(),
        password_hash=password_hash,
        salt=salt,
        is_active=True,
        tokens=[],
    )
    user_id = create_document("user", new_user)
    # create and attach token
    token = secrets.token_urlsafe(32)
    from bson import ObjectId
    db["user"].update_one({"_id": ObjectId(user_id)}, {"$push": {"tokens": token}})
    return AuthResponse(token=token, name=new_user.name, email=new_user.email)


@app.post("/api/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["user"].find_one({"email": str(payload.email).lower()})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    stored_hash = user.get("password_hash")
    salt = user.get("salt")
    if not stored_hash or not salt:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    computed_hash, _ = _hash_password(payload.password, salt)
    if computed_hash != stored_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_urlsafe(32)
    db["user"].update_one({"_id": user["_id"]}, {"$push": {"tokens": token}})
    return AuthResponse(token=token, name=user.get("name", ""), email=user.get("email", ""))


@app.get("/api/blogs")
def list_blogs(limit: int = 6):
    posts = get_documents("blogpost", {}, limit)
    return {"items": [_serialize_doc(p) for p in posts]}


@app.get("/api/blogs/{slug}")
def get_blog(slug: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    post = db["blogpost"].find_one({"slug": slug})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return _serialize_doc(post)


@app.post("/api/contact")
def submit_contact(payload: ContactSchema):
    create_document("contactmessage", payload)
    return {"status": "ok"}


@app.get("/test")
def test_database():
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
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
