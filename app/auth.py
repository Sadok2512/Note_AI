from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pydantic.networks import EmailStr
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

# Initialize router
router = APIRouter()

# ---------------------------
# Configuration
# ---------------------------

# Secret key for JWT encoding/decoding
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-for-dev")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URI must be set in environment")

try:
    client = MongoClient(MONGO_URI)
    db = client["noteai"]
    users_collection = db["users"]
except Exception as e:
    raise ConnectionError(f"Failed to connect to MongoDB: {str(e)}")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------
# Pydantic Models
# ---------------------------

class AuthData(BaseModel):
    email: EmailStr
    password: str


# ---------------------------
# Helper Functions
# ---------------------------

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ---------------------------
# Routes
# ---------------------------

@router.post("/register")
def register_user(data: AuthData):
    # Check if user already exists
    existing_user = users_collection.find_one({"email": data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash password and insert new user
    hashed_password = pwd_context.hash(data.password)
    user = {"email": data.email, "password": hashed_password}
    result = users_collection.insert_one(user)

    # Generate JWT token
    token = create_access_token({"sub": data.email})

    return {
        "user_id": str(result.inserted_id),
        "email": data.email,
        "token": token
    }


@router.post("/login")
def login_user(data: AuthData):
    # Find user by email
    user = users_collection.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Verify password
    if not pwd_context.verify(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate JWT token
    token = create_access_token({"sub": data.email})
    return {
        "user_id": str(user["_id"]),
        "email": data.email,
        "token": token
    }