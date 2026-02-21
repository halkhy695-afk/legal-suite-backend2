# =====================================================
# نظام إدارة مكتب المحامي هشام يوسف الخياط
# Backend مع MySQL
# =====================================================

from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Query, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import aiomysql
import os
from dotenv import load_dotenv
import uuid
import json

load_dotenv()

# =====================================================
# إعدادات التطبيق
# =====================================================
app = FastAPI(title="Al-Khayat Law Firm Management System", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_router = APIRouter(prefix="/api")

# =====================================================
# إعدادات الأمان
# =====================================================
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # أسبوع

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# =====================================================
# إعدادات MySQL
# =====================================================
MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
MYSQL_DB = os.environ.get("MYSQL_DB", "legal_suite")

pool = None

async def get_db_pool():
    global pool
    if pool is None:
        pool = await aiomysql.create_pool(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            db=MYSQL_DB,
            charset='utf8mb4',
            autocommit=True,
            minsize=1,
            maxsize=10
        )
    return pool

async def execute_query(query: str, params: tuple = None, fetch_one: bool = False, fetch_all: bool = False):
    """تنفيذ استعلام SQL"""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            await cursor.execute(query, params)
            if fetch_one:
                return await cursor.fetchone()
            if fetch_all:
                return await cursor.fetchall()
            return cursor.lastrowid

# =====================================================
# النماذج (Models)
# =====================================================
class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    phone: Optional[str] = None
    role: str = "client"
    national_id: Optional[str] = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str
