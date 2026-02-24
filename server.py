from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import base64
import certifi
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Union
import uuid
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from io import BytesIO
from fpdf import FPDF
import arabic_reshaper
from bidi.algorithm import get_display
import imaplib
import smtplib
import email as email_lib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.header import decode_header
import asyncio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# اتصال MongoDB مع دعم SSL لـ MongoDB Atlas
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
db_name = os.environ.get('DB_NAME', 'legal_suite')

# إضافة إعدادات SSL للـ Connection String إذا كان MongoDB Atlas
if 'mongodb+srv' in mongo_url or 'mongodb.net' in mongo_url:
    # إضافة معاملات TLS إلى الـ URL
    if '?' in mongo_url:
        if 'tls=' not in mongo_url.lower():
            mongo_url = mongo_url + '&tls=true&tlsAllowInvalidCertificates=true'
    else:
        mongo_url = mongo_url + '?tls=true&tlsAllowInvalidCertificates=true'
    
    client = AsyncIOMotorClient(
        mongo_url,
        serverSelectionTimeoutMS=30000,
        connectTimeoutMS=30000,
        socketTimeoutMS=30000
    )
else:
    client = AsyncIOMotorClient(mongo_url)

db = client[db_name]

app = FastAPI()
api_router = APIRouter(prefix="/api")

SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-this-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ==================== إعدادات البريد الخارجي (IMAP/SMTP) ====================
IMAP_SERVER = os.environ.get('IMAP_SERVER', 'mail.hklaw.sa')
IMAP_PORT = int(os.environ.get('IMAP_PORT', 993))
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'mail.hklaw.sa')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 465))
EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', '')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# دالة مساعدة لتحويل datetime إلى string
def convert_datetime_fields(data: dict) -> dict:
    """تحويل جميع حقول datetime إلى ISO string"""
    if data is None:
        return data
    result = dict(data)
    for key, value in result.items():
        if isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, dict):
            result[key] = convert_datetime_fields(value)
        elif isinstance(value, list):
            result[key] = [convert_datetime_fields(item) if isinstance(item, dict) else item for item in value]
    return result

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if user is None:
        raise credentials_exception
    
    # تحويل datetime إلى string
    user = convert_datetime_fields(user)
    return User(**user)

async def log_action(action_type: str, entity_type: str, entity_id: str, user_id: str, user_name: str, description: str):
    log_entry = AuditLog(
        action_type=action_type,
        entity_type=entity_type,
        entity_id=entity_id,
        user_id=user_id,
        user_name=user_name,
        description=description
    )
    doc = log_entry.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.audit_logs.insert_one(doc)

class UserRole:
    ADMIN = "admin"
    LAWYER = "lawyer"
    ACCOUNTANT = "accountant"
    STAFF = "staff"
    MARKETER = "marketer"
    CLIENT = "client"

# دالة مساعدة لتحويل التاريخ
def parse_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    phone: Optional[str] = None
    national_id: Optional[str] = None  # رقم الهوية للعملاء
    role: str
    department: Optional[str] = None
    first_login: bool = True
    created_at: Optional[str] = None  # سيتم تحويله من datetime إلى string

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    phone: Optional[str] = None
    national_id: Optional[str] = None  # رقم الهوية للعملاء
    role: str = UserRole.CLIENT
    department: Optional[str] = None

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

# نموذج إعدادات الدوام
class WorkSchedule(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schedule_type: str = "normal"  # normal أو ramadan
    work_days: List[str] = ["saturday", "sunday", "monday", "tuesday", "wednesday", "thursday"]
    morning_start: str = "08:00"
    morning_end: str = "17:00"
    evening_start: Optional[str] = None  # لدوام رمضان المسائي
    evening_end: Optional[str] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class WorkScheduleCreate(BaseModel):
    schedule_type: str = "normal"
    work_days: List[str] = ["saturday", "sunday", "monday", "tuesday", "wednesday", "thursday"]
    morning_start: str = "08:00"
    morning_end: str = "17:00"
    evening_start: Optional[str] = None
    evening_end: Optional[str] = None

# نموذج العملاء المحتملين (Leads)
class Lead(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    lead_number: str = ""
    full_name: str
    phone: str
    email: Optional[str] = None
    company: Optional[str] = None
    source: str = "direct"  # direct, referral, social_media, website, other
    interest: str = ""  # نوع الخدمة المهتم بها
    notes: Optional[str] = None
    status: str = "new"  # new, contacted, interested, proposal_sent, converted, lost
    assigned_to: Optional[str] = None
    assigned_to_name: Optional[str] = None
    last_contact: Optional[datetime] = None
    last_contact_type: Optional[str] = None  # whatsapp, call, email
    next_follow_up: Optional[datetime] = None
    created_by: Optional[str] = None
    created_by_name: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class LeadCreate(BaseModel):
    full_name: str
    phone: str
    email: Optional[str] = None
    company: Optional[str] = None
    source: str = "direct"
    interest: str = ""
    notes: Optional[str] = None

# نموذج العروض
class Proposal(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    proposal_number: str = ""
    lead_id: Optional[str] = None
    lead_name: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    phone: str
    email: Optional[str] = None
    title: str
    service_type: str
    description: str
    amount: float = 0
    discount: float = 0
    final_amount: float = 0
    validity_days: int = 30
    status: str = "draft"  # draft, sent, viewed, accepted, rejected, expired
    sent_at: Optional[datetime] = None
    sent_via: Optional[str] = None  # whatsapp, email
    viewed_at: Optional[datetime] = None
    response_at: Optional[datetime] = None
    response_notes: Optional[str] = None
    created_by: str
    created_by_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProposalCreate(BaseModel):
    lead_id: Optional[str] = None
    lead_name: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    phone: str
    email: Optional[str] = None
    title: str
    service_type: str
    description: str
    amount: float = 0
    discount: float = 0
    validity_days: int = 30

# نموذج سجل التواصل
class ContactLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    contact_type: str  # whatsapp_text, whatsapp_voice, call, email
    lead_id: Optional[str] = None
    lead_name: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    phone: str
    direction: str = "outgoing"  # outgoing, incoming
    duration: Optional[int] = None  # بالثواني للمكالمات
    notes: Optional[str] = None
    performed_by: str
    performed_by_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# نموذج القضايا المحدث
class Case(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_number: str = ""
    case_type: str  # نوع المعاملة
    title: str
    description: Optional[str] = None
    plaintiff_name: str = ""  # اسم المدعي
    defendant_name: str = ""  # اسم المدعى عليه
    client_name: str = ""  # اسم الموكل
    client_id: Optional[str] = None
    hearing_day: Optional[str] = None  # يوم الجلسة
    hearing_date: Optional[str] = None  # تاريخ الجلسة
    hearing_time: Optional[str] = None  # وقت الجلسة
    consultant_id: Optional[str] = None  # مستشار القضية
    consultant_name: Optional[str] = None
    responsible_id: Optional[str] = None  # مسؤول القضية
    responsible_name: Optional[str] = None
    lawyer_id: Optional[str] = None
    status: str = "active"
    court_name: Optional[str] = None
    next_hearing: Optional[datetime] = None
    # حقول تتبع آخر إجراء
    last_action: Optional[str] = None  # وصف آخر إجراء
    last_action_by: Optional[str] = None  # معرف الموظف
    last_action_by_name: Optional[str] = None  # اسم الموظف
    last_action_at: Optional[datetime] = None  # وقت آخر إجراء
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CaseCreate(BaseModel):
    case_type: str  # نوع المعاملة
    title: str
    description: Optional[str] = None
    plaintiff_name: str = ""  # اسم المدعي
    defendant_name: str = ""  # اسم المدعى عليه
    client_name: str = ""  # اسم الموكل
    client_id: Optional[str] = None
    hearing_day: Optional[str] = None  # يوم الجلسة
    hearing_date: Optional[str] = None  # تاريخ الجلسة
    hearing_time: Optional[str] = None  # وقت الجلسة
    consultant_id: Optional[str] = None  # مستشار القضية
    consultant_name: Optional[str] = None
    responsible_id: Optional[str] = None  # مسؤول القضية
    responsible_name: Optional[str] = None
    status: str = "active"
    court_name: Optional[str] = None
    next_hearing: Optional[datetime] = None

class CaseUpdate(BaseModel):
    status: Optional[str] = None
    last_action: Optional[str] = None
    hearing_date: Optional[str] = None
    hearing_time: Optional[str] = None
    notes: Optional[str] = None

class Appointment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    client_id: str
    client_name: str
    lawyer_id: str
    appointment_date: datetime
    duration_minutes: int
    status: str
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AppointmentCreate(BaseModel):
    title: str
    client_id: str
    client_name: str
    appointment_date: datetime
    duration_minutes: int = 60
    status: str = "scheduled"
    notes: Optional[str] = None

class Invoice(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    invoice_number: str
    client_id: str
    client_name: str
    case_id: Optional[str] = None
    amount: float
    status: str
    due_date: datetime
    description: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class InvoiceCreate(BaseModel):
    invoice_number: str
    client_id: str
    client_name: str
    case_id: Optional[str] = None
    amount: float
    status: str = "pending"
    due_date: datetime
    description: str

class Consultation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    consultation_number: str = ""
    client_id: str
    client_name: str
    client_email: str
    phone_number: Optional[str] = None
    subject: str
    message: str
    status: str
    response: Optional[str] = None
    attachments: List[dict] = []
    # حقول تتبع آخر إجراء
    last_action: Optional[str] = None
    last_action_by: Optional[str] = None
    last_action_by_name: Optional[str] = None
    last_action_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    responded_at: Optional[datetime] = None

class ConsultationCreate(BaseModel):
    subject: str
    message: str
    phone_number: Optional[str] = None
    attachments: List[dict] = []

class ConsultationResponse(BaseModel):
    response: str

class ConsultationUpdate(BaseModel):
    status: Optional[str] = None
    response: Optional[str] = None
    last_action: Optional[str] = None

class Document(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    case_id: Optional[str] = None
    client_id: str
    file_name: str
    file_url: str
    file_type: str
    uploaded_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class DocumentCreate(BaseModel):
    title: str
    case_id: Optional[str] = None
    client_id: str
    file_name: str
    file_url: str
    file_type: str

class GuestConsultation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    consultation_number: str = ""
    full_name: str
    phone: str
    subject: str
    message: str
    attachments: List[str] = []
    status: str = "pending"
    # ربط بالعميل (اختياري - إذا تم تحويله لعميل)
    linked_client_id: Optional[str] = None
    # حقول تتبع آخر إجراء
    last_action: Optional[str] = None
    last_action_by: Optional[str] = None
    last_action_by_name: Optional[str] = None
    last_action_at: Optional[datetime] = None
    response: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    responded_at: Optional[datetime] = None

class GuestConsultationCreate(BaseModel):
    full_name: str
    phone: str
    subject: str
    message: str
    attachments: List[str] = []

class GuestConsultationUpdate(BaseModel):
    status: Optional[str] = None
    response: Optional[str] = None
    last_action: Optional[str] = None
    linked_client_id: Optional[str] = None

# نموذج طلبات العملاء (قضايا جديدة، خدمات موثق)
class ClientRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_number: str = ""
    request_type: str  # case, notary
    client_id: str
    client_name: str
    client_national_id: Optional[str] = None  # رقم هوية العميل للربط
    # حقول القضية
    case_type: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    phone_number: Optional[str] = None
    # حقول الموثق
    service_type: Optional[str] = None
    # المرفقات
    attachments: List[dict] = []
    # الحالة والتتبع
    status: str = "pending"
    assigned_to: Optional[str] = None
    assigned_to_name: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ClientRequestCreate(BaseModel):
    request_type: str
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    client_national_id: Optional[str] = None  # رقم هوية العميل
    case_type: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    phone_number: Optional[str] = None
    service_type: Optional[str] = None
    attachments: List[dict] = []

class Assignment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    assignment_number: str = ""
    task_type: str = "معاملة"
    case_id: Optional[str] = None
    consultation_id: Optional[str] = None
    # ربط بالعميل
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    assigned_to: List[str] = []
    assigned_to_names: List[str] = []
    assigned_by: str
    assigned_by_name: str
    instructions: str
    status: str = "pending"
    response: Optional[str] = None
    # حقول تتبع آخر إجراء
    last_action: Optional[str] = None
    last_action_by: Optional[str] = None
    last_action_by_name: Optional[str] = None
    last_action_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AssignmentCreate(BaseModel):
    task_type: str = "معاملة"
    case_id: Optional[str] = None
    consultation_id: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    assigned_to: List[str] = []
    assigned_to_names: List[str] = []
    instructions: str

class AssignmentUpdate(BaseModel):
    response: str
    status: str
    last_action: Optional[str] = None
    reassign_to: Optional[str] = None
    reassign_to_name: Optional[str] = None

class ClientCaseUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    update_text: str
    updated_by: str
    updated_by_name: str
    visible_to_client: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ClientCaseUpdateCreate(BaseModel):
    case_id: str
    update_text: str
    visible_to_client: bool = True

class Message(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    assignment_id: Optional[str] = None
    case_id: Optional[str] = None
    from_user_id: str
    from_user_name: str
    to_user_id: str
    to_user_name: str
    message: str
    read: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MessageCreate(BaseModel):
    assignment_id: Optional[str] = None
    case_id: Optional[str] = None
    to_user_id: str
    to_user_name: str
    message: str

class AuditLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: str
    entity_type: str
    entity_id: str
    user_id: str
    user_name: str
    description: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Fee(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: Optional[str] = None
    consultation_id: Optional[str] = None
    client_id: str
    client_name: str
    fee_type: str
    amount: Optional[float] = None
    percentage: Optional[float] = None
    total_amount: float
    payment_method: str
    payment_status: str
    installments: List[dict] = []
    notes: Optional[str] = None
    created_by: str
    created_by_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class FeeCreate(BaseModel):
    case_id: Optional[str] = None
    consultation_id: Optional[str] = None
    client_id: str
    client_name: str
    fee_type: str
    amount: Optional[float] = None
    percentage: Optional[float] = None
    total_amount: float
    payment_method: str
    payment_status: str = "pending"
    installments: List[dict] = []
    notes: Optional[str] = None

class Voucher(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    voucher_number: str
    voucher_type: str
    amount: float
    payment_method: str
    case_id: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    description: str
    created_by: str
    created_by_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class VoucherCreate(BaseModel):
    voucher_number: str
    voucher_type: str
    amount: float
    payment_method: str
    case_id: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    description: str

class Meeting(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    meeting_type: str
    meeting_mode: str
    participants: List[str]
    participant_names: List[str]
    scheduled_time: datetime
    duration_minutes: int
    meeting_link: Optional[str] = None
    notes: Optional[str] = None
    status: str = "scheduled"
    created_by: str
    created_by_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MeetingCreate(BaseModel):
    title: str
    meeting_type: str
    meeting_mode: str
    participants: List[str]
    participant_names: List[str]
    scheduled_time: datetime
    duration_minutes: int = 60
    meeting_link: Optional[str] = None
    notes: Optional[str] = None

# نظام الحضور والانصراف
class Attendance(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    date: str  # YYYY-MM-DD
    clock_in: Optional[datetime] = None
    clock_out: Optional[datetime] = None
    clock_in_location: Optional[dict] = None  # {lat, lng, address}
    clock_out_location: Optional[dict] = None
    total_hours: Optional[float] = None
    status: str = "present"  # present, absent, late, early_leave
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AttendanceClockIn(BaseModel):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None

class AttendanceClockOut(BaseModel):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None
    notes: Optional[str] = None

# ========== نماذج المكتبة القانونية ==========
class LegalDocumentCategory(str):
    SYSTEM = "system"  # الأنظمة السعودية
    REGULATION = "regulation"  # اللوائح التنفيذية
    PRECEDENT = "precedent"  # السوابق القضائية
    SUPREME_COURT = "supreme_court"  # قرارات المحكمة العليا
    LAW_BOOK = "law_book"  # كتب القانون
    FIQH_BOOK = "fiqh_book"  # كتب الفقه
    DECISION = "decision"  # القرارات والتعاميم

class LegalDocument(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    category: str  # system, regulation, precedent, supreme_court, law_book, fiqh_book, decision
    subcategory: Optional[str] = None  # التخصص (جنائي، تجاري، أحوال شخصية، عمالي، إداري)
    content: str
    summary: Optional[str] = None
    source: Optional[str] = None  # المصدر
    year: Optional[int] = None  # سنة الإصدار
    number: Optional[str] = None  # رقم النظام/القرار
    last_update: Optional[str] = None  # آخر تحديث للنظام
    keywords: List[str] = []
    file_url: Optional[str] = None
    uploaded_by: str
    uploaded_by_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None

class LegalDocumentCreate(BaseModel):
    title: str
    category: str
    subcategory: Optional[str] = None
    content: str
    summary: Optional[str] = None
    source: Optional[str] = None
    year: Optional[int] = None
    number: Optional[str] = None
    last_update: Optional[str] = None  # آخر تحديث للنظام
    keywords: List[str] = []
    file_url: Optional[str] = None

class LegalChatMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    user_id: str
    user_name: str
    role: str  # user or assistant
    content: str
    sources: List[dict] = []  # مصادر المعلومات المستخدمة في الرد
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class LegalChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None

# ========== نماذج نظام إدارة المهام المتقدم ==========

class TaskCategory:
    CASES = "cases"  # القضايا
    EXECUTION = "execution"  # التنفيذ
    REVIEWS = "reviews"  # المراجعات
    INTERNAL = "internal"  # المهام الداخلية

class TaskStatus:
    PENDING = "pending"  # قيد الانتظار
    IN_PROGRESS = "in_progress"  # قيد العمل
    COMPLETED = "completed"  # مكتمل
    ARCHIVED = "archived"  # مؤرشف
    CANCELLED = "cancelled"  # ملغي

class Task(BaseModel):
    """نموذج المهمة المتقدم"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_number: str = ""
    category: str = TaskCategory.CASES  # cases, execution, reviews, internal
    
    # مصدر المهمة
    source_type: Optional[str] = None  # client_request, case, consultation, employee_created
    source_id: Optional[str] = None  # معرف الطلب/القضية/الاستشارة المرتبطة
    request_number: Optional[str] = None  # رقم الطلب الأصلي
    
    # بيانات العميل (قابلة للإخفاء)
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    client_phone: Optional[str] = None
    
    # الحقول المخفية عن الموظفين
    hidden_fields: List[str] = []  # قائمة الحقول المخفية
    
    # تفاصيل المهمة
    title: str
    description: Optional[str] = None
    instructions: Optional[str] = None  # تعليمات من المدير
    priority: str = "normal"  # low, normal, high, urgent
    
    # التعيين
    assigned_to: List[str] = []  # قائمة معرفات الموظفين
    assigned_to_names: List[str] = []  # قائمة أسماء الموظفين
    assigned_by: Optional[str] = None
    assigned_by_name: Optional[str] = None
    assigned_at: Optional[datetime] = None
    
    # المرفقات
    attachments: List[dict] = []
    
    # الحالة والتتبع
    status: str = TaskStatus.PENDING
    due_date: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None
    
    # آخر إجراء
    last_action: Optional[str] = None
    last_action_by: Optional[str] = None
    last_action_by_name: Optional[str] = None
    last_action_at: Optional[datetime] = None
    
    # البيانات الوصفية
    created_by: Optional[str] = None
    created_by_name: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class TaskCreate(BaseModel):
    """إنشاء مهمة جديدة"""
    category: str = TaskCategory.CASES
    source_type: Optional[str] = None
    source_id: Optional[str] = None
    request_number: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    client_phone: Optional[str] = None
    title: str
    description: Optional[str] = None
    instructions: Optional[str] = None
    priority: str = "normal"
    assigned_to: List[str] = []
    assigned_to_names: List[str] = []
    hidden_fields: List[str] = []
    attachments: List[dict] = []
    due_date: Optional[datetime] = None

class TaskAssign(BaseModel):
    """تعيين مهمة"""
    assigned_to: List[str]
    assigned_to_names: List[str]
    instructions: Optional[str] = None
    hidden_fields: List[str] = []
    priority: str = "normal"
    due_date: Optional[datetime] = None

class TaskUpdate(BaseModel):
    """تحديث على مهمة من الموظف"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str
    update_text: str
    update_type: str = "progress"  # progress, note, completion, issue
    updated_by: str
    updated_by_name: str
    visible_to_client: bool = True  # ظاهر للعميل
    attachments: List[dict] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class TaskUpdateCreate(BaseModel):
    """إنشاء تحديث جديد"""
    update_text: str
    update_type: str = "progress"
    visible_to_client: bool = True
    attachments: List[dict] = []

class WorkScheduleTable(BaseModel):
    """جدول العمل (ظاهر لجميع الموظفين)"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str  # cases, execution, reviews, internal
    name: str
    description: Optional[str] = None
    visible_to_all: bool = True  # ظاهر لجميع الموظفين
    visible_to_roles: List[str] = []  # أدوار محددة يمكنها الرؤية
    created_by: str
    created_by_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class EmployeeTaskReport(BaseModel):
    """تقرير أداء الموظف"""
    employee_id: str
    employee_name: str
    total_tasks: int = 0
    completed_tasks: int = 0
    in_progress_tasks: int = 0
    pending_tasks: int = 0
    completion_rate: float = 0.0
    average_completion_days: float = 0.0
    tasks_by_category: dict = {}

# ========== نظام الإشعارات ==========

class NotificationType:
    TASK_ASSIGNED = "task_assigned"  # تم تعيين مهمة
    TASK_UPDATED = "task_updated"  # تحديث على مهمة
    TASK_COMPLETED = "task_completed"  # مهمة مكتملة
    EMAIL_RECEIVED = "email_received"  # بريد جديد
    MEETING_REMINDER = "meeting_reminder"  # تذكير باجتماع
    SYSTEM = "system"  # إشعار نظام

class Notification(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str  # المستخدم المستهدف
    notification_type: str  # نوع الإشعار
    title: str
    message: str
    link: Optional[str] = None  # رابط للانتقال إليه
    related_id: Optional[str] = None  # معرف العنصر المرتبط (مهمة، بريد، إلخ)
    related_type: Optional[str] = None  # نوع العنصر (task, email, meeting)
    is_read: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class NotificationCreate(BaseModel):
    user_id: str
    notification_type: str
    title: str
    message: str
    link: Optional[str] = None
    related_id: Optional[str] = None
    related_type: Optional[str] = None

# ========== نظام البريد الداخلي ==========

class EmailStatus:
    DRAFT = "draft"  # مسودة
    SENT = "sent"  # مرسل
    RECEIVED = "received"  # مستلم
    DELETED = "deleted"  # محذوف
    ARCHIVED = "archived"  # مؤرشف

class EmailPriority:
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"

class InternalEmail(BaseModel):
    """نموذج البريد الداخلي"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    
    # المرسل
    sender_id: str
    sender_name: str
    sender_email: str
    
    # المستلمين
    recipients: List[dict] = []  # [{id, name, email, type: "to"|"cc"|"bcc"}]
    
    # محتوى البريد
    subject: str
    body: str
    body_html: Optional[str] = None
    
    # المرفقات
    attachments: List[dict] = []  # [{name, type, size, data}]
    
    # ربط بالمهام
    related_task_id: Optional[str] = None
    related_task_number: Optional[str] = None
    
    # الحالة
    priority: str = EmailPriority.NORMAL
    is_starred: bool = False
    is_external: bool = False  # هل هو بريد خارجي
    external_email: Optional[str] = None  # عنوان البريد الخارجي
    
    # سلسلة الرد
    thread_id: Optional[str] = None  # معرف السلسلة
    reply_to_id: Optional[str] = None  # رد على بريد محدد
    is_reply: bool = False
    is_forwarded: bool = False
    
    # التتبع
    status: str = EmailStatus.SENT
    sent_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class EmailRecipient(BaseModel):
    """نموذج حالة البريد لكل مستلم"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email_id: str
    user_id: str
    user_email: str
    recipient_type: str = "to"  # to, cc, bcc
    is_read: bool = False
    is_starred: bool = False
    is_deleted: bool = False
    is_archived: bool = False
    folder: str = "inbox"  # inbox, sent, drafts, trash, archive
    read_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None

class EmailCompose(BaseModel):
    """إنشاء بريد جديد"""
    recipients: List[dict]  # [{id, name, email, type}]
    subject: str
    body: str
    body_html: Optional[str] = None
    attachments: List[dict] = []
    priority: str = EmailPriority.NORMAL
    related_task_id: Optional[str] = None
    is_external: bool = False
    external_email: Optional[str] = None
    reply_to_id: Optional[str] = None
    is_reply: bool = False
    is_forwarded: bool = False
    save_as_draft: bool = False

class EmailUpdate(BaseModel):
    """تحديث بريد"""
    is_read: Optional[bool] = None
    is_starred: Optional[bool] = None
    is_deleted: Optional[bool] = None
    is_archived: Optional[bool] = None
    folder: Optional[str] = None

@api_router.post("/auth/register", response_model=Token)
async def register(user_input: UserCreate):
    # التسجيل العام للعملاء فقط
    if user_input.role != UserRole.CLIENT:
        user_input.role = UserRole.CLIENT  # فرض دور العميل
    
    existing_user = await db.users.find_one({"email": user_input.email}, {"_id": 0})
    if existing_user:
        raise HTTPException(status_code=400, detail="البريد الإلكتروني مسجل مسبقاً")
    
    # التحقق من رقم الهوية للعملاء
    if user_input.national_id:
        # التحقق من أن رقم الهوية 10 أرقام
        if not user_input.national_id.isdigit() or len(user_input.national_id) != 10:
            raise HTTPException(status_code=400, detail="رقم الهوية يجب أن يتكون من 10 أرقام")
        
        # التحقق من عدم تكرار رقم الهوية
        existing_national_id = await db.users.find_one({"national_id": user_input.national_id}, {"_id": 0})
        if existing_national_id:
            raise HTTPException(status_code=400, detail="رقم الهوية مسجل مسبقاً")
    
    hashed_password = get_password_hash(user_input.password)
    user_dict = user_input.model_dump(exclude={"password"})
    user_dict['created_at'] = datetime.now(timezone.utc).isoformat()  # إضافة التاريخ كـ string
    user_obj = User(**user_dict)
    user_in_db = UserInDB(**user_obj.model_dump(), hashed_password=hashed_password)
    
    doc = user_in_db.model_dump()
    await db.users.insert_one(doc)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_obj.id}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer", user=user_obj)

@api_router.post("/admin/create-user", response_model=User)
async def admin_create_user(user_input: UserCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only admins can create users")
    
    existing_user = await db.users.find_one({"email": user_input.email}, {"_id": 0})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user_input.password)
    user_dict = user_input.model_dump(exclude={"password"})
    user_dict['created_at'] = datetime.now(timezone.utc).isoformat()  # إضافة التاريخ كـ string
    user_obj = User(**user_dict)
    user_in_db = UserInDB(**user_obj.model_dump(), hashed_password=hashed_password)
    
    doc = user_in_db.model_dump()
    await db.users.insert_one(doc)
    
    return user_obj

@api_router.delete("/admin/delete-user/{user_id}")
async def admin_delete_user(user_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only admins can delete users")
    
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    await db.users.delete_one({"id": user_id})
    
    await log_action("delete", "user", user_id, current_user.id, current_user.full_name,
                    f"حذف حساب المستخدم {user.get('full_name')}")
    
    return {"message": "User deleted successfully"}

@api_router.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"email": form_data.username}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    # تحويل datetime إلى string
    user = convert_datetime_fields(user)
    
    user_obj = User(**{k: v for k, v in user.items() if k != 'hashed_password'})
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_obj.id}, expires_delta=access_token_expires
    )
    
    await log_action("login", "user", user_obj.id, user_obj.id, user_obj.full_name, f"تسجيل دخول المستخدم {user_obj.full_name}")
    
    return Token(access_token=access_token, token_type="bearer", user=user_obj)

@api_router.post("/auth/change-password")
async def change_password(password_data: PasswordChange, current_user: User = Depends(get_current_user)):
    user = await db.users.find_one({"id": current_user.id}, {"_id": 0})
    
    if not verify_password(password_data.old_password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="كلمة المرور القديمة غير صحيحة")
    
    new_hashed_password = get_password_hash(password_data.new_password)
    await db.users.update_one(
        {"id": current_user.id}, 
        {"$set": {"hashed_password": new_hashed_password, "first_login": False}}
    )
    
    await log_action("password_change", "user", current_user.id, current_user.id, current_user.full_name, "تغيير كلمة المرور")
    
    return {"message": "تم تغيير كلمة المرور بنجاح"}

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

# ========== APIs جدول القضايا ==========
@api_router.get("/cases/table/all")
async def get_all_cases_table(current_user: User = Depends(get_current_user)):
    """جدول القضايا يظهر لجميع المستخدمين"""
    cases = await db.cases.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    for case in cases:
        if isinstance(case.get('created_at'), str):
            case['created_at'] = datetime.fromisoformat(case['created_at'])
        if isinstance(case.get('updated_at'), str):
            case['updated_at'] = datetime.fromisoformat(case['updated_at'])
        if isinstance(case.get('next_hearing'), str):
            case['next_hearing'] = datetime.fromisoformat(case['next_hearing'])
    
    return cases

@api_router.get("/cases", response_model=List[Case])
async def get_cases(current_user: User = Depends(get_current_user)):
    # جميع المستخدمين يمكنهم رؤية القضايا
    cases = await db.cases.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    for case in cases:
        if isinstance(case.get('created_at'), str):
            case['created_at'] = datetime.fromisoformat(case['created_at'])
        if isinstance(case.get('updated_at'), str):
            case['updated_at'] = datetime.fromisoformat(case['updated_at'])
        if isinstance(case.get('next_hearing'), str):
            case['next_hearing'] = datetime.fromisoformat(case['next_hearing'])
    
    return cases

@api_router.post("/cases", response_model=Case)
async def create_case(case_input: CaseCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.LAWYER, UserRole.ADMIN, UserRole.ACCOUNTANT, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="Only staff can create cases")
    
    # توليد رقم تسلسلي للقضية
    case_number = await get_next_sequence("cases", "CASE-")
    
    case_dict = case_input.model_dump()
    case_dict['lawyer_id'] = current_user.id
    case_dict['case_number'] = case_number
    case_obj = Case(**case_dict)
    
    doc = case_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    if doc.get('next_hearing'):
        doc['next_hearing'] = doc['next_hearing'].isoformat()
    
    await db.cases.insert_one(doc)
    
    await log_action("create", "case", case_obj.id, current_user.id, current_user.full_name, 
                    f"إنشاء قضية جديدة رقم {case_number}: {case_obj.title}")
    
    return case_obj

@api_router.get("/cases/{case_id}", response_model=Case)
async def get_case(case_id: str, current_user: User = Depends(get_current_user)):
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    if current_user.role == UserRole.CLIENT and case['client_id'] != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to view this case")
    
    if isinstance(case.get('created_at'), str):
        case['created_at'] = datetime.fromisoformat(case['created_at'])
    if isinstance(case.get('updated_at'), str):
        case['updated_at'] = datetime.fromisoformat(case['updated_at'])
    if isinstance(case.get('next_hearing'), str):
        case['next_hearing'] = datetime.fromisoformat(case['next_hearing'])
    
    return Case(**case)

@api_router.put("/cases/{case_id}", response_model=Case)
async def update_case(case_id: str, case_update: CaseCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.LAWYER, UserRole.ADMIN, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="Only staff can update cases")
    
    existing_case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not existing_case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    update_data = case_update.model_dump()
    update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
    update_data['last_action_at'] = datetime.now(timezone.utc).isoformat()
    update_data['last_action_by'] = current_user.id
    update_data['last_action_by_name'] = current_user.full_name
    if update_data.get('next_hearing'):
        update_data['next_hearing'] = update_data['next_hearing'].isoformat()
    
    await db.cases.update_one({"id": case_id}, {"$set": update_data})
    
    updated_case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if isinstance(updated_case.get('created_at'), str):
        updated_case['created_at'] = datetime.fromisoformat(updated_case['created_at'])
    if isinstance(updated_case.get('updated_at'), str):
        updated_case['updated_at'] = datetime.fromisoformat(updated_case['updated_at'])
    if isinstance(updated_case.get('next_hearing'), str):
        updated_case['next_hearing'] = datetime.fromisoformat(updated_case['next_hearing'])
    
    return Case(**updated_case)

# ========== APIs حذف البيانات (للمدير فقط) ==========
@api_router.delete("/cases/{case_id}")
async def delete_case(case_id: str, current_user: User = Depends(get_current_user)):
    """حذف قضية"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف القضايا")
    
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(status_code=404, detail="القضية غير موجودة")
    
    await db.cases.delete_one({"id": case_id})
    await db.case_updates.delete_many({"case_id": case_id})
    
    await log_action("delete", "case", case_id, current_user.id, current_user.full_name,
                    f"حذف القضية: {case.get('case_number')} - {case.get('title')}")
    
    return {"message": "تم حذف القضية بنجاح"}

@api_router.delete("/assignments/{assignment_id}")
async def delete_assignment(assignment_id: str, current_user: User = Depends(get_current_user)):
    """حذف مهمة"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف المهام")
    
    assignment = await db.assignments.find_one({"id": assignment_id}, {"_id": 0})
    if not assignment:
        raise HTTPException(status_code=404, detail="المهمة غير موجودة")
    
    await db.assignments.delete_one({"id": assignment_id})
    
    await log_action("delete", "assignment", assignment_id, current_user.id, current_user.full_name,
                    f"حذف المهمة: {assignment.get('assignment_number')}")
    
    return {"message": "تم حذف المهمة بنجاح"}

@api_router.delete("/guest-consultations/{consultation_id}")
async def delete_guest_consultation(consultation_id: str, current_user: User = Depends(get_current_user)):
    """حذف استشارة زائر"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف الاستشارات")
    
    consultation = await db.guest_consultations.find_one({"id": consultation_id}, {"_id": 0})
    if not consultation:
        raise HTTPException(status_code=404, detail="الاستشارة غير موجودة")
    
    await db.guest_consultations.delete_one({"id": consultation_id})
    
    await log_action("delete", "consultation", consultation_id, current_user.id, current_user.full_name,
                    f"حذف استشارة: {consultation.get('subject')}")
    
    return {"message": "تم حذف الاستشارة بنجاح"}

@api_router.delete("/consultations/{consultation_id}")
async def delete_consultation(consultation_id: str, current_user: User = Depends(get_current_user)):
    """حذف استشارة"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف الاستشارات")
    
    consultation = await db.consultations.find_one({"id": consultation_id}, {"_id": 0})
    if not consultation:
        raise HTTPException(status_code=404, detail="الاستشارة غير موجودة")
    
    await db.consultations.delete_one({"id": consultation_id})
    
    await log_action("delete", "consultation", consultation_id, current_user.id, current_user.full_name,
                    f"حذف استشارة: {consultation.get('subject')}")
    
    return {"message": "تم حذف الاستشارة بنجاح"}

@api_router.delete("/appointments/{appointment_id}")
async def delete_appointment(appointment_id: str, current_user: User = Depends(get_current_user)):
    """حذف موعد"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف المواعيد")
    
    appointment = await db.appointments.find_one({"id": appointment_id}, {"_id": 0})
    if not appointment:
        raise HTTPException(status_code=404, detail="الموعد غير موجود")
    
    await db.appointments.delete_one({"id": appointment_id})
    
    await log_action("delete", "appointment", appointment_id, current_user.id, current_user.full_name,
                    f"حذف موعد: {appointment.get('title')}")
    
    return {"message": "تم حذف الموعد بنجاح"}

@api_router.delete("/meetings/{meeting_id}")
async def delete_meeting(meeting_id: str, current_user: User = Depends(get_current_user)):
    """حذف اجتماع"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف الاجتماعات")
    
    meeting = await db.meetings.find_one({"id": meeting_id}, {"_id": 0})
    if not meeting:
        raise HTTPException(status_code=404, detail="الاجتماع غير موجود")
    
    await db.meetings.delete_one({"id": meeting_id})
    
    await log_action("delete", "meeting", meeting_id, current_user.id, current_user.full_name,
                    f"حذف اجتماع: {meeting.get('title')}")
    
    return {"message": "تم حذف الاجتماع بنجاح"}

@api_router.delete("/attendance/{attendance_id}")
async def delete_attendance(attendance_id: str, current_user: User = Depends(get_current_user)):
    """حذف سجل حضور"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف سجلات الحضور")
    
    attendance = await db.attendance.find_one({"id": attendance_id}, {"_id": 0})
    if not attendance:
        raise HTTPException(status_code=404, detail="السجل غير موجود")
    
    await db.attendance.delete_one({"id": attendance_id})
    
    await log_action("delete", "attendance", attendance_id, current_user.id, current_user.full_name,
                    f"حذف سجل حضور: {attendance.get('user_name')} - {attendance.get('date')}")
    
    return {"message": "تم حذف سجل الحضور بنجاح"}

# ========== APIs تحديث الإجراءات على القضايا/الاستشارات/المهام ==========
@api_router.post("/cases/{case_id}/action")
async def add_case_action(case_id: str, action_text: str, current_user: User = Depends(get_current_user)):
    """إضافة إجراء على قضية"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    now = datetime.now(timezone.utc)
    update_data = {
        "last_action": action_text,
        "last_action_by": current_user.id,
        "last_action_by_name": current_user.full_name,
        "last_action_at": now.isoformat(),
        "updated_at": now.isoformat()
    }
    
    result = await db.cases.update_one({"id": case_id}, {"$set": update_data})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="القضية غير موجودة")
    
    # تسجيل في سجل التحديثات للعميل
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if case and case.get('client_id'):
        update_record = {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "update_text": action_text,
            "updated_by": current_user.id,
            "updated_by_name": current_user.full_name,
            "visible_to_client": True,
            "created_at": now.isoformat()
        }
        await db.case_updates.insert_one(update_record)
    
    await log_action("update", "case", case_id, current_user.id, current_user.full_name, action_text)
    
    return {"message": "تم تسجيل الإجراء بنجاح"}

@api_router.post("/guest-consultations/{consultation_id}/action")
async def add_consultation_action(consultation_id: str, action_text: str, current_user: User = Depends(get_current_user)):
    """إضافة إجراء على استشارة"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    now = datetime.now(timezone.utc)
    update_data = {
        "last_action": action_text,
        "last_action_by": current_user.id,
        "last_action_by_name": current_user.full_name,
        "last_action_at": now.isoformat()
    }
    
    result = await db.guest_consultations.update_one({"id": consultation_id}, {"$set": update_data})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="الاستشارة غير موجودة")
    
    await log_action("update", "consultation", consultation_id, current_user.id, current_user.full_name, action_text)
    
    return {"message": "تم تسجيل الإجراء بنجاح"}

@api_router.post("/guest-consultations/{consultation_id}/link-client")
async def link_consultation_to_client(consultation_id: str, client_id: str, current_user: User = Depends(get_current_user)):
    """ربط استشارة بعميل"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER]:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    # التحقق من وجود العميل
    client = await db.users.find_one({"id": client_id, "role": "client"}, {"_id": 0})
    if not client:
        raise HTTPException(status_code=404, detail="العميل غير موجود")
    
    now = datetime.now(timezone.utc)
    update_data = {
        "linked_client_id": client_id,
        "last_action": f"تم ربط الاستشارة بالعميل: {client.get('full_name')}",
        "last_action_by": current_user.id,
        "last_action_by_name": current_user.full_name,
        "last_action_at": now.isoformat()
    }
    
    result = await db.guest_consultations.update_one({"id": consultation_id}, {"$set": update_data})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="الاستشارة غير موجودة")
    
    return {"message": "تم ربط الاستشارة بالعميل بنجاح"}

# ========== APIs بوابة العميل - عرض جميع العناصر المرتبطة ==========
@api_router.get("/client-portal/my-items")
async def get_client_items(current_user: User = Depends(get_current_user)):
    """جلب جميع العناصر المرتبطة بالعميل"""
    client_id = current_user.id
    
    # جلب القضايا المرتبطة بالعميل
    cases = await db.cases.find(
        {"client_id": client_id},
        {"_id": 0}
    ).sort("updated_at", -1).to_list(100)
    
    # جلب الاستشارات المرتبطة
    consultations = await db.consultations.find(
        {"client_id": client_id},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    # جلب استشارات الزوار المرتبطة
    guest_consultations = await db.guest_consultations.find(
        {"linked_client_id": client_id},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    # جلب المهام المرتبطة بالعميل
    assignments = await db.assignments.find(
        {"client_id": client_id},
        {"_id": 0}
    ).sort("updated_at", -1).to_list(100)
    
    # جلب المواعيد
    appointments = await db.appointments.find(
        {"client_id": client_id},
        {"_id": 0}
    ).sort("appointment_date", -1).to_list(100)
    
    # جلب تحديثات القضايا
    case_ids = [c.get('id') for c in cases]
    case_updates = []
    if case_ids:
        case_updates = await db.case_updates.find(
            {"case_id": {"$in": case_ids}, "visible_to_client": True},
            {"_id": 0}
        ).sort("created_at", -1).to_list(100)
    
    return {
        "cases": cases,
        "consultations": consultations,
        "guest_consultations": guest_consultations,
        "assignments": assignments,
        "appointments": appointments,
        "case_updates": case_updates,
        "summary": {
            "total_cases": len(cases),
            "active_cases": len([c for c in cases if c.get('status') == 'active']),
            "total_consultations": len(consultations) + len(guest_consultations),
            "total_assignments": len(assignments),
            "pending_assignments": len([a for a in assignments if a.get('status') == 'pending'])
        }
    }

@api_router.get("/client-portal/case/{case_id}/updates")
async def get_case_updates_for_client(case_id: str, current_user: User = Depends(get_current_user)):
    """جلب تحديثات قضية معينة للعميل"""
    # التحقق من أن القضية تخص هذا العميل
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(status_code=404, detail="القضية غير موجودة")
    
    if current_user.role == UserRole.CLIENT and case.get('client_id') != current_user.id:
        raise HTTPException(status_code=403, detail="غير مصرح بعرض هذه القضية")
    
    updates = await db.case_updates.find(
        {"case_id": case_id, "visible_to_client": True},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    return {
        "case": case,
        "updates": updates
    }

@api_router.get("/appointments", response_model=List[Appointment])
async def get_appointments(current_user: User = Depends(get_current_user)):
    if current_user.role == UserRole.LAWYER:
        appointments = await db.appointments.find({"lawyer_id": current_user.id}, {"_id": 0}).to_list(1000)
    else:
        appointments = await db.appointments.find({"client_id": current_user.id}, {"_id": 0}).to_list(1000)
    
    for apt in appointments:
        if isinstance(apt.get('created_at'), str):
            apt['created_at'] = datetime.fromisoformat(apt['created_at'])
        if isinstance(apt.get('appointment_date'), str):
            apt['appointment_date'] = datetime.fromisoformat(apt['appointment_date'])
    
    return appointments

@api_router.post("/appointments", response_model=Appointment)
async def create_appointment(appointment_input: AppointmentCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.LAWYER:
        raise HTTPException(status_code=403, detail="Only lawyers can create appointments")
    
    apt_dict = appointment_input.model_dump()
    apt_dict['lawyer_id'] = current_user.id
    apt_obj = Appointment(**apt_dict)
    
    doc = apt_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['appointment_date'] = doc['appointment_date'].isoformat()
    
    await db.appointments.insert_one(doc)
    return apt_obj

@api_router.get("/invoices", response_model=List[Invoice])
async def get_invoices(current_user: User = Depends(get_current_user)):
    if current_user.role in [UserRole.LAWYER, UserRole.ADMIN, UserRole.ACCOUNTANT]:
        invoices = await db.invoices.find({}, {"_id": 0}).to_list(1000)
    else:
        invoices = await db.invoices.find({"client_id": current_user.id}, {"_id": 0}).to_list(1000)
    
    for inv in invoices:
        if isinstance(inv.get('created_at'), str):
            inv['created_at'] = datetime.fromisoformat(inv['created_at'])
        if isinstance(inv.get('due_date'), str):
            inv['due_date'] = datetime.fromisoformat(inv['due_date'])
    
    return invoices

@api_router.post("/invoices", response_model=Invoice)
async def create_invoice(invoice_input: InvoiceCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.LAWYER:
        raise HTTPException(status_code=403, detail="Only lawyers can create invoices")
    
    inv_obj = Invoice(**invoice_input.model_dump())
    
    doc = inv_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['due_date'] = doc['due_date'].isoformat()
    
    await db.invoices.insert_one(doc)
    return inv_obj

@api_router.get("/consultations", response_model=List[Consultation])
async def get_consultations(current_user: User = Depends(get_current_user)):
    if current_user.role == UserRole.LAWYER:
        consultations = await db.consultations.find({}, {"_id": 0}).to_list(1000)
    else:
        consultations = await db.consultations.find({"client_id": current_user.id}, {"_id": 0}).to_list(1000)
    
    for cons in consultations:
        if isinstance(cons.get('created_at'), str):
            cons['created_at'] = datetime.fromisoformat(cons['created_at'])
        if cons.get('responded_at') and isinstance(cons['responded_at'], str):
            cons['responded_at'] = datetime.fromisoformat(cons['responded_at'])
    
    return consultations

@api_router.post("/consultations", response_model=Consultation)
async def create_consultation(consultation_input: ConsultationCreate, current_user: User = Depends(get_current_user)):
    # توليد رقم استشارة تسلسلي
    year = datetime.now().year
    counter = await db.sequences.find_one_and_update(
        {"_id": f"consultations_{year}"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    seq = counter.get("seq", 1)
    consultation_number = f"CONS-{year}-{seq:05d}"
    
    cons_dict = consultation_input.model_dump()
    cons_dict['consultation_number'] = consultation_number
    cons_dict['client_id'] = current_user.id
    cons_dict['client_name'] = current_user.full_name
    cons_dict['client_email'] = current_user.email
    cons_dict['status'] = 'pending'
    cons_obj = Consultation(**cons_dict)
    
    doc = cons_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.consultations.insert_one(doc)
    return cons_obj

@api_router.put("/consultations/{consultation_id}", response_model=Consultation)
async def respond_to_consultation(consultation_id: str, response_input: ConsultationResponse, current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.LAWYER:
        raise HTTPException(status_code=403, detail="Only lawyers can respond to consultations")
    
    existing = await db.consultations.find_one({"id": consultation_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Consultation not found")
    
    update_data = {
        'response': response_input.response,
        'status': 'responded',
        'responded_at': datetime.now(timezone.utc).isoformat()
    }
    
    await db.consultations.update_one({"id": consultation_id}, {"$set": update_data})
    
    updated = await db.consultations.find_one({"id": consultation_id}, {"_id": 0})
    if isinstance(updated.get('created_at'), str):
        updated['created_at'] = datetime.fromisoformat(updated['created_at'])
    if updated.get('responded_at') and isinstance(updated['responded_at'], str):
        updated['responded_at'] = datetime.fromisoformat(updated['responded_at'])
    
    return Consultation(**updated)

@api_router.get("/documents", response_model=List[Document])
async def get_documents(current_user: User = Depends(get_current_user)):
    if current_user.role == UserRole.LAWYER:
        documents = await db.documents.find({}, {"_id": 0}).to_list(1000)
    else:
        documents = await db.documents.find({"client_id": current_user.id}, {"_id": 0}).to_list(1000)
    
    for doc in documents:
        if isinstance(doc.get('created_at'), str):
            doc['created_at'] = datetime.fromisoformat(doc['created_at'])
    
    return documents

@api_router.post("/documents", response_model=Document)
async def create_document(document_input: DocumentCreate, current_user: User = Depends(get_current_user)):
    doc_dict = document_input.model_dump()
    doc_dict['uploaded_by'] = current_user.id
    doc_obj = Document(**doc_dict)
    
    doc = doc_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.documents.insert_one(doc)
    return doc_obj

@api_router.get("/clients", response_model=List[User])
async def get_clients(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.LAWYER:
        raise HTTPException(status_code=403, detail="Only lawyers can view clients list")
    
    clients = await db.users.find({"role": UserRole.CLIENT}, {"_id": 0, "hashed_password": 0}).to_list(1000)
    
    for client in clients:
        if isinstance(client.get('created_at'), str):
            client['created_at'] = datetime.fromisoformat(client['created_at'])
    
    return clients

@api_router.post("/guest-consultations", response_model=GuestConsultation)
async def create_guest_consultation(consultation_input: GuestConsultationCreate):
    cons_obj = GuestConsultation(**consultation_input.model_dump())
    
    doc = cons_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.guest_consultations.insert_one(doc)
    return cons_obj

# API لطلبات خدمات الموثق من الزوار (بدون تسجيل دخول)
@api_router.post("/guest-notary-request")
async def create_guest_notary_request(
    client_name: str = Form(...),
    phone: str = Form(...),
    subject: str = Form(...),
    description: str = Form(...),
    client_requests: str = Form(""),
    request_type: str = Form("notary"),
    service_type: str = Form("خدمات الموثق"),
    file_0: Optional[UploadFile] = File(None),
    file_1: Optional[UploadFile] = File(None),
    file_2: Optional[UploadFile] = File(None),
    file_3: Optional[UploadFile] = File(None),
    file_4: Optional[UploadFile] = File(None),
):
    # جمع الملفات المرفقة
    files_data = []
    for file in [file_0, file_1, file_2, file_3, file_4]:
        if file and file.filename:
            content = await file.read()
            # تحويل الملف لـ base64 للتخزين
            file_data = {
                "filename": file.filename,
                "content_type": file.content_type,
                "size": len(content),
                "data": base64.b64encode(content).decode('utf-8')
            }
            files_data.append(file_data)
    
    # إنشاء الطلب
    request_id = str(uuid.uuid4())
    notary_request = {
        "id": request_id,
        "client_name": client_name,
        "phone": phone,
        "subject": subject,
        "description": description,
        "client_requests": client_requests,
        "request_type": request_type,
        "service_type": service_type,
        "files": files_data,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_guest": True,
        "assigned_to": [],
        "actions": []
    }
    
    await db.client_requests.insert_one(notary_request)
    
    return {
        "success": True,
        "message": "تم إرسال طلبك بنجاح",
        "request_id": request_id
    }

@api_router.get("/guest-consultations", response_model=List[GuestConsultation])
async def get_guest_consultations(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.LAWYER:
        raise HTTPException(status_code=403, detail="Only lawyers can view guest consultations")
    
    consultations = await db.guest_consultations.find({}, {"_id": 0}).to_list(1000)
    
    for cons in consultations:
        if isinstance(cons.get('created_at'), str):
            cons['created_at'] = datetime.fromisoformat(cons['created_at'])
        if cons.get('responded_at') and isinstance(cons['responded_at'], str):
            cons['responded_at'] = datetime.fromisoformat(cons['responded_at'])
    
    return consultations

@api_router.put("/guest-consultations/{consultation_id}", response_model=GuestConsultation)
async def respond_to_guest_consultation(consultation_id: str, response_input: ConsultationResponse, current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.LAWYER:
        raise HTTPException(status_code=403, detail="Only lawyers can respond to consultations")
    
    existing = await db.guest_consultations.find_one({"id": consultation_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Consultation not found")
    
    update_data = {
        'response': response_input.response,
        'status': 'responded',
        'responded_at': datetime.now(timezone.utc).isoformat()
    }
    
    await db.guest_consultations.update_one({"id": consultation_id}, {"$set": update_data})
    
    updated = await db.guest_consultations.find_one({"id": consultation_id}, {"_id": 0})
    if isinstance(updated.get('created_at'), str):
        updated['created_at'] = datetime.fromisoformat(updated['created_at'])
    if updated.get('responded_at') and isinstance(updated['responded_at'], str):
        updated['responded_at'] = datetime.fromisoformat(updated['responded_at'])
    
    return GuestConsultation(**updated)

@api_router.get("/dashboard/stats")
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.LAWYER, UserRole.ADMIN, UserRole.ACCOUNTANT, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="Only staff can view dashboard stats")
    
    if current_user.role == UserRole.ADMIN:
        total_cases = await db.cases.count_documents({})
        active_cases = await db.cases.count_documents({"status": "active"})
        pending_assignments = await db.assignments.count_documents({"status": "pending"})
    else:
        total_cases = await db.cases.count_documents({"lawyer_id": current_user.id})
        active_cases = await db.cases.count_documents({"lawyer_id": current_user.id, "status": "active"})
        pending_assignments = await db.assignments.count_documents({"assigned_to": current_user.id, "status": "pending"})
    
    total_clients = await db.users.count_documents({"role": UserRole.CLIENT})
    pending_consultations = await db.consultations.count_documents({"status": "pending"})
    pending_guest_consultations = await db.guest_consultations.count_documents({"status": "pending"})
    
    upcoming_appointments = await db.appointments.find(
        {"status": "scheduled"},
        {"_id": 0}
    ).sort("appointment_date", 1).limit(5).to_list(5)
    
    for apt in upcoming_appointments:
        if isinstance(apt.get('created_at'), str):
            apt['created_at'] = datetime.fromisoformat(apt['created_at'])
        if isinstance(apt.get('appointment_date'), str):
            apt['appointment_date'] = datetime.fromisoformat(apt['appointment_date'])
    
    return {
        "total_cases": total_cases,
        "active_cases": active_cases,
        "total_clients": total_clients,
        "pending_consultations": pending_consultations,
        "pending_guest_consultations": pending_guest_consultations,
        "pending_assignments": pending_assignments,
        "upcoming_appointments": upcoming_appointments
    }

@api_router.get("/dashboard/admin-stats")
async def get_admin_dashboard_stats(current_user: User = Depends(get_current_user)):
    """إحصائيات لوحة تحكم المدير الشاملة"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه عرض هذه الإحصائيات")
    
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    # إحصائيات القضايا
    cases_stats = {
        "total": await db.client_requests.count_documents({"request_type": "case"}),
        "new": await db.client_requests.count_documents({"request_type": "case", "status": "pending"}),
        "in_progress": await db.client_requests.count_documents({"request_type": "case", "status": {"$in": ["in_progress", "under_review", "processing"]}}),
        "completed": await db.client_requests.count_documents({"request_type": "case", "status": "completed"})
    }
    
    # إحصائيات الاستشارات (من العملاء المسجلين)
    consultations_stats = {
        "total": await db.consultations.count_documents({}),
        "new": await db.consultations.count_documents({"status": "pending"}),
        "in_progress": await db.consultations.count_documents({"status": {"$in": ["in_progress", "under_review", "processing"]}}),
        "completed": await db.consultations.count_documents({"status": "completed"})
    }
    
    # إحصائيات استشارات الزوار
    guest_consultations_stats = {
        "total": await db.guest_consultations.count_documents({}),
        "new": await db.guest_consultations.count_documents({"status": "pending"}),
        "in_progress": await db.guest_consultations.count_documents({"status": {"$in": ["in_progress", "under_review", "processing"]}}),
        "completed": await db.guest_consultations.count_documents({"status": "completed"})
    }
    
    # إحصائيات خدمات الموثق
    notary_stats = {
        "total": await db.client_requests.count_documents({"request_type": "notary"}),
        "new": await db.client_requests.count_documents({"request_type": "notary", "status": "pending"}),
        "in_progress": await db.client_requests.count_documents({"request_type": "notary", "status": {"$in": ["in_progress", "under_review", "processing"]}}),
        "completed": await db.client_requests.count_documents({"request_type": "notary", "status": "completed"})
    }
    
    # إحصائيات المهام
    tasks_stats = {
        "total": await db.tasks.count_documents({}),
        "new": await db.tasks.count_documents({"status": "pending"}),
        "in_progress": await db.tasks.count_documents({"status": "in_progress"}),
        "completed": await db.tasks.count_documents({"status": "completed"}),
        "from_clients": await db.tasks.count_documents({"source": "client"}),
        "from_employees": await db.tasks.count_documents({"source": {"$ne": "client"}})
    }
    
    # الموظفين المتواجدين (سجلوا حضور اليوم ولم يسجلوا انصراف)
    online_employees = await db.attendance.find(
        {"date": today, "clock_in": {"$exists": True}, "clock_out": {"$exists": False}},
        {"_id": 0, "user_id": 1, "user_name": 1, "clock_in": 1, "clock_in_location": 1}
    ).to_list(100)
    
    # العملاء المتصلين (نشطين خلال آخر 15 دقيقة)
    fifteen_mins_ago = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
    online_clients = await db.user_sessions.find(
        {"role": "client", "last_activity": {"$gte": fifteen_mins_ago}},
        {"_id": 0, "user_id": 1, "user_name": 1, "last_activity": 1}
    ).to_list(100)
    
    # جدول حضور الموظفين اليوم
    today_attendance = await db.attendance.find(
        {"date": today},
        {"_id": 0}
    ).sort("clock_in", -1).to_list(100)
    
    # إجمالي الموظفين والعملاء
    total_employees = await db.users.count_documents({"role": {"$in": [UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF]}})
    total_clients = await db.users.count_documents({"role": UserRole.CLIENT})
    
    return {
        "cases": cases_stats,
        "consultations": consultations_stats,
        "guest_consultations": guest_consultations_stats,
        "notary": notary_stats,
        "tasks": tasks_stats,
        "online_employees": online_employees,
        "online_employees_count": len(online_employees),
        "online_clients": online_clients,
        "online_clients_count": len(online_clients),
        "today_attendance": today_attendance,
        "total_employees": total_employees,
        "total_clients": total_clients
    }

@api_router.post("/user-sessions/heartbeat")
async def update_user_session(current_user: User = Depends(get_current_user)):
    """تحديث نشاط المستخدم (heartbeat)"""
    now = datetime.now(timezone.utc).isoformat()
    
    await db.user_sessions.update_one(
        {"user_id": current_user.id},
        {
            "$set": {
                "user_id": current_user.id,
                "user_name": current_user.full_name,
                "role": current_user.role,
                "last_activity": now
            }
        },
        upsert=True
    )
    
    return {"status": "ok"}

@api_router.get("/employees", response_model=List[User])
async def get_employees(
    include_admins: bool = False,
    current_user: User = Depends(get_current_user)
):
    """جلب قائمة الموظفين (وتشمل المدراء اختيارياً للبريد)"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    # الأدوار المطلوبة
    roles = [UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF, UserRole.MARKETER]
    if include_admins:
        roles.append(UserRole.ADMIN)
    
    employees = await db.users.find(
        {"role": {"$in": roles}},
        {"_id": 0, "hashed_password": 0}
    ).to_list(1000)
    
    for emp in employees:
        if isinstance(emp.get('created_at'), str):
            emp['created_at'] = datetime.fromisoformat(emp['created_at'])
    
    return employees

@api_router.put("/users/{user_id}/role")
async def update_user_role(user_id: str, new_role: str, current_user: User = Depends(get_current_user)):
    """تحديث دور المستخدم (للمدير فقط)"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه تغيير الأدوار")
    
    valid_roles = [UserRole.ADMIN, UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF, UserRole.MARKETER, UserRole.CLIENT]
    if new_role not in valid_roles:
        raise HTTPException(status_code=400, detail="دور غير صالح")
    
    result = await db.users.update_one(
        {"id": user_id},
        {"$set": {"role": new_role}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="المستخدم غير موجود")
    
    return {"message": f"تم تحديث الدور إلى {new_role}"}

@api_router.post("/assignments", response_model=Assignment)
async def create_assignment(assignment_input: AssignmentCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="Only staff can create assignments")
    
    # توليد رقم تسلسلي
    assignment_number = await get_next_sequence("assignments", "ASN-")
    
    assignment_dict = assignment_input.model_dump()
    assignment_dict['assigned_by'] = current_user.id
    assignment_dict['assigned_by_name'] = current_user.full_name
    assignment_dict['assignment_number'] = assignment_number
    assignment_obj = Assignment(**assignment_dict)
    
    doc = assignment_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    
    await db.assignments.insert_one(doc)
    
    assigned_names = ", ".join(assignment_input.assigned_to_names) if assignment_input.assigned_to_names else "غير محدد"
    await log_action("create", "assignment", assignment_obj.id, current_user.id, current_user.full_name,
                    f"إحالة مهمة رقم {assignment_number} إلى {assigned_names}")
    
    return assignment_obj

@api_router.get("/assignments", response_model=List[Assignment])
async def get_assignments(current_user: User = Depends(get_current_user)):
    if current_user.role == UserRole.ADMIN:
        assignments = await db.assignments.find({}, {"_id": 0}).to_list(1000)
    elif current_user.role in [UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF]:
        # البحث في قائمة الموظفين المسندين
        assignments = await db.assignments.find(
            {"$or": [
                {"assigned_to": {"$in": [current_user.id]}},
                {"assigned_by": current_user.id}
            ]},
            {"_id": 0}
        ).to_list(1000)
    else:
        raise HTTPException(status_code=403, detail="Access denied")
    
    for asg in assignments:
        if isinstance(asg.get('created_at'), str):
            asg['created_at'] = datetime.fromisoformat(asg['created_at'])
        if isinstance(asg.get('updated_at'), str):
            asg['updated_at'] = datetime.fromisoformat(asg['updated_at'])
    
    return assignments

@api_router.put("/assignments/{assignment_id}", response_model=Assignment)
async def update_assignment(assignment_id: str, update_input: AssignmentUpdate, current_user: User = Depends(get_current_user)):
    existing = await db.assignments.find_one({"id": assignment_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Assignment not found")
    
    # التحقق من الصلاحية - التحقق من وجود المستخدم في قائمة الموظفين المسندين
    assigned_to_list = existing.get('assigned_to', [])
    if current_user.id not in assigned_to_list and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    update_data = {
        'response': update_input.response,
        'status': update_input.status,
        'updated_at': datetime.now(timezone.utc).isoformat()
    }
    
    await db.assignments.update_one({"id": assignment_id}, {"$set": update_data})
    
    if update_input.reassign_to:
        new_assignment = AssignmentCreate(
            case_id=existing.get('case_id'),
            consultation_id=existing.get('consultation_id'),
            assigned_to=update_input.reassign_to,
            assigned_to_name=update_input.reassign_to_name,
            instructions=f"محال من {current_user.full_name}: {update_input.response}"
        )
        await create_assignment(new_assignment, current_user)
    
    updated = await db.assignments.find_one({"id": assignment_id}, {"_id": 0})
    if isinstance(updated.get('created_at'), str):
        updated['created_at'] = datetime.fromisoformat(updated['created_at'])
    if isinstance(updated.get('updated_at'), str):
        updated['updated_at'] = datetime.fromisoformat(updated['updated_at'])
    
    return Assignment(**updated)

@api_router.post("/case-updates", response_model=ClientCaseUpdate)
async def create_case_update(update_input: ClientCaseUpdateCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="Only staff can create updates")
    
    update_dict = update_input.model_dump()
    update_dict['updated_by'] = current_user.id
    update_dict['updated_by_name'] = current_user.full_name
    update_obj = ClientCaseUpdate(**update_dict)
    
    doc = update_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.case_updates.insert_one(doc)
    return update_obj

@api_router.get("/cases/{case_id}/updates", response_model=List[ClientCaseUpdate])
async def get_case_updates(case_id: str, current_user: User = Depends(get_current_user)):
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    if current_user.role == UserRole.CLIENT:
        updates = await db.case_updates.find(
            {"case_id": case_id, "visible_to_client": True},
            {"_id": 0}
        ).to_list(1000)
    else:
        updates = await db.case_updates.find({"case_id": case_id}, {"_id": 0}).to_list(1000)
    
    for upd in updates:
        if isinstance(upd.get('created_at'), str):
            upd['created_at'] = datetime.fromisoformat(upd['created_at'])
    
    return updates

@api_router.post("/messages", response_model=Message)
async def create_message(message_input: MessageCreate, current_user: User = Depends(get_current_user)):
    msg_dict = message_input.model_dump()
    msg_dict['from_user_id'] = current_user.id
    msg_dict['from_user_name'] = current_user.full_name
    msg_obj = Message(**msg_dict)
    
    doc = msg_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.messages.insert_one(doc)
    
    await log_action("message_sent", "message", msg_obj.id, current_user.id, current_user.full_name, 
                    f"إرسال رسالة إلى {message_input.to_user_name}")
    
    return msg_obj

@api_router.get("/messages", response_model=List[Message])
async def get_messages(current_user: User = Depends(get_current_user)):
    messages = await db.messages.find(
        {"$or": [{"from_user_id": current_user.id}, {"to_user_id": current_user.id}]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(1000)
    
    for msg in messages:
        if isinstance(msg.get('created_at'), str):
            msg['created_at'] = datetime.fromisoformat(msg['created_at'])
    
    return messages

@api_router.get("/messages/conversation/{other_user_id}", response_model=List[Message])
async def get_conversation(other_user_id: str, current_user: User = Depends(get_current_user)):
    messages = await db.messages.find(
        {"$or": [
            {"from_user_id": current_user.id, "to_user_id": other_user_id},
            {"from_user_id": other_user_id, "to_user_id": current_user.id}
        ]},
        {"_id": 0}
    ).sort("created_at", 1).to_list(1000)
    
    for msg in messages:
        if isinstance(msg.get('created_at'), str):
            msg['created_at'] = datetime.fromisoformat(msg['created_at'])
    
    await db.messages.update_many(
        {"from_user_id": other_user_id, "to_user_id": current_user.id, "read": False},
        {"$set": {"read": True}}
    )
    
    return messages

@api_router.get("/audit-logs", response_model=List[AuditLog])
async def get_audit_logs(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only admins can view audit logs")
    
    logs = await db.audit_logs.find({}, {"_id": 0}).sort("created_at", -1).limit(500).to_list(500)
    
    for log in logs:
        if isinstance(log.get('created_at'), str):
            log['created_at'] = datetime.fromisoformat(log['created_at'])
    
    return logs

@api_router.get("/audit-logs/entity/{entity_type}/{entity_id}", response_model=List[AuditLog])
async def get_entity_audit_logs(entity_type: str, entity_id: str, current_user: User = Depends(get_current_user)):
    logs = await db.audit_logs.find(
        {"entity_type": entity_type, "entity_id": entity_id},
        {"_id": 0}
    ).sort("created_at", -1).to_list(1000)
    
    for log in logs:
        if isinstance(log.get('created_at'), str):
            log['created_at'] = datetime.fromisoformat(log['created_at'])
    
    return logs

@api_router.post("/fees", response_model=Fee)
async def create_fee(fee_input: FeeCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.ADMIN, UserRole.ACCOUNTANT]:
        raise HTTPException(status_code=403, detail="Only admins and accountants can create fees")
    
    fee_dict = fee_input.model_dump()
    fee_dict['created_by'] = current_user.id
    fee_dict['created_by_name'] = current_user.full_name
    fee_obj = Fee(**fee_dict)
    
    doc = fee_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.fees.insert_one(doc)
    
    await log_action("create", "fee", fee_obj.id, current_user.id, current_user.full_name,
                    f"إضافة أتعاب بمبلغ {fee_obj.total_amount} للعميل {fee_obj.client_name}")
    
    return fee_obj

@api_router.get("/fees", response_model=List[Fee])
async def get_fees(current_user: User = Depends(get_current_user)):
    if current_user.role in [UserRole.ADMIN, UserRole.ACCOUNTANT]:
        fees = await db.fees.find({}, {"_id": 0}).to_list(1000)
    else:
        raise HTTPException(status_code=403, detail="Only admins and accountants can view fees")
    
    for fee in fees:
        if isinstance(fee.get('created_at'), str):
            fee['created_at'] = datetime.fromisoformat(fee['created_at'])
    
    return fees

@api_router.get("/fees/case/{case_id}", response_model=List[Fee])
async def get_case_fees(case_id: str, current_user: User = Depends(get_current_user)):
    fees = await db.fees.find({"case_id": case_id}, {"_id": 0}).to_list(1000)
    
    for fee in fees:
        if isinstance(fee.get('created_at'), str):
            fee['created_at'] = datetime.fromisoformat(fee['created_at'])
    
    return fees

@api_router.post("/vouchers", response_model=Voucher)
async def create_voucher(voucher_input: VoucherCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.ADMIN, UserRole.ACCOUNTANT]:
        raise HTTPException(status_code=403, detail="Only admins and accountants can create vouchers")
    
    voucher_dict = voucher_input.model_dump()
    voucher_dict['created_by'] = current_user.id
    voucher_dict['created_by_name'] = current_user.full_name
    voucher_obj = Voucher(**voucher_dict)
    
    doc = voucher_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.vouchers.insert_one(doc)
    
    await log_action("create", "voucher", voucher_obj.id, current_user.id, current_user.full_name,
                    f"إصدار سند {voucher_obj.voucher_type} رقم {voucher_obj.voucher_number}")
    
    return voucher_obj

@api_router.get("/vouchers", response_model=List[Voucher])
async def get_vouchers(current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.ADMIN, UserRole.ACCOUNTANT]:
        raise HTTPException(status_code=403, detail="Only admins and accountants can view vouchers")
    
    vouchers = await db.vouchers.find({}, {"_id": 0}).to_list(1000)
    
    for voucher in vouchers:
        if isinstance(voucher.get('created_at'), str):
            voucher['created_at'] = datetime.fromisoformat(voucher['created_at'])
    
    return vouchers

# ==================== PDF Generation ====================

class ArabicPDF(FPDF):
    """كلاس PDF مخصص لدعم اللغة العربية"""
    
    def __init__(self):
        super().__init__()
        # تحميل الخطوط العربية
        fonts_dir = ROOT_DIR / "fonts"
        self.add_font("NotoArabic", "", str(fonts_dir / "NotoSansArabic-Regular.ttf"))
        self.add_font("NotoArabic", "B", str(fonts_dir / "NotoSansArabic-Bold.ttf"))
        
    def arabic_text(self, text):
        """تحويل النص العربي للعرض الصحيح"""
        reshaped_text = arabic_reshaper.reshape(text)
        bidi_text = get_display(reshaped_text)
        return bidi_text
    
    def header(self):
        pass
        
    def footer(self):
        self.set_y(-15)
        self.set_font("NotoArabic", "", 8)
        self.cell(0, 10, self.arabic_text("مجموعة المحامي هشام يوسف الخياط للمحاماة والاستشارات القانونية"), align="C")

def create_invoice_pdf(invoice: dict) -> BytesIO:
    """إنشاء ملف PDF للفاتورة"""
    pdf = ArabicPDF()
    pdf.add_page()
    
    # الشعار والترويسة
    logo_path = ROOT_DIR / "fonts" / "logo.jpg"
    if logo_path.exists():
        pdf.image(str(logo_path), x=80, y=10, w=50)
    
    pdf.set_y(70)
    
    # اسم الشركة
    pdf.set_font("NotoArabic", "B", 16)
    pdf.cell(0, 10, pdf.arabic_text("مجموعة المحامي هشام يوسف الخياط"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("NotoArabic", "", 12)
    pdf.cell(0, 8, pdf.arabic_text("للمحاماة والاستشارات القانونية"), align="C", new_x="LMARGIN", new_y="NEXT")
    
    # العنوان
    pdf.set_font("NotoArabic", "", 10)
    pdf.cell(0, 8, pdf.arabic_text("جدة - حي الحمراء - شارع الشانزلزيه"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, pdf.arabic_text("جوال: 0597771616"), align="C", new_x="LMARGIN", new_y="NEXT")
    
    # خط فاصل
    pdf.ln(5)
    pdf.set_draw_color(197, 160, 89)  # اللون الذهبي
    pdf.set_line_width(1)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(10)
    
    # عنوان الفاتورة
    pdf.set_font("NotoArabic", "B", 20)
    pdf.set_text_color(15, 23, 42)  # اللون الأزرق الداكن
    pdf.cell(0, 12, pdf.arabic_text("فاتورة"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # معلومات الفاتورة
    pdf.set_font("NotoArabic", "", 12)
    pdf.set_text_color(0, 0, 0)
    
    # رقم الفاتورة والتاريخ
    pdf.set_fill_color(249, 249, 247)
    pdf.cell(95, 10, pdf.arabic_text(f"تاريخ الإصدار: {datetime.now().strftime('%Y-%m-%d')}"), fill=True, align="R")
    pdf.cell(95, 10, pdf.arabic_text(f"رقم الفاتورة: {invoice.get('invoice_number', '')}"), fill=True, align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # تاريخ الاستحقاق
    due_date = invoice.get('due_date', '')
    if isinstance(due_date, datetime):
        due_date = due_date.strftime('%Y-%m-%d')
    elif isinstance(due_date, str) and 'T' in due_date:
        due_date = due_date.split('T')[0]
    
    pdf.cell(190, 10, pdf.arabic_text(f"تاريخ الاستحقاق: {due_date}"), fill=True, align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    # معلومات العميل
    pdf.set_font("NotoArabic", "B", 14)
    pdf.cell(0, 10, pdf.arabic_text("معلومات العميل"), align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("NotoArabic", "", 12)
    pdf.cell(190, 10, pdf.arabic_text(f"اسم العميل: {invoice.get('client_name', '')}"), fill=True, align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    # الوصف
    pdf.set_font("NotoArabic", "B", 14)
    pdf.cell(0, 10, pdf.arabic_text("تفاصيل الفاتورة"), align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("NotoArabic", "", 12)
    pdf.multi_cell(190, 10, pdf.arabic_text(invoice.get('description', '')), align="R")
    pdf.ln(10)
    
    # المبلغ
    pdf.set_fill_color(197, 160, 89)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("NotoArabic", "B", 18)
    amount = invoice.get('amount', 0)
    pdf.cell(190, 15, pdf.arabic_text(f"المبلغ الإجمالي: {amount:,.2f} ريال"), fill=True, align="C", new_x="LMARGIN", new_y="NEXT")
    
    # الحالة
    pdf.ln(10)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("NotoArabic", "", 12)
    status = invoice.get('status', 'pending')
    status_text = "مدفوعة" if status == 'paid' else "معلقة" if status == 'pending' else status
    pdf.cell(190, 10, pdf.arabic_text(f"الحالة: {status_text}"), align="R", new_x="LMARGIN", new_y="NEXT")
    
    # إخراج PDF
    output = BytesIO()
    pdf.output(output)
    output.seek(0)
    return output

def create_voucher_pdf(voucher: dict) -> BytesIO:
    """إنشاء ملف PDF للسند"""
    pdf = ArabicPDF()
    pdf.add_page()
    
    # الشعار والترويسة
    logo_path = ROOT_DIR / "fonts" / "logo.jpg"
    if logo_path.exists():
        pdf.image(str(logo_path), x=80, y=10, w=50)
    
    pdf.set_y(70)
    
    # اسم الشركة
    pdf.set_font("NotoArabic", "B", 16)
    pdf.cell(0, 10, pdf.arabic_text("مجموعة المحامي هشام يوسف الخياط"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("NotoArabic", "", 12)
    pdf.cell(0, 8, pdf.arabic_text("للمحاماة والاستشارات القانونية"), align="C", new_x="LMARGIN", new_y="NEXT")
    
    # العنوان
    pdf.set_font("NotoArabic", "", 10)
    pdf.cell(0, 8, pdf.arabic_text("جدة - حي الحمراء - شارع الشانزلزيه"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, pdf.arabic_text("جوال: 0597771616"), align="C", new_x="LMARGIN", new_y="NEXT")
    
    # خط فاصل
    pdf.ln(5)
    pdf.set_draw_color(197, 160, 89)
    pdf.set_line_width(1)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(10)
    
    # نوع السند
    voucher_type = voucher.get('voucher_type', 'قبض')
    pdf.set_font("NotoArabic", "B", 22)
    if voucher_type == 'قبض':
        pdf.set_text_color(34, 139, 34)  # أخضر
    else:
        pdf.set_text_color(220, 53, 69)  # أحمر
    pdf.cell(0, 12, pdf.arabic_text(f"سند {voucher_type}"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    pdf.set_text_color(0, 0, 0)
    
    # معلومات السند
    pdf.set_font("NotoArabic", "", 12)
    pdf.set_fill_color(249, 249, 247)
    
    # رقم السند والتاريخ
    created_at = voucher.get('created_at', '')
    if isinstance(created_at, datetime):
        created_at = created_at.strftime('%Y-%m-%d')
    elif isinstance(created_at, str) and 'T' in created_at:
        created_at = created_at.split('T')[0]
    
    pdf.cell(95, 10, pdf.arabic_text(f"التاريخ: {created_at}"), fill=True, align="R")
    pdf.cell(95, 10, pdf.arabic_text(f"رقم السند: {voucher.get('voucher_number', '')}"), fill=True, align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # العميل (إن وجد)
    if voucher.get('client_name'):
        pdf.cell(190, 10, pdf.arabic_text(f"العميل: {voucher.get('client_name', '')}"), fill=True, align="R", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
    
    # طريقة الدفع
    pdf.cell(190, 10, pdf.arabic_text(f"طريقة الدفع: {voucher.get('payment_method', '')}"), fill=True, align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    # البيان
    pdf.set_font("NotoArabic", "B", 14)
    pdf.cell(0, 10, pdf.arabic_text("البيان"), align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("NotoArabic", "", 12)
    pdf.multi_cell(190, 10, pdf.arabic_text(voucher.get('description', '')), align="R")
    pdf.ln(10)
    
    # المبلغ
    pdf.set_fill_color(197, 160, 89)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("NotoArabic", "B", 20)
    amount = voucher.get('amount', 0)
    pdf.cell(190, 18, pdf.arabic_text(f"المبلغ: {amount:,.2f} ريال"), fill=True, align="C", new_x="LMARGIN", new_y="NEXT")
    
    # خانات التوقيع
    pdf.ln(30)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("NotoArabic", "", 12)
    
    # خط للتوقيعات
    pdf.set_draw_color(0, 0, 0)
    pdf.set_line_width(0.5)
    
    # المستلم
    pdf.cell(60, 10, "", border="B")
    pdf.cell(35, 10, "")
    # المحاسب
    pdf.cell(60, 10, "", border="B")
    pdf.cell(35, 10, "")
    pdf.ln(8)
    
    pdf.cell(60, 10, pdf.arabic_text("المستلم"), align="C")
    pdf.cell(35, 10, "")
    pdf.cell(60, 10, pdf.arabic_text("المحاسب"), align="C")
    
    # اسم من أصدر السند
    pdf.ln(10)
    pdf.cell(60, 10, "")
    pdf.cell(35, 10, "")
    pdf.cell(60, 10, pdf.arabic_text(voucher.get('created_by_name', '')), align="C")
    
    # إخراج PDF
    output = BytesIO()
    pdf.output(output)
    output.seek(0)
    return output

@api_router.get("/invoices/{invoice_id}/pdf")
async def download_invoice_pdf(invoice_id: str, current_user: User = Depends(get_current_user)):
    """تحميل فاتورة كملف PDF"""
    invoice = await db.invoices.find_one({"id": invoice_id}, {"_id": 0})
    
    if not invoice:
        raise HTTPException(status_code=404, detail="الفاتورة غير موجودة")
    
    # التحقق من الصلاحيات
    if current_user.role == UserRole.CLIENT and invoice.get('client_id') != current_user.id:
        raise HTTPException(status_code=403, detail="غير مصرح لك بتحميل هذه الفاتورة")
    
    # تحويل التاريخ إذا كان نص
    if isinstance(invoice.get('due_date'), str):
        invoice['due_date'] = datetime.fromisoformat(invoice['due_date'].replace('Z', '+00:00'))
    if isinstance(invoice.get('created_at'), str):
        invoice['created_at'] = datetime.fromisoformat(invoice['created_at'].replace('Z', '+00:00'))
    
    pdf_content = create_invoice_pdf(invoice)
    
    return StreamingResponse(
        pdf_content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=invoice_{invoice.get('invoice_number', invoice_id)}.pdf"
        }
    )

@api_router.get("/vouchers/{voucher_id}/pdf")
async def download_voucher_pdf(voucher_id: str, current_user: User = Depends(get_current_user)):
    """تحميل سند كملف PDF"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ACCOUNTANT, UserRole.LAWYER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك بتحميل السندات")
    
    voucher = await db.vouchers.find_one({"id": voucher_id}, {"_id": 0})
    
    if not voucher:
        raise HTTPException(status_code=404, detail="السند غير موجود")
    
    # تحويل التاريخ إذا كان نص
    if isinstance(voucher.get('created_at'), str):
        voucher['created_at'] = datetime.fromisoformat(voucher['created_at'].replace('Z', '+00:00'))
    
    pdf_content = create_voucher_pdf(voucher)
    
    return StreamingResponse(
        pdf_content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=voucher_{voucher.get('voucher_number', voucher_id)}.pdf"
        }
    )

@api_router.get("/financial-reports/{report_type}")
async def get_financial_report(report_type: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.ADMIN, UserRole.ACCOUNTANT]:
        raise HTTPException(status_code=403, detail="Only admins and accountants can view financial reports")
    
    now = datetime.now(timezone.utc)
    
    if report_type == "daily":
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif report_type == "weekly":
        start_date = now - timedelta(days=7)
    elif report_type == "monthly":
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        raise HTTPException(status_code=400, detail="Invalid report type")
    
    start_date_str = start_date.isoformat()
    
    fees = await db.fees.find(
        {"created_at": {"$gte": start_date_str}},
        {"_id": 0}
    ).to_list(1000)
    
    vouchers = await db.vouchers.find(
        {"created_at": {"$gte": start_date_str}},
        {"_id": 0}
    ).to_list(1000)
    
    total_fees = sum(f['total_amount'] for f in fees)
    total_receipts = sum(v['amount'] for v in vouchers if v['voucher_type'] == 'قبض')
    total_payments = sum(v['amount'] for v in vouchers if v['voucher_type'] == 'صرف')
    
    return {
        "report_type": report_type,
        "start_date": start_date_str,
        "end_date": now.isoformat(),
        "total_fees": total_fees,
        "total_receipts": total_receipts,
        "total_payments": total_payments,
        "net_income": total_receipts - total_payments,
        "fees_count": len(fees),
        "receipts_count": len([v for v in vouchers if v['voucher_type'] == 'قبض']),
        "payments_count": len([v for v in vouchers if v['voucher_type'] == 'صرف']),
        "fees": fees,
        "vouchers": vouchers
    }

@api_router.post("/meetings", response_model=Meeting)
async def create_meeting(meeting_input: MeetingCreate, current_user: User = Depends(get_current_user)):
    # السماح للمدير والموظفين بإنشاء الاجتماعات
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="العملاء لا يمكنهم إنشاء اجتماعات")
    
    meeting_dict = meeting_input.model_dump()
    meeting_dict['created_by'] = current_user.id
    meeting_dict['created_by_name'] = current_user.full_name
    
    # إضافة المنشئ كمشارك تلقائياً إذا لم يكن موجوداً
    if current_user.id not in meeting_dict.get('participants', []):
        meeting_dict['participants'] = meeting_dict.get('participants', []) + [current_user.id]
        meeting_dict['participant_names'] = meeting_dict.get('participant_names', []) + [current_user.full_name]
    
    meeting_obj = Meeting(**meeting_dict)
    
    doc = meeting_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['scheduled_time'] = doc['scheduled_time'].isoformat()
    
    await db.meetings.insert_one(doc)
    
    await log_action("create", "meeting", meeting_obj.id, current_user.id, current_user.full_name,
                    f"إنشاء اجتماع: {meeting_obj.title}")
    
    return meeting_obj

@api_router.get("/meetings", response_model=List[Meeting])
async def get_meetings(current_user: User = Depends(get_current_user)):
    # المدير والموظفين يرون جميع الاجتماعات، العملاء يرون فقط اجتماعاتهم
    if current_user.role in [UserRole.ADMIN, UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF]:
        meetings = await db.meetings.find({}, {"_id": 0}).to_list(1000)
    else:
        meetings = await db.meetings.find(
            {"participants": current_user.id},
            {"_id": 0}
        ).to_list(1000)
    
    for meeting in meetings:
        if isinstance(meeting.get('created_at'), str):
            meeting['created_at'] = datetime.fromisoformat(meeting['created_at'])
        if isinstance(meeting.get('scheduled_time'), str):
            meeting['scheduled_time'] = datetime.fromisoformat(meeting['scheduled_time'])
    
    return meetings

@api_router.get("/meetings/all", response_model=List[Meeting])
async def get_all_meetings(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only admins can view all meetings")
    
    meetings = await db.meetings.find({}, {"_id": 0}).to_list(1000)
    
    for meeting in meetings:
        if isinstance(meeting.get('created_at'), str):
            meeting['created_at'] = datetime.fromisoformat(meeting['created_at'])
        if isinstance(meeting.get('scheduled_time'), str):
            meeting['scheduled_time'] = datetime.fromisoformat(meeting['scheduled_time'])
    
    return meetings

# ========== نظام الأرقام التسلسلية ==========
async def get_next_sequence(collection_name: str, prefix: str = "") -> str:
    """توليد رقم تسلسلي فريد لكل مجموعة"""
    result = await db.sequences.find_one_and_update(
        {"_id": collection_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    seq_num = result.get("seq", 1)
    year = datetime.now(timezone.utc).year
    return f"{prefix}{year}-{seq_num:05d}"

@api_router.get("/sequences/{collection_name}")
async def get_current_sequence(collection_name: str, current_user: User = Depends(get_current_user)):
    """الحصول على الرقم التسلسلي الحالي"""
    result = await db.sequences.find_one({"_id": collection_name}, {"_id": 0})
    if result:
        return {"collection": collection_name, "current_seq": result.get("seq", 0)}
    return {"collection": collection_name, "current_seq": 0}

# ========== نظام أوقات الدوام ==========
@api_router.get("/work-schedule/current")
async def get_current_work_schedule(current_user: User = Depends(get_current_user)):
    """الحصول على جدول الدوام الحالي"""
    schedule = await db.work_schedules.find_one({"is_active": True}, {"_id": 0})
    if not schedule:
        # إنشاء جدول دوام افتراضي
        default_schedule = {
            "id": str(uuid.uuid4()),
            "schedule_type": "normal",
            "work_days": ["saturday", "sunday", "monday", "tuesday", "wednesday", "thursday"],
            "morning_start": "08:00",
            "morning_end": "17:00",
            "evening_start": None,
            "evening_end": None,
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.work_schedules.insert_one(default_schedule)
        return default_schedule
    return schedule

@api_router.get("/work-schedule/all")
async def get_all_work_schedules(current_user: User = Depends(get_current_user)):
    """الحصول على جميع جداول الدوام"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه عرض جميع جداول الدوام")
    
    schedules = await db.work_schedules.find({}, {"_id": 0}).to_list(100)
    return schedules

@api_router.post("/work-schedule")
async def create_work_schedule(schedule_input: WorkScheduleCreate, current_user: User = Depends(get_current_user)):
    """إنشاء جدول دوام جديد"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه إنشاء جدول دوام")
    
    # إلغاء تفعيل الجدول السابق
    await db.work_schedules.update_many({}, {"$set": {"is_active": False}})
    
    schedule = WorkSchedule(**schedule_input.model_dump())
    doc = schedule.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.work_schedules.insert_one(doc)
    
    await log_action("create", "work_schedule", schedule.id, current_user.id, current_user.full_name,
                    f"إنشاء جدول دوام جديد: {schedule.schedule_type}")
    
    return {"message": "تم إنشاء جدول الدوام بنجاح", "schedule": doc}

@api_router.put("/work-schedule/activate/{schedule_type}")
async def activate_work_schedule(schedule_type: str, current_user: User = Depends(get_current_user)):
    """تفعيل نوع دوام معين (normal أو ramadan)"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه تغيير جدول الدوام")
    
    # إلغاء تفعيل جميع الجداول
    await db.work_schedules.update_many({}, {"$set": {"is_active": False}})
    
    # البحث عن الجدول المطلوب وتفعيله
    schedule = await db.work_schedules.find_one({"schedule_type": schedule_type})
    
    if not schedule:
        # إنشاء جدول جديد حسب النوع
        if schedule_type == "ramadan":
            new_schedule = {
                "id": str(uuid.uuid4()),
                "schedule_type": "ramadan",
                "work_days": ["saturday", "sunday", "monday", "tuesday", "wednesday", "thursday"],
                "morning_start": "10:00",
                "morning_end": "16:00",
                "evening_start": "22:00",
                "evening_end": "02:00",
                "is_active": True,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        else:
            new_schedule = {
                "id": str(uuid.uuid4()),
                "schedule_type": "normal",
                "work_days": ["saturday", "sunday", "monday", "tuesday", "wednesday", "thursday"],
                "morning_start": "08:00",
                "morning_end": "17:00",
                "evening_start": None,
                "evening_end": None,
                "is_active": True,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        await db.work_schedules.insert_one(new_schedule)
        schedule = new_schedule
    else:
        await db.work_schedules.update_one(
            {"schedule_type": schedule_type},
            {"$set": {"is_active": True}}
        )
    
    await log_action("update", "work_schedule", schedule.get('id', ''), current_user.id, current_user.full_name,
                    f"تفعيل جدول دوام: {schedule_type}")
    
    return {"message": f"تم تفعيل جدول الدوام: {schedule_type}", "schedule_type": schedule_type}

# ========== نظام الحضور والانصراف ==========
@api_router.post("/attendance/clock-in", response_model=Attendance)
async def clock_in(clock_in_data: AttendanceClockIn, current_user: User = Depends(get_current_user)):
    """تسجيل الحضور"""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    # التحقق من عدم وجود تسجيل حضور لنفس اليوم
    existing = await db.attendance.find_one(
        {"user_id": current_user.id, "date": today},
        {"_id": 0}
    )
    if existing and existing.get("clock_in"):
        raise HTTPException(status_code=400, detail="لقد قمت بتسجيل الحضور بالفعل اليوم")
    
    now = datetime.now(timezone.utc)
    location = None
    if clock_in_data.latitude and clock_in_data.longitude:
        location = {
            "lat": clock_in_data.latitude,
            "lng": clock_in_data.longitude,
            "address": clock_in_data.address or ""
        }
    
    attendance = Attendance(
        user_id=current_user.id,
        user_name=current_user.full_name,
        date=today,
        clock_in=now,
        clock_in_location=location,
        status="present"
    )
    
    doc = attendance.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['clock_in'] = doc['clock_in'].isoformat()
    
    await db.attendance.insert_one(doc)
    
    await log_action("clock_in", "attendance", attendance.id, current_user.id, current_user.full_name,
                    f"تسجيل حضور - {today}")
    
    return attendance

@api_router.post("/attendance/clock-out")
async def clock_out(clock_out_data: AttendanceClockOut, current_user: User = Depends(get_current_user)):
    """تسجيل الانصراف"""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    existing = await db.attendance.find_one(
        {"user_id": current_user.id, "date": today},
        {"_id": 0}
    )
    if not existing:
        raise HTTPException(status_code=400, detail="لم يتم تسجيل الحضور اليوم")
    if existing.get("clock_out"):
        raise HTTPException(status_code=400, detail="لقد قمت بتسجيل الانصراف بالفعل")
    
    now = datetime.now(timezone.utc)
    clock_in_time = datetime.fromisoformat(existing['clock_in'])
    total_hours = (now - clock_in_time).total_seconds() / 3600
    
    location = None
    if clock_out_data.latitude and clock_out_data.longitude:
        location = {
            "lat": clock_out_data.latitude,
            "lng": clock_out_data.longitude,
            "address": clock_out_data.address or ""
        }
    
    update_data = {
        "clock_out": now.isoformat(),
        "clock_out_location": location,
        "total_hours": round(total_hours, 2),
        "notes": clock_out_data.notes
    }
    
    await db.attendance.update_one(
        {"user_id": current_user.id, "date": today},
        {"$set": update_data}
    )
    
    await log_action("clock_out", "attendance", existing['id'], current_user.id, current_user.full_name,
                    f"تسجيل انصراف - {today} - {round(total_hours, 2)} ساعات")
    
    return {"message": "تم تسجيل الانصراف بنجاح", "total_hours": round(total_hours, 2)}

@api_router.get("/attendance/today")
async def get_today_attendance(current_user: User = Depends(get_current_user)):
    """الحصول على سجل حضور اليوم للموظف الحالي"""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    attendance = await db.attendance.find_one(
        {"user_id": current_user.id, "date": today},
        {"_id": 0}
    )
    return attendance

@api_router.get("/attendance/my-records")
async def get_my_attendance_records(current_user: User = Depends(get_current_user)):
    """الحصول على سجلات حضور الموظف الحالي"""
    records = await db.attendance.find(
        {"user_id": current_user.id},
        {"_id": 0}
    ).sort("date", -1).limit(30).to_list(30)
    return records

@api_router.get("/attendance/all")
async def get_all_attendance(
    date: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """الحصول على جميع سجلات الحضور (للمدير فقط)"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه عرض جميع سجلات الحضور")
    
    query = {}
    if date:
        query["date"] = date
    
    records = await db.attendance.find(query, {"_id": 0}).sort("date", -1).to_list(1000)
    return records

@api_router.get("/attendance/report")
async def get_attendance_report(
    start_date: str,
    end_date: str,
    user_id: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """تقرير الحضور والانصراف"""
    if current_user.role != UserRole.ADMIN and user_id != current_user.id:
        user_id = current_user.id
    
    query = {"date": {"$gte": start_date, "$lte": end_date}}
    if user_id:
        query["user_id"] = user_id
    
    records = await db.attendance.find(query, {"_id": 0}).to_list(1000)
    
    total_days = len(records)
    total_hours = sum(r.get('total_hours', 0) for r in records if r.get('total_hours'))
    present_days = len([r for r in records if r.get('status') == 'present'])
    
    # تجميع حسب الموظف
    by_employee = {}
    for r in records:
        emp_id = r.get('user_id')
        if emp_id not in by_employee:
            by_employee[emp_id] = {
                "user_name": r.get('user_name'),
                "days": 0,
                "total_hours": 0
            }
        by_employee[emp_id]["days"] += 1
        by_employee[emp_id]["total_hours"] += r.get('total_hours', 0) or 0
    
    return {
        "start_date": start_date,
        "end_date": end_date,
        "total_records": total_days,
        "total_hours": round(total_hours, 2),
        "present_days": present_days,
        "by_employee": list(by_employee.values()),
        "records": records
    }

@api_router.get("/attendance/alerts")
async def get_attendance_alerts(current_user: User = Depends(get_current_user)):
    """الحصول على تنبيهات الحضور والانصراف"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه عرض التنبيهات")
    
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    now = datetime.now(timezone.utc)
    current_hour = now.hour
    current_minute = now.minute
    current_time_minutes = current_hour * 60 + current_minute
    
    # إعدادات الدوام الافتراضية (يمكن تخصيصها لاحقاً)
    work_start = 8 * 60  # 8:00 صباحاً
    work_end = 17 * 60   # 5:00 مساءً
    
    alerts = []
    
    # جلب جميع الموظفين
    employees = await db.users.find(
        {"role": {"$in": [UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF]}},
        {"_id": 0, "id": 1, "full_name": 1}
    ).to_list(100)
    
    # جلب سجلات الحضور اليوم
    today_records = await db.attendance.find(
        {"date": today},
        {"_id": 0}
    ).to_list(100)
    
    clocked_in_ids = {r['user_id'] for r in today_records if r.get('clock_in')}
    not_clocked_out_ids = {r['user_id'] for r in today_records if r.get('clock_in') and not r.get('clock_out')}
    
    # تنبيهات التأخر (بعد 15 دقيقة من بداية الدوام)
    if current_time_minutes > work_start + 15:
        for emp in employees:
            if emp['id'] not in clocked_in_ids:
                alerts.append({
                    "type": "late_arrival",
                    "severity": "warning",
                    "user_id": emp['id'],
                    "user_name": emp['full_name'],
                    "message": f"الموظف {emp['full_name']} لم يسجل حضوره حتى الآن",
                    "time": now.isoformat()
                })
    
    # تنبيهات تجاوز وقت العمل (أكثر من ساعة بعد نهاية الدوام)
    if current_time_minutes > work_end + 60:
        for emp_id in not_clocked_out_ids:
            emp = next((e for e in employees if e['id'] == emp_id), None)
            if emp:
                record = next((r for r in today_records if r['user_id'] == emp_id), None)
                if record:
                    clock_in_time = datetime.fromisoformat(record['clock_in'])
                    hours_worked = (now - clock_in_time).total_seconds() / 3600
                    if hours_worked > 10:  # أكثر من 10 ساعات
                        alerts.append({
                            "type": "overtime",
                            "severity": "warning",
                            "user_id": emp_id,
                            "user_name": emp['full_name'],
                            "message": f"الموظف {emp['full_name']} تجاوز {round(hours_worked, 1)} ساعة عمل",
                            "time": now.isoformat()
                        })
    
    # تنبيهات نسيان تسجيل الانصراف (نهاية الدوام + 30 دقيقة)
    if current_time_minutes > work_end + 30:
        for emp_id in not_clocked_out_ids:
            emp = next((e for e in employees if e['id'] == emp_id), None)
            if emp:
                alerts.append({
                    "type": "missing_clock_out",
                    "severity": "info",
                    "user_id": emp_id,
                    "user_name": emp['full_name'],
                    "message": f"الموظف {emp['full_name']} لم يسجل انصرافه بعد",
                    "time": now.isoformat()
                })
    
    return {
        "alerts": alerts,
        "total_alerts": len(alerts),
        "checked_at": now.isoformat()
    }

# ========== تحديث إنشاء المهام مع الأرقام التسلسلية ==========
@api_router.post("/assignments/with-number", response_model=Assignment)
async def create_assignment_with_number(assignment_input: AssignmentCreate, current_user: User = Depends(get_current_user)):
    """إنشاء مهمة جديدة مع رقم تسلسلي"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="Only staff can create assignments")
    
    # توليد رقم تسلسلي
    assignment_number = await get_next_sequence("assignments", "ASN-")
    
    assignment_dict = assignment_input.model_dump()
    assignment_dict['assigned_by'] = current_user.id
    assignment_dict['assigned_by_name'] = current_user.full_name
    assignment_dict['assignment_number'] = assignment_number
    assignment_obj = Assignment(**assignment_dict)
    
    doc = assignment_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    
    await db.assignments.insert_one(doc)
    
    assigned_names = ", ".join(assignment_input.assigned_to_names) if assignment_input.assigned_to_names else "غير محدد"
    await log_action("create", "assignment", assignment_obj.id, current_user.id, current_user.full_name,
                    f"إحالة مهمة رقم {assignment_number} إلى {assigned_names}")
    
    return assignment_obj

# ========== تقارير العمل التفصيلية ==========
@api_router.get("/reports/work-summary")
async def get_work_summary_report(
    start_date: str,
    end_date: str,
    current_user: User = Depends(get_current_user)
):
    """تقرير ملخص العمل"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه عرض التقارير")
    
    # إحصائيات المهام
    assignments = await db.assignments.find(
        {"created_at": {"$gte": start_date, "$lte": end_date}},
        {"_id": 0}
    ).to_list(1000)
    
    total_assignments = len(assignments)
    completed_assignments = len([a for a in assignments if a.get('status') == 'completed'])
    pending_assignments = len([a for a in assignments if a.get('status') == 'pending'])
    
    # إحصائيات القضايا
    cases = await db.cases.find(
        {"created_at": {"$gte": start_date, "$lte": end_date}},
        {"_id": 0}
    ).to_list(1000)
    
    # إحصائيات الاستشارات
    consultations = await db.consultations.find(
        {"created_at": {"$gte": start_date, "$lte": end_date}},
        {"_id": 0}
    ).to_list(1000)
    
    guest_consultations = await db.guest_consultations.find(
        {"created_at": {"$gte": start_date, "$lte": end_date}},
        {"_id": 0}
    ).to_list(1000)
    
    # إحصائيات الحضور
    attendance = await db.attendance.find(
        {"date": {"$gte": start_date, "$lte": end_date}},
        {"_id": 0}
    ).to_list(1000)
    
    total_work_hours = sum(a.get('total_hours', 0) for a in attendance if a.get('total_hours'))
    
    return {
        "period": {"start": start_date, "end": end_date},
        "assignments": {
            "total": total_assignments,
            "completed": completed_assignments,
            "pending": pending_assignments,
            "completion_rate": round((completed_assignments / total_assignments * 100) if total_assignments > 0 else 0, 2)
        },
        "cases": {
            "total": len(cases),
            "active": len([c for c in cases if c.get('status') == 'active'])
        },
        "consultations": {
            "registered": len(consultations),
            "guests": len(guest_consultations),
            "total": len(consultations) + len(guest_consultations)
        },
        "attendance": {
            "total_records": len(attendance),
            "total_work_hours": round(total_work_hours, 2)
        }
    }

@api_router.get("/reports/employee-performance")
async def get_employee_performance_report(
    start_date: str,
    end_date: str,
    employee_id: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """تقرير أداء الموظفين"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه عرض التقارير")
    
    # جلب الموظفين
    employee_query = {"role": {"$in": [UserRole.LAWYER, UserRole.ACCOUNTANT, UserRole.STAFF]}}
    if employee_id:
        employee_query["id"] = employee_id
    
    employees = await db.users.find(employee_query, {"_id": 0, "hashed_password": 0}).to_list(100)
    
    performance_data = []
    for emp in employees:
        emp_id = emp.get('id')
        
        # المهام المسندة للموظف
        emp_assignments = await db.assignments.find(
            {"assigned_to": emp_id, "created_at": {"$gte": start_date, "$lte": end_date}},
            {"_id": 0}
        ).to_list(1000)
        
        total_tasks = len(emp_assignments)
        completed_tasks = len([a for a in emp_assignments if a.get('status') == 'completed'])
        
        # سجلات الحضور
        emp_attendance = await db.attendance.find(
            {"user_id": emp_id, "date": {"$gte": start_date, "$lte": end_date}},
            {"_id": 0}
        ).to_list(1000)
        
        total_hours = sum(a.get('total_hours', 0) for a in emp_attendance if a.get('total_hours'))
        
        performance_data.append({
            "employee_id": emp_id,
            "employee_name": emp.get('full_name'),
            "role": emp.get('role'),
            "tasks": {
                "total": total_tasks,
                "completed": completed_tasks,
                "completion_rate": round((completed_tasks / total_tasks * 100) if total_tasks > 0 else 0, 2)
            },
            "attendance": {
                "days_present": len(emp_attendance),
                "total_hours": round(total_hours, 2)
            }
        })
    
    return {
        "period": {"start": start_date, "end": end_date},
        "employees": performance_data
    }

# ========== المكتبة القانونية ==========
@api_router.get("/legal-library/documents")
async def get_legal_documents(
    category: Optional[str] = None,
    subcategory: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """الحصول على المستندات القانونية"""
    query = {}
    if category:
        query["category"] = category
    if subcategory:
        query["subcategory"] = subcategory
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"content": {"$regex": search, "$options": "i"}},
            {"keywords": {"$in": [search]}}
        ]
    
    documents = await db.legal_documents.find(query, {"_id": 0, "content": 0}).sort("created_at", -1).to_list(100)
    return documents

@api_router.get("/legal-library/documents/{doc_id}")
async def get_legal_document(doc_id: str, current_user: User = Depends(get_current_user)):
    """الحصول على مستند قانوني محدد"""
    document = await db.legal_documents.find_one({"id": doc_id}, {"_id": 0})
    if not document:
        raise HTTPException(status_code=404, detail="المستند غير موجود")
    return document

@api_router.post("/legal-library/documents", response_model=LegalDocument)
async def create_legal_document(doc_input: LegalDocumentCreate, current_user: User = Depends(get_current_user)):
    """إضافة مستند قانوني جديد"""
    if current_user.role == "client":
        raise HTTPException(status_code=403, detail="العملاء لا يمكنهم إضافة مستندات")
    
    doc_dict = doc_input.model_dump()
    doc_dict['uploaded_by'] = current_user.id
    doc_dict['uploaded_by_name'] = current_user.full_name
    
    document = LegalDocument(**doc_dict)
    doc_to_save = document.model_dump()
    doc_to_save['created_at'] = doc_to_save['created_at'].isoformat()
    
    await db.legal_documents.insert_one(doc_to_save)
    
    await log_action("create", "legal_document", document.id, current_user.id, current_user.full_name,
                    f"إضافة مستند قانوني: {document.title}")
    
    return document

@api_router.delete("/legal-library/documents/{doc_id}")
async def delete_legal_document(doc_id: str, current_user: User = Depends(get_current_user)):
    """حذف مستند قانوني"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف المستندات")
    
    result = await db.legal_documents.delete_one({"id": doc_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="المستند غير موجود")
    
    return {"message": "تم حذف المستند بنجاح"}

@api_router.get("/legal-library/categories")
async def get_legal_categories(current_user: User = Depends(get_current_user)):
    """الحصول على فئات المكتبة القانونية"""
    categories = [
        {"id": "system", "name": "الأنظمة السعودية", "icon": "📜"},
        {"id": "regulation", "name": "اللوائح التنفيذية", "icon": "📋"},
        {"id": "precedent", "name": "السوابق القضائية", "icon": "⚖️"},
        {"id": "supreme_court", "name": "قرارات المحكمة العليا", "icon": "🏛️"},
        {"id": "law_book", "name": "كتب القانون", "icon": "📖"},
        {"id": "fiqh_book", "name": "كتب الفقه", "icon": "📕"},
        {"id": "decision", "name": "القرارات والتعاميم", "icon": "📄"},
    ]
    
    subcategories = [
        {"id": "criminal", "name": "جنائي"},
        {"id": "commercial", "name": "تجاري"},
        {"id": "family", "name": "أحوال شخصية"},
        {"id": "labor", "name": "عمالي"},
        {"id": "administrative", "name": "إداري"},
        {"id": "civil", "name": "مدني"},
        {"id": "real_estate", "name": "عقاري"},
    ]
    
    # إحصائيات
    stats = {}
    for cat in categories:
        count = await db.legal_documents.count_documents({"category": cat["id"]})
        stats[cat["id"]] = count
    
    return {"categories": categories, "subcategories": subcategories, "stats": stats}

# ========== الذكاء الاصطناعي القانوني ==========
@api_router.post("/legal-library/ai/chat")
async def legal_ai_chat(request: LegalChatRequest, current_user: User = Depends(get_current_user)):
    """المحادثة مع المساعد القانوني الذكي"""
    from emergentintegrations.llm.chat import LlmChat, UserMessage
    
    # إنشاء session_id جديد إذا لم يكن موجوداً
    session_id = request.session_id or str(uuid.uuid4())
    
    # البحث في المكتبة القانونية للحصول على سياق
    search_query = request.message
    relevant_docs = await db.legal_documents.find(
        {"$or": [
            {"title": {"$regex": search_query, "$options": "i"}},
            {"content": {"$regex": search_query, "$options": "i"}},
            {"keywords": {"$elemMatch": {"$regex": search_query, "$options": "i"}}}
        ]},
        {"_id": 0, "title": 1, "category": 1, "content": 1, "source": 1, "year": 1, "number": 1}
    ).limit(5).to_list(5)
    
    # بناء السياق من المستندات
    context = ""
    sources = []
    if relevant_docs:
        context = "\n\nالمعلومات المتوفرة في المكتبة القانونية:\n"
        for doc in relevant_docs:
            context += f"\n--- {doc.get('title', '')} ---\n"
            content = doc.get('content', '')[:2000]  # أول 2000 حرف
            context += content + "\n"
            sources.append({
                "title": doc.get('title'),
                "category": doc.get('category'),
                "source": doc.get('source'),
                "year": doc.get('year'),
                "number": doc.get('number')
            })
    
    # بناء رسالة النظام
    system_message = """أنت مساعد قانوني متخصص في الأنظمة السعودية والفقه الإسلامي.
مهمتك:
1. الإجابة على الأسئلة القانونية بدقة استناداً للأنظمة السعودية
2. الاستشهاد بالمواد والأنظمة ذات الصلة
3. توضيح الإجراءات القانونية المطلوبة
4. التنويه بأن الإجابات للاسترشاد وليست بديلاً عن الاستشارة القانونية المتخصصة

الرجاء الإجابة باللغة العربية بشكل واضح ومنظم.
إذا لم تكن متأكداً من المعلومة، اذكر ذلك بوضوح.
""" + context
    
    try:
        # إنشاء محادثة مع Gemini
        api_key = os.environ.get('EMERGENT_LLM_KEY')
        if not api_key:
            raise HTTPException(status_code=500, detail="مفتاح API غير متوفر")
        
        chat = LlmChat(
            api_key=api_key,
            session_id=session_id,
            system_message=system_message
        ).with_model("gemini", "gemini-3-flash-preview")
        
        # إرسال الرسالة
        user_message = UserMessage(text=request.message)
        response = await chat.send_message(user_message)
        
        # حفظ رسالة المستخدم
        user_msg = LegalChatMessage(
            session_id=session_id,
            user_id=current_user.id,
            user_name=current_user.full_name,
            role="user",
            content=request.message
        )
        user_msg_dict = user_msg.model_dump()
        user_msg_dict['created_at'] = user_msg_dict['created_at'].isoformat()
        await db.legal_chat_messages.insert_one(user_msg_dict)
        
        # حفظ رد المساعد
        assistant_msg = LegalChatMessage(
            session_id=session_id,
            user_id="ai",
            user_name="المساعد القانوني",
            role="assistant",
            content=response,
            sources=sources
        )
        assistant_msg_dict = assistant_msg.model_dump()
        assistant_msg_dict['created_at'] = assistant_msg_dict['created_at'].isoformat()
        await db.legal_chat_messages.insert_one(assistant_msg_dict)
        
        return {
            "session_id": session_id,
            "response": response,
            "sources": sources
        }
        
    except Exception as e:
        logger.error(f"Error in legal AI chat: {str(e)}")
        raise HTTPException(status_code=500, detail=f"حدث خطأ في المساعد الذكي: {str(e)}")

@api_router.get("/legal-library/ai/history/{session_id}")
async def get_chat_history(session_id: str, current_user: User = Depends(get_current_user)):
    """الحصول على سجل المحادثة"""
    messages = await db.legal_chat_messages.find(
        {"session_id": session_id},
        {"_id": 0}
    ).sort("created_at", 1).to_list(100)
    return messages

@api_router.get("/legal-library/ai/sessions")
async def get_user_sessions(current_user: User = Depends(get_current_user)):
    """الحصول على جلسات المحادثة للمستخدم"""
    pipeline = [
        {"$match": {"user_id": current_user.id, "role": "user"}},
        {"$group": {
            "_id": "$session_id",
            "first_message": {"$first": "$content"},
            "created_at": {"$first": "$created_at"},
            "message_count": {"$sum": 1}
        }},
        {"$sort": {"created_at": -1}},
        {"$limit": 20}
    ]
    sessions = await db.legal_chat_messages.aggregate(pipeline).to_list(20)
    return sessions

@api_router.delete("/legal-library/ai/sessions/{session_id}")
async def delete_chat_session(session_id: str, current_user: User = Depends(get_current_user)):
    """حذف جلسة محادثة"""
    await db.legal_chat_messages.delete_many({"session_id": session_id})
    return {"message": "تم حذف الجلسة بنجاح"}

# ==================== طلبات العملاء ====================

async def get_next_request_number():
    """توليد رقم طلب تسلسلي"""
    year = datetime.now().year
    counter = await db.sequences.find_one_and_update(
        {"_id": f"client_requests_{year}"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    seq = counter.get("seq", 1)
    return f"REQ-{year}-{seq:05d}"

@api_router.post("/client-requests", response_model=ClientRequest)
async def create_client_request(request_input: ClientRequestCreate, current_user: User = Depends(get_current_user)):
    """إنشاء طلب جديد من العميل (قضية أو خدمة موثق)"""
    request_number = await get_next_request_number()
    
    request_obj = ClientRequest(
        request_number=request_number,
        request_type=request_input.request_type,
        client_id=current_user.id,
        client_name=current_user.full_name,
        case_type=request_input.case_type,
        title=request_input.title,
        description=request_input.description,
        phone_number=request_input.phone_number,
        service_type=request_input.service_type,
        attachments=request_input.attachments,
    )
    
    doc = request_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.client_requests.insert_one(doc)
    
    # تسجيل في سجل الإجراءات
    await log_action(
        action_type="create",
        entity_type="client_request",
        entity_id=request_obj.id,
        user_id=current_user.id,
        user_name=current_user.full_name,
        description=f"طلب جديد: {request_input.request_type} - {request_number}"
    )
    
    return request_obj

@api_router.get("/client-requests", response_model=List[ClientRequest])
async def get_client_requests(current_user: User = Depends(get_current_user)):
    """الحصول على طلبات العملاء"""
    if current_user.role in [UserRole.ADMIN, UserRole.LAWYER]:
        # المدير والمحامي يرون جميع الطلبات
        requests = await db.client_requests.find({}, {"_id": 0}).to_list(1000)
    else:
        # العميل يرى طلباته فقط (بناءً على رقم الهوية أو معرف المستخدم)
        query = {"$or": [{"client_id": current_user.id}]}
        if current_user.national_id:
            query["$or"].append({"client_national_id": current_user.national_id})
        requests = await db.client_requests.find(query, {"_id": 0}).to_list(1000)
    
    for req in requests:
        if isinstance(req.get('created_at'), str):
            req['created_at'] = datetime.fromisoformat(req['created_at'])
    
    return requests

# API للحصول على جميع معاملات عميل بناءً على رقم الهوية
@api_router.get("/client-requests/by-national-id/{national_id}")
async def get_client_requests_by_national_id(national_id: str, current_user: User = Depends(get_current_user)):
    """الحصول على جميع معاملات عميل بناءً على رقم الهوية"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER]:
        # العميل يمكنه فقط رؤية معاملاته الخاصة
        if current_user.national_id != national_id:
            raise HTTPException(status_code=403, detail="غير مصرح لك بعرض هذه المعاملات")
    
    # جلب جميع المعاملات المرتبطة برقم الهوية
    requests = await db.client_requests.find(
        {"client_national_id": national_id}, {"_id": 0}
    ).to_list(1000)
    
    # جلب الاستشارات المرتبطة
    consultations = await db.consultations.find(
        {"client_national_id": national_id}, {"_id": 0}
    ).to_list(1000)
    
    # جلب القضايا المرتبطة
    cases = await db.cases.find(
        {"client_national_id": national_id}, {"_id": 0}
    ).to_list(1000)
    
    return {
        "national_id": national_id,
        "client_requests": requests,
        "consultations": consultations,
        "cases": cases,
        "total_requests": len(requests),
        "total_consultations": len(consultations),
        "total_cases": len(cases)
    }

@api_router.get("/client-requests/{request_id}", response_model=ClientRequest)
async def get_client_request(request_id: str, current_user: User = Depends(get_current_user)):
    """الحصول على تفاصيل طلب معين"""
    request = await db.client_requests.find_one({"id": request_id}, {"_id": 0})
    
    if not request:
        raise HTTPException(status_code=404, detail="الطلب غير موجود")
    
    # التحقق من الصلاحيات
    if current_user.role == UserRole.CLIENT and request.get('client_id') != current_user.id:
        # التحقق من رقم الهوية أيضاً
        if current_user.national_id and request.get('client_national_id') != current_user.national_id:
            raise HTTPException(status_code=403, detail="غير مصرح لك بعرض هذا الطلب")
    
    if isinstance(request.get('created_at'), str):
        request['created_at'] = datetime.fromisoformat(request['created_at'])
    
    return ClientRequest(**request)

@api_router.put("/client-requests/{request_id}")
async def update_client_request(
    request_id: str,
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    assigned_to_name: Optional[str] = None,
    notes: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """تحديث طلب العميل (للمدير والمحامي فقط)"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك بتعديل الطلبات")
    
    update_data = {}
    if status:
        update_data['status'] = status
    if assigned_to:
        update_data['assigned_to'] = assigned_to
    if assigned_to_name:
        update_data['assigned_to_name'] = assigned_to_name
    if notes:
        update_data['notes'] = notes
    
    if not update_data:
        raise HTTPException(status_code=400, detail="لا توجد بيانات للتحديث")
    
    result = await db.client_requests.update_one(
        {"id": request_id},
        {"$set": update_data}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="الطلب غير موجود")
    
    return {"message": "تم تحديث الطلب بنجاح"}

# ========== API حذف طلبات العملاء (للمدير فقط) ==========
@api_router.delete("/client-requests/{request_id}")
async def delete_client_request(request_id: str, current_user: User = Depends(get_current_user)):
    """حذف طلب عميل - للمدير فقط"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف الطلبات")
    
    request = await db.client_requests.find_one({"id": request_id}, {"_id": 0})
    if not request:
        raise HTTPException(status_code=404, detail="الطلب غير موجود")
    
    await db.client_requests.delete_one({"id": request_id})
    
    await log_action("delete", "client_request", request_id, current_user.id, current_user.full_name,
                    f"حذف طلب العميل: {request.get('subject', 'بدون عنوان')}")
    
    return {"message": "تم حذف الطلب بنجاح"}

# ========== نظام إحالة الطلبات مع سجل الإجراءات ==========

class RequestActionCreate(BaseModel):
    """نموذج إضافة إجراء على طلب"""
    action_type: str  # assign, update, transfer, archive, complete
    action_text: str
    new_assigned_to: Optional[List[str]] = None
    new_assigned_to_names: Optional[List[str]] = None
    new_status: Optional[str] = None

class RequestAction(BaseModel):
    """نموذج إجراء على طلب"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    request_type: str  # case, consultation, notary, task
    action_type: str
    action_text: str
    performed_by: str
    performed_by_name: str
    previous_status: Optional[str] = None
    new_status: Optional[str] = None
    previous_assigned_to: Optional[List[str]] = None
    new_assigned_to: Optional[List[str]] = None
    new_assigned_to_names: Optional[List[str]] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

@api_router.post("/requests/{request_type}/{request_id}/actions")
async def add_request_action(
    request_type: str,
    request_id: str,
    action: RequestActionCreate,
    current_user: User = Depends(get_current_user)
):
    """إضافة إجراء على طلب (إحالة، تحديث، نقل، أرشفة)"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER, UserRole.STAFF, UserRole.ACCOUNTANT]:
        raise HTTPException(status_code=403, detail="غير مصرح لك بإجراء هذا")
    
    # تحديد الـ collection بناءً على نوع الطلب
    collection_map = {
        "case": "client_requests",
        "consultation": "consultations",
        "notary": "client_requests",
        "task": "tasks"
    }
    collection_name = collection_map.get(request_type)
    if not collection_name:
        raise HTTPException(status_code=400, detail="نوع طلب غير صالح")
    
    collection = db[collection_name]
    
    # جلب الطلب الحالي
    current_request = await collection.find_one({"id": request_id}, {"_id": 0})
    if not current_request:
        raise HTTPException(status_code=404, detail="الطلب غير موجود")
    
    # إنشاء سجل الإجراء
    action_record = RequestAction(
        request_id=request_id,
        request_type=request_type,
        action_type=action.action_type,
        action_text=action.action_text,
        performed_by=current_user.id,
        performed_by_name=current_user.full_name,
        previous_status=current_request.get('status'),
        new_status=action.new_status,
        previous_assigned_to=current_request.get('assigned_to') if isinstance(current_request.get('assigned_to'), list) else [current_request.get('assigned_to')] if current_request.get('assigned_to') else None,
        new_assigned_to=action.new_assigned_to,
        new_assigned_to_names=action.new_assigned_to_names
    )
    
    # حفظ سجل الإجراء
    action_doc = action_record.model_dump()
    action_doc['created_at'] = action_doc['created_at'].isoformat()
    await db.request_actions.insert_one(action_doc)
    
    # تحديث الطلب
    update_data = {}
    if action.new_status:
        update_data['status'] = action.new_status
    if action.new_assigned_to:
        update_data['assigned_to'] = action.new_assigned_to
        update_data['assigned_to_names'] = action.new_assigned_to_names
        update_data['assigned_at'] = datetime.now(timezone.utc).isoformat()
        update_data['assigned_by'] = current_user.id
        update_data['assigned_by_name'] = current_user.full_name
    
    if update_data:
        await collection.update_one({"id": request_id}, {"$set": update_data})
    
    # إرسال إشعار للموظفين الجدد
    if action.new_assigned_to:
        for emp_id in action.new_assigned_to:
            notification = {
                "id": str(uuid.uuid4()),
                "user_id": emp_id,
                "message": f"تم إحالة طلب جديد إليك: {action.action_text}",
                "link": "/my-tasks",
                "is_read": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            await db.notifications.insert_one(notification)
    
    return {"message": "تم إضافة الإجراء بنجاح", "action_id": action_record.id}

@api_router.get("/requests/{request_type}/{request_id}/actions")
async def get_request_actions(
    request_type: str,
    request_id: str,
    current_user: User = Depends(get_current_user)
):
    """جلب سجل الإجراءات على طلب"""
    actions = await db.request_actions.find(
        {"request_id": request_id, "request_type": request_type},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    return actions

@api_router.get("/my-assigned-requests")
async def get_my_assigned_requests(current_user: User = Depends(get_current_user)):
    """جلب الطلبات المحالة للموظف الحالي"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="غير متاح للعملاء")
    
    # جلب الطلبات المحالة للموظف
    client_requests = await db.client_requests.find(
        {"$or": [
            {"assigned_to": current_user.id},
            {"assigned_to": {"$in": [current_user.id]}}
        ]},
        {"_id": 0}
    ).to_list(100)
    
    # جلب الاستشارات المحالة
    consultations = await db.consultations.find(
        {"$or": [
            {"assigned_to": current_user.id},
            {"assigned_to": {"$in": [current_user.id]}}
        ]},
        {"_id": 0}
    ).to_list(100)
    
    # دمج النتائج مع إضافة نوع الطلب
    results = []
    for req in client_requests:
        req['request_type'] = req.get('request_type', 'case')
        results.append(req)
    
    for cons in consultations:
        cons['request_type'] = 'consultation'
        results.append(cons)
    
    return results

@api_router.get("/client/my-requests-actions")
async def get_client_requests_with_actions(current_user: User = Depends(get_current_user)):
    """جلب طلبات العميل مع سجل الإجراءات"""
    if current_user.role != UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="هذا API للعملاء فقط")
    
    # جلب طلبات العميل
    client_requests = await db.client_requests.find(
        {"client_id": current_user.id},
        {"_id": 0}
    ).to_list(100)
    
    consultations = await db.consultations.find(
        {"client_id": current_user.id},
        {"_id": 0}
    ).to_list(100)
    
    # جلب الإجراءات لكل طلب
    results = []
    
    for req in client_requests:
        actions = await db.request_actions.find(
            {"request_id": req['id']},
            {"_id": 0}
        ).sort("created_at", -1).to_list(50)
        req['actions'] = actions
        results.append(req)
    
    for cons in consultations:
        actions = await db.request_actions.find(
            {"request_id": cons['id']},
            {"_id": 0}
        ).sort("created_at", -1).to_list(50)
        cons['actions'] = actions
        cons['request_type'] = 'consultation'
        results.append(cons)
    
    return results

# ==================== نظام إدارة المهام المتقدم ====================

async def get_next_task_number():
    """توليد رقم مهمة تسلسلي"""
    year = datetime.now().year
    counter = await db.sequences.find_one_and_update(
        {"_id": f"tasks_{year}"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    seq = counter.get("seq", 1)
    return f"TASK-{year}-{seq:05d}"

@api_router.post("/tasks", response_model=Task)
async def create_task(task_input: TaskCreate, current_user: User = Depends(get_current_user)):
    """إنشاء مهمة جديدة"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER, UserRole.STAFF]:
        raise HTTPException(status_code=403, detail="غير مصرح لك بإنشاء المهام")
    
    task_number = await get_next_task_number()
    
    task_obj = Task(
        task_number=task_number,
        category=task_input.category,
        source_type=task_input.source_type or "employee_created",
        source_id=task_input.source_id,
        request_number=task_input.request_number,
        client_id=task_input.client_id,
        client_name=task_input.client_name,
        client_phone=task_input.client_phone,
        title=task_input.title,
        description=task_input.description,
        instructions=task_input.instructions,
        priority=task_input.priority,
        assigned_to=task_input.assigned_to,
        assigned_to_names=task_input.assigned_to_names,
        hidden_fields=task_input.hidden_fields,
        attachments=task_input.attachments,
        due_date=task_input.due_date,
        created_by=current_user.id,
        created_by_name=current_user.full_name,
        assigned_by=current_user.id if task_input.assigned_to else None,
        assigned_by_name=current_user.full_name if task_input.assigned_to else None,
        assigned_at=datetime.now(timezone.utc) if task_input.assigned_to else None,
        status=TaskStatus.PENDING if not task_input.assigned_to else TaskStatus.IN_PROGRESS
    )
    
    doc = task_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    if doc.get('assigned_at'):
        doc['assigned_at'] = doc['assigned_at'].isoformat()
    if doc.get('due_date'):
        doc['due_date'] = doc['due_date'].isoformat()
    
    await db.tasks.insert_one(doc)
    
    await log_action(
        "create", "task", task_obj.id,
        current_user.id, current_user.full_name,
        f"إنشاء مهمة جديدة: {task_number} - {task_input.title}"
    )
    
    return task_obj

@api_router.post("/tasks/from-request/{request_id}", response_model=Task)
async def create_task_from_request(
    request_id: str,
    task_input: TaskAssign,
    current_user: User = Depends(get_current_user)
):
    """إنشاء مهمة من طلب عميل وتعيينها للموظفين"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه تحويل الطلبات لمهام")
    
    # جلب طلب العميل
    client_request = await db.client_requests.find_one({"id": request_id}, {"_id": 0})
    if not client_request:
        raise HTTPException(status_code=404, detail="الطلب غير موجود")
    
    task_number = await get_next_task_number()
    
    # تحديد الفئة بناءً على نوع الطلب
    category_map = {
        "case": TaskCategory.CASES,
        "consultation": TaskCategory.REVIEWS,
        "notary": TaskCategory.EXECUTION
    }
    category = category_map.get(client_request.get('request_type'), TaskCategory.CASES)
    
    task_obj = Task(
        task_number=task_number,
        category=category,
        source_type="client_request",
        source_id=request_id,
        request_number=client_request.get('request_number'),
        client_id=client_request.get('client_id'),
        client_name=client_request.get('client_name'),
        client_phone=client_request.get('phone_number'),
        title=client_request.get('title') or client_request.get('service_type') or f"طلب {client_request.get('request_type')}",
        description=client_request.get('description'),
        instructions=task_input.instructions,
        priority=task_input.priority,
        assigned_to=task_input.assigned_to,
        assigned_to_names=task_input.assigned_to_names,
        hidden_fields=task_input.hidden_fields,
        attachments=client_request.get('attachments', []),
        due_date=task_input.due_date,
        created_by=current_user.id,
        created_by_name=current_user.full_name,
        assigned_by=current_user.id,
        assigned_by_name=current_user.full_name,
        assigned_at=datetime.now(timezone.utc),
        status=TaskStatus.IN_PROGRESS
    )
    
    doc = task_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    doc['assigned_at'] = doc['assigned_at'].isoformat()
    if doc.get('due_date'):
        doc['due_date'] = doc['due_date'].isoformat()
    
    await db.tasks.insert_one(doc)
    
    # تحديث حالة الطلب الأصلي
    await db.client_requests.update_one(
        {"id": request_id},
        {"$set": {
            "status": "in_progress",
            "assigned_to": ", ".join(task_input.assigned_to_names)
        }}
    )
    
    # إرسال إشعارات للموظفين المعينين
    await notify_task_assignment(task_obj.model_dump(), task_input.assigned_to, current_user.full_name)
    
    await log_action(
        "assign", "task", task_obj.id,
        current_user.id, current_user.full_name,
        f"تحويل الطلب {client_request.get('request_number')} إلى مهمة {task_number}"
    )
    
    return task_obj

@api_router.get("/tasks")
async def get_tasks(
    category: Optional[str] = None,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """جلب المهام"""
    query = {}
    
    if current_user.role == UserRole.ADMIN:
        # المدير يرى جميع المهام
        pass
    elif current_user.role in [UserRole.LAWYER, UserRole.STAFF, UserRole.ACCOUNTANT]:
        # الموظفون يرون المهام المعينة لهم فقط
        query["assigned_to"] = {"$in": [current_user.id]}
    else:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    if category:
        query["category"] = category
    if status:
        query["status"] = status
    else:
        # لا نظهر المهام المؤرشفة افتراضياً
        query["status"] = {"$ne": TaskStatus.ARCHIVED}
    
    tasks = await db.tasks.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    # إخفاء الحقول للموظفين غير المدراء
    if current_user.role != UserRole.ADMIN:
        for task in tasks:
            hidden = task.get('hidden_fields', [])
            for field in hidden:
                if field in task:
                    task[field] = "[مخفي]"
    
    # تحويل التواريخ
    for task in tasks:
        for date_field in ['created_at', 'updated_at', 'assigned_at', 'due_date', 'completed_at', 'archived_at', 'last_action_at']:
            if task.get(date_field) and isinstance(task[date_field], str):
                task[date_field] = datetime.fromisoformat(task[date_field])
    
    return tasks

@api_router.get("/tasks/my-tasks")
async def get_my_tasks(current_user: User = Depends(get_current_user)):
    """جلب المهام المعينة للموظف الحالي"""
    if current_user.role not in [UserRole.LAWYER, UserRole.STAFF, UserRole.ACCOUNTANT, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    query = {
        "assigned_to": {"$in": [current_user.id]},
        "status": {"$nin": [TaskStatus.ARCHIVED, TaskStatus.CANCELLED]}
    }
    
    tasks = await db.tasks.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    # إخفاء الحقول
    for task in tasks:
        hidden = task.get('hidden_fields', [])
        for field in hidden:
            if field in task:
                task[field] = "[مخفي]"
    
    # تحويل التواريخ
    for task in tasks:
        for date_field in ['created_at', 'updated_at', 'assigned_at', 'due_date', 'completed_at', 'archived_at', 'last_action_at']:
            if task.get(date_field) and isinstance(task[date_field], str):
                task[date_field] = datetime.fromisoformat(task[date_field])
    
    return tasks

@api_router.get("/tasks/{task_id}")
async def get_task(task_id: str, current_user: User = Depends(get_current_user)):
    """جلب تفاصيل مهمة"""
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="المهمة غير موجودة")
    
    # التحقق من الصلاحيات
    if current_user.role != UserRole.ADMIN and current_user.id not in task.get('assigned_to', []):
        raise HTTPException(status_code=403, detail="غير مصرح لك بعرض هذه المهمة")
    
    # إخفاء الحقول للموظفين
    if current_user.role != UserRole.ADMIN:
        hidden = task.get('hidden_fields', [])
        for field in hidden:
            if field in task:
                task[field] = "[مخفي]"
    
    return task

@api_router.put("/tasks/{task_id}/assign")
async def assign_task(
    task_id: str,
    assignment: TaskAssign,
    current_user: User = Depends(get_current_user)
):
    """تعيين أو إعادة تعيين مهمة"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه تعيين المهام")
    
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="المهمة غير موجودة")
    
    update_data = {
        "assigned_to": assignment.assigned_to,
        "assigned_to_names": assignment.assigned_to_names,
        "assigned_by": current_user.id,
        "assigned_by_name": current_user.full_name,
        "assigned_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "status": TaskStatus.IN_PROGRESS
    }
    
    if assignment.instructions:
        update_data["instructions"] = assignment.instructions
    if assignment.hidden_fields:
        update_data["hidden_fields"] = assignment.hidden_fields
    if assignment.priority:
        update_data["priority"] = assignment.priority
    if assignment.due_date:
        update_data["due_date"] = assignment.due_date.isoformat()
    
    await db.tasks.update_one({"id": task_id}, {"$set": update_data})
    
    await log_action(
        "assign", "task", task_id,
        current_user.id, current_user.full_name,
        f"تعيين المهمة {task.get('task_number')} إلى {', '.join(assignment.assigned_to_names)}"
    )
    
    return {"message": "تم تعيين المهمة بنجاح"}

@api_router.put("/tasks/{task_id}/status")
async def update_task_status(
    task_id: str,
    status: str,
    current_user: User = Depends(get_current_user)
):
    """تحديث حالة المهمة"""
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="المهمة غير موجودة")
    
    # التحقق من الصلاحيات
    if current_user.role != UserRole.ADMIN and current_user.id not in task.get('assigned_to', []):
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    update_data = {
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "last_action": f"تغيير الحالة إلى {status}",
        "last_action_by": current_user.id,
        "last_action_by_name": current_user.full_name,
        "last_action_at": datetime.now(timezone.utc).isoformat()
    }
    
    if status == TaskStatus.COMPLETED:
        update_data["completed_at"] = datetime.now(timezone.utc).isoformat()
    elif status == TaskStatus.ARCHIVED:
        update_data["archived_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.tasks.update_one({"id": task_id}, {"$set": update_data})
    
    # إذا كانت المهمة مرتبطة بطلب عميل، نحدث حالته أيضاً
    if task.get('source_type') == 'client_request' and task.get('source_id'):
        request_status_map = {
            TaskStatus.COMPLETED: "completed",
            TaskStatus.IN_PROGRESS: "in_progress",
            TaskStatus.ARCHIVED: "completed"
        }
        if status in request_status_map:
            await db.client_requests.update_one(
                {"id": task.get('source_id')},
                {"$set": {"status": request_status_map[status]}}
            )
    
    await log_action(
        "update", "task", task_id,
        current_user.id, current_user.full_name,
        f"تحديث حالة المهمة {task.get('task_number')} إلى {status}"
    )
    
    return {"message": "تم تحديث الحالة بنجاح"}

@api_router.post("/tasks/{task_id}/updates")
async def add_task_update(
    task_id: str,
    update_input: TaskUpdateCreate,
    current_user: User = Depends(get_current_user)
):
    """إضافة تحديث على مهمة"""
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="المهمة غير موجودة")
    
    # التحقق من الصلاحيات
    if current_user.role != UserRole.ADMIN and current_user.id not in task.get('assigned_to', []):
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    update_obj = TaskUpdate(
        task_id=task_id,
        update_text=update_input.update_text,
        update_type=update_input.update_type,
        updated_by=current_user.id,
        updated_by_name=current_user.full_name,
        visible_to_client=update_input.visible_to_client,
        attachments=update_input.attachments
    )
    
    doc = update_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.task_updates.insert_one(doc)
    
    # تحديث آخر إجراء على المهمة
    now = datetime.now(timezone.utc)
    await db.tasks.update_one(
        {"id": task_id},
        {"$set": {
            "last_action": update_input.update_text[:100],
            "last_action_by": current_user.id,
            "last_action_by_name": current_user.full_name,
            "last_action_at": now.isoformat(),
            "updated_at": now.isoformat()
        }}
    )
    
    await log_action(
        "update", "task", task_id,
        current_user.id, current_user.full_name,
        f"إضافة تحديث على المهمة {task.get('task_number')}: {update_input.update_text[:50]}"
    )
    
    return {"message": "تم إضافة التحديث بنجاح", "update_id": update_obj.id}

@api_router.get("/tasks/{task_id}/updates")
async def get_task_updates(task_id: str, current_user: User = Depends(get_current_user)):
    """جلب تحديثات مهمة"""
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="المهمة غير موجودة")
    
    # التحقق من الصلاحيات
    is_client = current_user.role == UserRole.CLIENT
    is_assigned = current_user.id in task.get('assigned_to', [])
    is_admin = current_user.role == UserRole.ADMIN
    is_task_client = task.get('client_id') == current_user.id
    
    if not (is_admin or is_assigned or is_task_client):
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    query = {"task_id": task_id}
    
    # العملاء يرون فقط التحديثات المرئية لهم
    if is_client:
        query["visible_to_client"] = True
    
    updates = await db.task_updates.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    return updates

@api_router.delete("/tasks/{task_id}")
async def delete_task(task_id: str, current_user: User = Depends(get_current_user)):
    """حذف مهمة"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه حذف المهام")
    
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="المهمة غير موجودة")
    
    await db.tasks.delete_one({"id": task_id})
    await db.task_updates.delete_many({"task_id": task_id})
    
    await log_action(
        "delete", "task", task_id,
        current_user.id, current_user.full_name,
        f"حذف المهمة {task.get('task_number')}"
    )
    
    return {"message": "تم حذف المهمة بنجاح"}

@api_router.put("/tasks/{task_id}/archive")
async def archive_task(task_id: str, current_user: User = Depends(get_current_user)):
    """أرشفة مهمة مكتملة"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه أرشفة المهام")
    
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="المهمة غير موجودة")
    
    now = datetime.now(timezone.utc)
    await db.tasks.update_one(
        {"id": task_id},
        {"$set": {
            "status": TaskStatus.ARCHIVED,
            "archived_at": now.isoformat(),
            "updated_at": now.isoformat()
        }}
    )
    
    return {"message": "تم أرشفة المهمة بنجاح"}

@api_router.get("/tasks/archived")
async def get_archived_tasks(current_user: User = Depends(get_current_user)):
    """جلب المهام المؤرشفة"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="فقط المدير يمكنه عرض الأرشيف")
    
    tasks = await db.tasks.find(
        {"status": TaskStatus.ARCHIVED},
        {"_id": 0}
    ).sort("archived_at", -1).to_list(500)
    
    return tasks

# ========== تقارير المهام والأداء ==========

@api_router.get("/tasks/reports/summary")
async def get_tasks_summary(current_user: User = Depends(get_current_user)):
    """ملخص المهام"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    # إحصائيات عامة
    total = await db.tasks.count_documents({})
    pending = await db.tasks.count_documents({"status": TaskStatus.PENDING})
    in_progress = await db.tasks.count_documents({"status": TaskStatus.IN_PROGRESS})
    completed = await db.tasks.count_documents({"status": TaskStatus.COMPLETED})
    archived = await db.tasks.count_documents({"status": TaskStatus.ARCHIVED})
    
    # إحصائيات حسب الفئة
    categories = {}
    for cat in [TaskCategory.CASES, TaskCategory.EXECUTION, TaskCategory.REVIEWS, TaskCategory.INTERNAL]:
        count = await db.tasks.count_documents({"category": cat, "status": {"$ne": TaskStatus.ARCHIVED}})
        categories[cat] = count
    
    # إحصائيات حسب الأولوية
    priorities = {}
    for priority in ["low", "normal", "high", "urgent"]:
        count = await db.tasks.count_documents({"priority": priority, "status": {"$ne": TaskStatus.ARCHIVED}})
        priorities[priority] = count
    
    return {
        "total": total,
        "pending": pending,
        "in_progress": in_progress,
        "completed": completed,
        "archived": archived,
        "by_category": categories,
        "by_priority": priorities
    }

@api_router.get("/tasks/reports/employees")
async def get_employee_performance(current_user: User = Depends(get_current_user)):
    """تقرير أداء الموظفين"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    # جلب جميع الموظفين
    employees = await db.users.find(
        {"role": {"$in": [UserRole.LAWYER, UserRole.STAFF, UserRole.ACCOUNTANT]}},
        {"_id": 0, "id": 1, "full_name": 1}
    ).to_list(100)
    
    reports = []
    for emp in employees:
        emp_id = emp['id']
        emp_name = emp['full_name']
        
        # إحصائيات المهام
        total = await db.tasks.count_documents({"assigned_to": {"$in": [emp_id]}})
        completed = await db.tasks.count_documents({
            "assigned_to": {"$in": [emp_id]},
            "status": TaskStatus.COMPLETED
        })
        in_progress = await db.tasks.count_documents({
            "assigned_to": {"$in": [emp_id]},
            "status": TaskStatus.IN_PROGRESS
        })
        pending = await db.tasks.count_documents({
            "assigned_to": {"$in": [emp_id]},
            "status": TaskStatus.PENDING
        })
        
        completion_rate = (completed / total * 100) if total > 0 else 0
        
        # حساب متوسط وقت الإنجاز
        completed_tasks = await db.tasks.find({
            "assigned_to": {"$in": [emp_id]},
            "status": TaskStatus.COMPLETED,
            "completed_at": {"$exists": True},
            "assigned_at": {"$exists": True}
        }, {"_id": 0, "completed_at": 1, "assigned_at": 1}).to_list(100)
        
        avg_days = 0
        if completed_tasks:
            total_days = 0
            for t in completed_tasks:
                try:
                    completed_at = datetime.fromisoformat(t['completed_at']) if isinstance(t['completed_at'], str) else t['completed_at']
                    assigned_at = datetime.fromisoformat(t['assigned_at']) if isinstance(t['assigned_at'], str) else t['assigned_at']
                    days = (completed_at - assigned_at).days
                    total_days += max(0, days)
                except Exception:
                    pass
            avg_days = total_days / len(completed_tasks) if completed_tasks else 0
        
        reports.append({
            "employee_id": emp_id,
            "employee_name": emp_name,
            "total_tasks": total,
            "completed_tasks": completed,
            "in_progress_tasks": in_progress,
            "pending_tasks": pending,
            "completion_rate": round(completion_rate, 1),
            "average_completion_days": round(avg_days, 1)
        })
    
    # ترتيب حسب نسبة الإنجاز
    reports.sort(key=lambda x: x['completion_rate'], reverse=True)
    
    return reports

@api_router.get("/tasks/reports/workflow")
async def get_workflow_report(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """تقرير سير العمل"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    query = {}
    if start_date:
        query["created_at"] = {"$gte": start_date}
    if end_date:
        if "created_at" in query:
            query["created_at"]["$lte"] = end_date
        else:
            query["created_at"] = {"$lte": end_date}
    
    # جلب جميع المهام
    tasks = await db.tasks.find(query, {"_id": 0}).to_list(1000)
    
    # تحليل البيانات
    by_category = {}
    by_status = {}
    by_month = {}
    
    for task in tasks:
        # حسب الفئة
        cat = task.get('category', 'unknown')
        by_category[cat] = by_category.get(cat, 0) + 1
        
        # حسب الحالة
        status = task.get('status', 'unknown')
        by_status[status] = by_status.get(status, 0) + 1
        
        # حسب الشهر
        created_at = task.get('created_at')
        if created_at:
            try:
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at)
                month_key = created_at.strftime("%Y-%m")
                by_month[month_key] = by_month.get(month_key, 0) + 1
            except Exception:
                pass
    
    return {
        "total_tasks": len(tasks),
        "by_category": by_category,
        "by_status": by_status,
        "by_month": dict(sorted(by_month.items()))
    }

# ========== جداول العمل المشتركة ==========

@api_router.get("/work-schedules/tables")
async def get_work_schedule_tables(current_user: User = Depends(get_current_user)):
    """جلب جداول العمل المشتركة"""
    if current_user.role not in [UserRole.ADMIN, UserRole.LAWYER, UserRole.STAFF, UserRole.ACCOUNTANT]:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    # جلب المهام مصنفة حسب الفئة
    categories = [
        {"id": TaskCategory.CASES, "name": "القضايا", "icon": "briefcase"},
        {"id": TaskCategory.EXECUTION, "name": "التنفيذ", "icon": "play-circle"},
        {"id": TaskCategory.REVIEWS, "name": "المراجعات", "icon": "search"},
        {"id": TaskCategory.INTERNAL, "name": "المهام الداخلية", "icon": "clipboard"}
    ]
    
    tables = []
    for cat in categories:
        tasks = await db.tasks.find(
            {"category": cat["id"], "status": {"$ne": TaskStatus.ARCHIVED}},
            {"_id": 0}
        ).sort("created_at", -1).to_list(100)
        
        # إخفاء الحقول للموظفين غير المدراء
        if current_user.role != UserRole.ADMIN:
            for task in tasks:
                hidden = task.get('hidden_fields', [])
                for field in hidden:
                    if field in task:
                        task[field] = "[مخفي]"
        
        tables.append({
            "category": cat,
            "tasks": tasks,
            "count": len(tasks)
        })
    
    return tables

# ========== تحديثات مرئية للعميل ==========

@api_router.get("/client/my-request-updates/{request_id}")
async def get_client_request_updates(request_id: str, current_user: User = Depends(get_current_user)):
    """جلب تحديثات الطلب للعميل"""
    # البحث عن المهمة المرتبطة بالطلب
    task = await db.tasks.find_one(
        {"source_id": request_id, "source_type": "client_request"},
        {"_id": 0}
    )
    
    if not task:
        return {"updates": [], "message": "لم يتم البدء في معالجة الطلب بعد"}
    
    # التحقق من أن العميل هو صاحب الطلب
    if task.get('client_id') != current_user.id:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    # جلب التحديثات المرئية للعميل
    updates = await db.task_updates.find(
        {"task_id": task['id'], "visible_to_client": True},
        {"_id": 0}
    ).sort("created_at", -1).to_list(50)
    
    return {
        "task_number": task.get('task_number'),
        "status": task.get('status'),
        "assigned_to": task.get('assigned_to_names', []),
        "last_action": task.get('last_action'),
        "last_action_at": task.get('last_action_at'),
        "updates": updates
    }

# ==================== نظام الإشعارات ====================

async def create_notification(
    user_id: str,
    notification_type: str,
    title: str,
    message: str,
    link: str = None,
    related_id: str = None,
    related_type: str = None
):
    """إنشاء إشعار جديد"""
    notification = Notification(
        user_id=user_id,
        notification_type=notification_type,
        title=title,
        message=message,
        link=link,
        related_id=related_id,
        related_type=related_type
    )
    doc = notification.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.notifications.insert_one(doc)
    return notification

async def notify_task_assignment(task: dict, assigned_user_ids: List[str], assigned_by_name: str):
    """إرسال إشعارات عند تعيين مهمة"""
    for user_id in assigned_user_ids:
        await create_notification(
            user_id=user_id,
            notification_type=NotificationType.TASK_ASSIGNED,
            title="مهمة جديدة",
            message=f"تم تعيينك في المهمة: {task.get('title')} بواسطة {assigned_by_name}",
            link="/my-tasks",
            related_id=task.get('id'),
            related_type="task"
        )

@api_router.get("/notifications")
async def get_notifications(
    unread_only: bool = False,
    limit: int = 50,
    current_user: User = Depends(get_current_user)
):
    """جلب إشعارات المستخدم"""
    query = {"user_id": current_user.id}
    if unread_only:
        query["is_read"] = False
    
    notifications = await db.notifications.find(
        query, {"_id": 0}
    ).sort("created_at", -1).limit(limit).to_list(limit)
    
    return notifications

@api_router.get("/notifications/unread-count")
async def get_unread_notifications_count(current_user: User = Depends(get_current_user)):
    """عدد الإشعارات غير المقروءة"""
    count = await db.notifications.count_documents({
        "user_id": current_user.id,
        "is_read": False
    })
    return {"count": count}

@api_router.put("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, current_user: User = Depends(get_current_user)):
    """تحديد إشعار كمقروء"""
    result = await db.notifications.update_one(
        {"id": notification_id, "user_id": current_user.id},
        {"$set": {"is_read": True}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="الإشعار غير موجود")
    return {"message": "تم تحديد الإشعار كمقروء"}

@api_router.put("/notifications/mark-all-read")
async def mark_all_notifications_read(current_user: User = Depends(get_current_user)):
    """تحديد جميع الإشعارات كمقروءة"""
    await db.notifications.update_many(
        {"user_id": current_user.id, "is_read": False},
        {"$set": {"is_read": True}}
    )
    return {"message": "تم تحديد جميع الإشعارات كمقروءة"}

@api_router.delete("/notifications/{notification_id}")
async def delete_notification(notification_id: str, current_user: User = Depends(get_current_user)):
    """حذف إشعار"""
    result = await db.notifications.delete_one({
        "id": notification_id,
        "user_id": current_user.id
    })
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="الإشعار غير موجود")
    return {"message": "تم حذف الإشعار"}

# ==================== نظام البريد الداخلي ====================

@api_router.post("/emails/compose")
async def compose_email(email_input: EmailCompose, current_user: User = Depends(get_current_user)):
    """إنشاء وإرسال بريد جديد"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    # إنشاء thread_id جديد إذا لم يكن رداً
    thread_id = None
    if email_input.reply_to_id:
        # جلب البريد الأصلي للحصول على thread_id
        original = await db.emails.find_one({"id": email_input.reply_to_id}, {"_id": 0})
        if original:
            thread_id = original.get('thread_id') or original.get('id')
    
    if not thread_id:
        thread_id = str(uuid.uuid4())
    
    # إنشاء البريد
    email = InternalEmail(
        sender_id=current_user.id,
        sender_name=current_user.full_name,
        sender_email=current_user.email,
        recipients=email_input.recipients,
        subject=email_input.subject,
        body=email_input.body,
        body_html=email_input.body_html,
        attachments=email_input.attachments,
        priority=email_input.priority,
        related_task_id=email_input.related_task_id,
        is_external=email_input.is_external,
        external_email=email_input.external_email,
        thread_id=thread_id,
        reply_to_id=email_input.reply_to_id,
        is_reply=email_input.is_reply,
        is_forwarded=email_input.is_forwarded,
        status=EmailStatus.DRAFT if email_input.save_as_draft else EmailStatus.SENT,
        sent_at=None if email_input.save_as_draft else datetime.now(timezone.utc)
    )
    
    # حفظ البريد
    doc = email.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    if doc.get('sent_at'):
        doc['sent_at'] = doc['sent_at'].isoformat()
    await db.emails.insert_one(doc)
    
    # إنشاء سجل للمرسل (في المسودات أو المرسل)
    sender_recipient = EmailRecipient(
        email_id=email.id,
        user_id=current_user.id,
        user_email=current_user.email,
        recipient_type="sender",
        is_read=True,
        folder="drafts" if email_input.save_as_draft else "sent"
    )
    sender_doc = sender_recipient.model_dump()
    await db.email_recipients.insert_one(sender_doc)
    
    # إذا لم يكن مسودة، إنشاء سجلات للمستلمين وإشعارات
    if not email_input.save_as_draft:
        for recipient in email_input.recipients:
            # إنشاء سجل المستلم
            recipient_record = EmailRecipient(
                email_id=email.id,
                user_id=recipient.get('id'),
                user_email=recipient.get('email'),
                recipient_type=recipient.get('type', 'to'),
                folder="inbox"
            )
            recipient_doc = recipient_record.model_dump()
            await db.email_recipients.insert_one(recipient_doc)
            
            # إرسال إشعار
            if recipient.get('id'):
                await create_notification(
                    user_id=recipient.get('id'),
                    notification_type=NotificationType.EMAIL_RECEIVED,
                    title="بريد جديد",
                    message=f"رسالة من {current_user.full_name}: {email_input.subject}",
                    link="/emails/inbox",
                    related_id=email.id,
                    related_type="email"
                )
    
    # ربط بالمهمة إذا وجدت
    if email_input.related_task_id:
        task = await db.tasks.find_one({"id": email_input.related_task_id}, {"_id": 0})
        if task:
            await db.tasks.update_one(
                {"id": email_input.related_task_id},
                {"$set": {"related_task_number": task.get('task_number')}}
            )
    
    return {"message": "تم إرسال البريد بنجاح" if not email_input.save_as_draft else "تم حفظ المسودة", "email_id": email.id}

@api_router.get("/emails/inbox")
async def get_inbox(
    page: int = 1,
    limit: int = 20,
    current_user: User = Depends(get_current_user)
):
    """صندوق الوارد"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    skip = (page - 1) * limit
    
    # جلب سجلات البريد للمستخدم
    recipient_records = await db.email_recipients.find({
        "user_id": current_user.id,
        "folder": "inbox",
        "is_deleted": False
    }, {"_id": 0}).sort("_id", -1).skip(skip).limit(limit).to_list(limit)
    
    # جلب تفاصيل الرسائل
    emails = []
    for record in recipient_records:
        email = await db.emails.find_one({"id": record['email_id']}, {"_id": 0})
        if email:
            email['is_read'] = record.get('is_read', False)
            email['is_starred'] = record.get('is_starred', False)
            email['recipient_record_id'] = record.get('id')
            emails.append(email)
    
    # عدد الرسائل الكلي
    total = await db.email_recipients.count_documents({
        "user_id": current_user.id,
        "folder": "inbox",
        "is_deleted": False
    })
    
    return {
        "emails": emails,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/emails/sent")
async def get_sent_emails(
    page: int = 1,
    limit: int = 20,
    current_user: User = Depends(get_current_user)
):
    """البريد المرسل"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    skip = (page - 1) * limit
    
    emails = await db.emails.find({
        "sender_id": current_user.id,
        "status": EmailStatus.SENT
    }, {"_id": 0}).sort("sent_at", -1).skip(skip).limit(limit).to_list(limit)
    
    total = await db.emails.count_documents({
        "sender_id": current_user.id,
        "status": EmailStatus.SENT
    })
    
    return {
        "emails": emails,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/emails/drafts")
async def get_drafts(
    page: int = 1,
    limit: int = 20,
    current_user: User = Depends(get_current_user)
):
    """المسودات"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    skip = (page - 1) * limit
    
    emails = await db.emails.find({
        "sender_id": current_user.id,
        "status": EmailStatus.DRAFT
    }, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    total = await db.emails.count_documents({
        "sender_id": current_user.id,
        "status": EmailStatus.DRAFT
    })
    
    return {
        "emails": emails,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/emails/trash")
async def get_trash(
    page: int = 1,
    limit: int = 20,
    current_user: User = Depends(get_current_user)
):
    """المهملات"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    skip = (page - 1) * limit
    
    recipient_records = await db.email_recipients.find({
        "user_id": current_user.id,
        "is_deleted": True
    }, {"_id": 0}).sort("deleted_at", -1).skip(skip).limit(limit).to_list(limit)
    
    emails = []
    for record in recipient_records:
        email = await db.emails.find_one({"id": record['email_id']}, {"_id": 0})
        if email:
            emails.append(email)
    
    total = await db.email_recipients.count_documents({
        "user_id": current_user.id,
        "is_deleted": True
    })
    
    return {
        "emails": emails,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/emails/starred")
async def get_starred(
    page: int = 1,
    limit: int = 20,
    current_user: User = Depends(get_current_user)
):
    """الرسائل المميزة بنجمة"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    skip = (page - 1) * limit
    
    recipient_records = await db.email_recipients.find({
        "user_id": current_user.id,
        "is_starred": True,
        "is_deleted": False
    }, {"_id": 0}).skip(skip).limit(limit).to_list(limit)
    
    emails = []
    for record in recipient_records:
        email = await db.emails.find_one({"id": record['email_id']}, {"_id": 0})
        if email:
            email['is_starred'] = True
            emails.append(email)
    
    total = await db.email_recipients.count_documents({
        "user_id": current_user.id,
        "is_starred": True,
        "is_deleted": False
    })
    
    return {
        "emails": emails,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/emails/{email_id}")
async def get_email(email_id: str, current_user: User = Depends(get_current_user)):
    """جلب تفاصيل بريد"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    email = await db.emails.find_one({"id": email_id}, {"_id": 0})
    if not email:
        raise HTTPException(status_code=404, detail="البريد غير موجود")
    
    # التحقق من الصلاحية
    is_sender = email.get('sender_id') == current_user.id
    is_recipient = await db.email_recipients.find_one({
        "email_id": email_id,
        "user_id": current_user.id
    })
    
    if not is_sender and not is_recipient:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    # تحديد كمقروء
    if is_recipient:
        await db.email_recipients.update_one(
            {"email_id": email_id, "user_id": current_user.id},
            {"$set": {"is_read": True, "read_at": datetime.now(timezone.utc).isoformat()}}
        )
    
    # جلب سلسلة الرد إذا وجدت
    thread_emails = []
    if email.get('thread_id'):
        thread_emails = await db.emails.find({
            "thread_id": email.get('thread_id'),
            "status": EmailStatus.SENT
        }, {"_id": 0}).sort("sent_at", 1).to_list(50)
    
    return {
        "email": email,
        "thread": thread_emails
    }

@api_router.put("/emails/{email_id}")
async def update_email(
    email_id: str,
    update: EmailUpdate,
    current_user: User = Depends(get_current_user)
):
    """تحديث حالة بريد"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    update_data = {}
    if update.is_read is not None:
        update_data['is_read'] = update.is_read
        if update.is_read:
            update_data['read_at'] = datetime.now(timezone.utc).isoformat()
    if update.is_starred is not None:
        update_data['is_starred'] = update.is_starred
    if update.is_deleted is not None:
        update_data['is_deleted'] = update.is_deleted
        if update.is_deleted:
            update_data['deleted_at'] = datetime.now(timezone.utc).isoformat()
    if update.folder is not None:
        update_data['folder'] = update.folder
    
    if not update_data:
        raise HTTPException(status_code=400, detail="لا توجد بيانات للتحديث")
    
    result = await db.email_recipients.update_one(
        {"email_id": email_id, "user_id": current_user.id},
        {"$set": update_data}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="البريد غير موجود")
    
    return {"message": "تم التحديث بنجاح"}

@api_router.delete("/emails/{email_id}")
async def delete_email(email_id: str, permanent: bool = False, current_user: User = Depends(get_current_user)):
    """حذف بريد"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    if permanent:
        # حذف نهائي
        await db.email_recipients.delete_one({
            "email_id": email_id,
            "user_id": current_user.id
        })
    else:
        # نقل للمهملات
        await db.email_recipients.update_one(
            {"email_id": email_id, "user_id": current_user.id},
            {"$set": {
                "is_deleted": True,
                "deleted_at": datetime.now(timezone.utc).isoformat(),
                "folder": "trash"
            }}
        )
    
    return {"message": "تم حذف البريد"}

@api_router.put("/emails/{email_id}/restore")
async def restore_email(email_id: str, current_user: User = Depends(get_current_user)):
    """استعادة بريد من المهملات"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    await db.email_recipients.update_one(
        {"email_id": email_id, "user_id": current_user.id},
        {"$set": {
            "is_deleted": False,
            "deleted_at": None,
            "folder": "inbox"
        }}
    )
    
    return {"message": "تم استعادة البريد"}

@api_router.get("/emails/stats/unread")
async def get_email_stats(current_user: User = Depends(get_current_user)):
    """إحصائيات البريد"""
    if current_user.role == UserRole.CLIENT:
        return {"unread": 0, "drafts": 0}
    
    unread = await db.email_recipients.count_documents({
        "user_id": current_user.id,
        "folder": "inbox",
        "is_read": False,
        "is_deleted": False
    })
    
    drafts = await db.emails.count_documents({
        "sender_id": current_user.id,
        "status": EmailStatus.DRAFT
    })
    
    return {"unread": unread, "drafts": drafts}

@api_router.get("/emails/search")
async def search_emails(
    q: str,
    folder: str = "all",
    current_user: User = Depends(get_current_user)
):
    """البحث في البريد"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="البريد متاح للموظفين فقط")
    
    # البحث في الرسائل المرسلة والمستلمة
    query = {
        "$and": [
            {"$or": [
                {"sender_id": current_user.id},
                {"recipients.id": current_user.id}
            ]},
            {"$or": [
                {"subject": {"$regex": q, "$options": "i"}},
                {"body": {"$regex": q, "$options": "i"}},
                {"sender_name": {"$regex": q, "$options": "i"}}
            ]}
        ]
    }
    
    emails = await db.emails.find(query, {"_id": 0}).limit(50).to_list(50)
    
    return {"emails": emails, "count": len(emails)}

# ==================== تحديث تعيين المهام لإرسال إشعارات ====================

# ==================== APIs المسوق - العملاء المحتملين والعروض ====================

async def get_next_lead_number():
    """توليد رقم عميل محتمل تسلسلي"""
    year = datetime.now().year
    counter = await db.sequences.find_one_and_update(
        {"_id": f"leads_{year}"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    seq = counter.get("seq", 1)
    return f"LEAD-{year}-{seq:05d}"

async def get_next_proposal_number():
    """توليد رقم عرض تسلسلي"""
    year = datetime.now().year
    counter = await db.sequences.find_one_and_update(
        {"_id": f"proposals_{year}"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    seq = counter.get("seq", 1)
    return f"PROP-{year}-{seq:05d}"

@api_router.post("/leads", response_model=Lead)
async def create_lead(lead_input: LeadCreate, current_user: User = Depends(get_current_user)):
    """إنشاء عميل محتمل جديد"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MARKETER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك بإضافة عملاء محتملين")
    
    lead_number = await get_next_lead_number()
    
    lead = Lead(
        lead_number=lead_number,
        full_name=lead_input.full_name,
        phone=lead_input.phone,
        email=lead_input.email,
        company=lead_input.company,
        source=lead_input.source,
        interest=lead_input.interest,
        notes=lead_input.notes,
        assigned_to=current_user.id,
        assigned_to_name=current_user.full_name,
        created_by=current_user.id,
        created_by_name=current_user.full_name
    )
    
    lead_doc = lead.model_dump()
    lead_doc['created_at'] = lead_doc['created_at'].isoformat()
    await db.leads.insert_one(lead_doc)
    
    return lead

@api_router.get("/leads")
async def get_leads(
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """جلب قائمة العملاء المحتملين"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MARKETER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك بعرض العملاء المحتملين")
    
    query = {}
    
    # المسوق يرى فقط العملاء المحالين إليه
    if current_user.role == UserRole.MARKETER:
        query["assigned_to"] = current_user.id
    elif assigned_to:
        query["assigned_to"] = assigned_to
    
    if status:
        query["status"] = status
    
    leads = await db.leads.find(query, {"_id": 0}).sort("created_at", -1).to_list(200)
    return leads

@api_router.get("/leads/{lead_id}")
async def get_lead(lead_id: str, current_user: User = Depends(get_current_user)):
    """جلب تفاصيل عميل محتمل"""
    lead = await db.leads.find_one({"id": lead_id}, {"_id": 0})
    if not lead:
        raise HTTPException(status_code=404, detail="العميل المحتمل غير موجود")
    return lead

@api_router.put("/leads/{lead_id}")
async def update_lead(
    lead_id: str,
    status: Optional[str] = None,
    notes: Optional[str] = None,
    next_follow_up: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """تحديث عميل محتمل"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MARKETER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك")
    
    update_data = {}
    if status:
        update_data['status'] = status
    if notes:
        update_data['notes'] = notes
    if next_follow_up:
        update_data['next_follow_up'] = next_follow_up
    
    if update_data:
        await db.leads.update_one({"id": lead_id}, {"$set": update_data})
    
    return {"message": "تم التحديث بنجاح"}

@api_router.post("/proposals", response_model=Proposal)
async def create_proposal(proposal_input: ProposalCreate, current_user: User = Depends(get_current_user)):
    """إنشاء عرض جديد"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MARKETER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك بإنشاء عروض")
    
    proposal_number = await get_next_proposal_number()
    final_amount = proposal_input.amount - proposal_input.discount
    
    proposal = Proposal(
        proposal_number=proposal_number,
        lead_id=proposal_input.lead_id,
        lead_name=proposal_input.lead_name,
        client_id=proposal_input.client_id,
        client_name=proposal_input.client_name,
        phone=proposal_input.phone,
        email=proposal_input.email,
        title=proposal_input.title,
        service_type=proposal_input.service_type,
        description=proposal_input.description,
        amount=proposal_input.amount,
        discount=proposal_input.discount,
        final_amount=final_amount,
        validity_days=proposal_input.validity_days,
        created_by=current_user.id,
        created_by_name=current_user.full_name
    )
    
    proposal_doc = proposal.model_dump()
    proposal_doc['created_at'] = proposal_doc['created_at'].isoformat()
    await db.proposals.insert_one(proposal_doc)
    
    return proposal

@api_router.get("/proposals")
async def get_proposals(
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """جلب قائمة العروض"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MARKETER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك")
    
    query = {}
    
    if current_user.role == UserRole.MARKETER:
        query["created_by"] = current_user.id
    
    if status:
        query["status"] = status
    
    proposals = await db.proposals.find(query, {"_id": 0}).sort("created_at", -1).to_list(200)
    return proposals

@api_router.put("/proposals/{proposal_id}/send")
async def send_proposal(
    proposal_id: str,
    send_via: str = "whatsapp",
    current_user: User = Depends(get_current_user)
):
    """تحديث حالة العرض كـ مرسل"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MARKETER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك")
    
    proposal = await db.proposals.find_one({"id": proposal_id}, {"_id": 0})
    if not proposal:
        raise HTTPException(status_code=404, detail="العرض غير موجود")
    
    await db.proposals.update_one(
        {"id": proposal_id},
        {"$set": {
            "status": "sent",
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "sent_via": send_via
        }}
    )
    
    # تحديث حالة العميل المحتمل إذا وجد
    if proposal.get('lead_id'):
        await db.leads.update_one(
            {"id": proposal['lead_id']},
            {"$set": {"status": "proposal_sent"}}
        )
    
    return {"message": "تم تحديث حالة العرض", "proposal": proposal}

@api_router.post("/contact-logs")
async def create_contact_log(
    contact_type: str,
    phone: str,
    lead_id: Optional[str] = None,
    lead_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_name: Optional[str] = None,
    direction: str = "outgoing",
    duration: Optional[int] = None,
    notes: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """تسجيل تواصل جديد"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MARKETER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك")
    
    contact_log = ContactLog(
        contact_type=contact_type,
        lead_id=lead_id,
        lead_name=lead_name,
        client_id=client_id,
        client_name=client_name,
        phone=phone,
        direction=direction,
        duration=duration,
        notes=notes,
        performed_by=current_user.id,
        performed_by_name=current_user.full_name
    )
    
    log_doc = contact_log.model_dump()
    log_doc['created_at'] = log_doc['created_at'].isoformat()
    await db.contact_logs.insert_one(log_doc)
    
    # تحديث آخر تواصل للعميل المحتمل
    if lead_id:
        await db.leads.update_one(
            {"id": lead_id},
            {"$set": {
                "last_contact": datetime.now(timezone.utc).isoformat(),
                "last_contact_type": contact_type,
                "status": "contacted" if contact_type else None
            }}
        )
    
    return {"message": "تم تسجيل التواصل", "id": contact_log.id}

@api_router.get("/contact-logs")
async def get_contact_logs(
    lead_id: Optional[str] = None,
    client_id: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """جلب سجل التواصل"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MARKETER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك")
    
    query = {}
    if current_user.role == UserRole.MARKETER:
        query["performed_by"] = current_user.id
    if lead_id:
        query["lead_id"] = lead_id
    if client_id:
        query["client_id"] = client_id
    
    logs = await db.contact_logs.find(query, {"_id": 0}).sort("created_at", -1).to_list(200)
    return logs

@api_router.get("/marketer/dashboard")
async def get_marketer_dashboard(current_user: User = Depends(get_current_user)):
    """إحصائيات لوحة تحكم المسوق"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MARKETER]:
        raise HTTPException(status_code=403, detail="غير مصرح لك")
    
    query = {}
    if current_user.role == UserRole.MARKETER:
        query["assigned_to"] = current_user.id
    
    # إحصائيات العملاء المحتملين
    total_leads = await db.leads.count_documents(query)
    new_leads = await db.leads.count_documents({**query, "status": "new"})
    contacted_leads = await db.leads.count_documents({**query, "status": "contacted"})
    interested_leads = await db.leads.count_documents({**query, "status": "interested"})
    proposal_sent = await db.leads.count_documents({**query, "status": "proposal_sent"})
    converted_leads = await db.leads.count_documents({**query, "status": "converted"})
    
    # إحصائيات العروض
    proposal_query = {"created_by": current_user.id} if current_user.role == UserRole.MARKETER else {}
    total_proposals = await db.proposals.count_documents(proposal_query)
    sent_proposals = await db.proposals.count_documents({**proposal_query, "status": "sent"})
    accepted_proposals = await db.proposals.count_documents({**proposal_query, "status": "accepted"})
    
    # إحصائيات التواصل اليوم
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    contact_query = {"performed_by": current_user.id} if current_user.role == UserRole.MARKETER else {}
    today_contacts = await db.contact_logs.count_documents({
        **contact_query,
        "created_at": {"$regex": f"^{today}"}
    })
    
    return {
        "leads": {
            "total": total_leads,
            "new": new_leads,
            "contacted": contacted_leads,
            "interested": interested_leads,
            "proposal_sent": proposal_sent,
            "converted": converted_leads
        },
        "proposals": {
            "total": total_proposals,
            "sent": sent_proposals,
            "accepted": accepted_proposals
        },
        "today_contacts": today_contacts
    }

# ==================== المحكمة الافتراضية APIs ====================

# نماذج بيانات المحكمة الافتراضية
class VirtualCourtCase(BaseModel):
    """نموذج القضية التدريبية"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    case_type: str  # جنائي، مدني، تجاري، أحوال شخصية
    difficulty: str  # مبتدئ، متوسط، متقدم
    description: str
    facts: str
    evidence: List[dict] = []  # قائمة الأدلة
    witnesses: List[dict] = []  # قائمة الشهود
    legal_articles: List[str] = []  # المواد القانونية المرتبطة
    correct_verdict: Optional[str] = None
    points: int = 100
    time_limit: int = 30  # بالدقائق

class ProsecutorGameScenario(BaseModel):
    """سيناريو لعبة وكيل النيابة"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    case_summary: str  # ملخص القضية
    crime_type: str  # نوع الجريمة
    evidence_list: List[dict]  # الأدلة المتاحة
    suspects: List[dict]  # المشتبه بهم
    correct_accusation: str  # التهمة الصحيحة
    correct_articles: List[str]  # المواد القانونية الصحيحة
    difficulty: str
    points: int = 150
    time_limit: int = 20  # بالدقائق

class GameAttempt(BaseModel):
    """محاولة اللعب"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    game_type: str  # prosecutor, golden_pleading, procedural_error
    scenario_id: str
    score: int = 0
    correct_answers: int = 0
    total_questions: int = 0
    time_taken: int = 0  # بالثواني
    completed: bool = False
    answers: List[dict] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserGameProfile(BaseModel):
    """ملف اللاعب"""
    user_id: str
    total_xp: int = 0
    level: int = 1
    rank: str = "مبتدئ"
    games_played: int = 0
    games_won: int = 0
    badges: List[str] = []
    streak_days: int = 0
    last_played: Optional[str] = None

# سيناريوهات لعبة وكيل النيابة المدمجة
PROSECUTOR_SCENARIOS = [
    {
        "id": "scenario_1",
        "title": "سرقة المتجر",
        "case_summary": "تم الإبلاغ عن سرقة متجر إلكترونيات في حي الملز. كاميرات المراقبة سجلت الحادثة وتم القبض على المشتبه به بعد ساعتين من الحادثة.",
        "crime_type": "سرقة",
        "evidence_list": [
            {"id": "e1", "type": "video", "description": "تسجيل كاميرا المراقبة يظهر شخصاً يدخل المتجر ويأخذ أجهزة", "relevance": "high"},
            {"id": "e2", "type": "physical", "description": "أجهزة مسروقة وجدت في سيارة المشتبه به", "relevance": "high"},
            {"id": "e3", "type": "witness", "description": "شهادة صاحب المتجر", "relevance": "medium"},
            {"id": "e4", "type": "document", "description": "فواتير الأجهزة المسروقة", "relevance": "medium"},
            {"id": "e5", "type": "irrelevant", "description": "تذكرة مخالفة مرورية قديمة", "relevance": "none"}
        ],
        "suspects": [
            {"id": "s1", "name": "خالد محمد", "description": "موظف سابق في المتجر، تم فصله قبل شهر", "is_culprit": True},
            {"id": "s2", "name": "أحمد علي", "description": "زبون اشترى من المتجر نفس اليوم", "is_culprit": False}
        ],
        "correct_accusation": "جريمة سرقة موصوفة",
        "correct_articles": ["نظام مكافحة الاحتيال المالي - المادة 4", "نظام العقوبات - المادة 321"],
        "difficulty": "مبتدئ",
        "points": 100,
        "time_limit": 15
    },
    {
        "id": "scenario_2",
        "title": "الاحتيال المالي",
        "case_summary": "قدم موظف في شركة مالية مستندات مزورة للحصول على قروض باسم عملاء وهميين. تم اكتشاف العملية عند مراجعة الحسابات السنوية.",
        "crime_type": "احتيال مالي",
        "evidence_list": [
            {"id": "e1", "type": "document", "description": "مستندات مزورة تحمل توقيعات مزيفة", "relevance": "high"},
            {"id": "e2", "type": "digital", "description": "سجلات الدخول لنظام الشركة تظهر تعديلات غير مصرح بها", "relevance": "high"},
            {"id": "e3", "type": "financial", "description": "تحويلات مالية لحسابات مشبوهة", "relevance": "high"},
            {"id": "e4", "type": "witness", "description": "شهادة مدير القسم", "relevance": "medium"},
            {"id": "e5", "type": "irrelevant", "description": "صور من حفل الشركة السنوي", "relevance": "none"}
        ],
        "suspects": [
            {"id": "s1", "name": "سعد الحربي", "description": "موظف في قسم القروض منذ 5 سنوات", "is_culprit": True},
            {"id": "s2", "name": "فهد الدوسري", "description": "مدير القسم المالي", "is_culprit": False},
            {"id": "s3", "name": "محمد السبيعي", "description": "موظف جديد انضم قبل 3 أشهر", "is_culprit": False}
        ],
        "correct_accusation": "احتيال مالي وتزوير مستندات رسمية",
        "correct_articles": ["نظام مكافحة الاحتيال المالي - المادة 2", "نظام مكافحة التزوير - المادة 5", "نظام العمل - المادة 80"],
        "difficulty": "متوسط",
        "points": 150,
        "time_limit": 20
    },
    {
        "id": "scenario_3",
        "title": "التهديد والابتزاز",
        "case_summary": "تلقت سيدة رسائل تهديد وابتزاز عبر وسائل التواصل الاجتماعي من شخص يدعي امتلاكه صوراً خاصة ويطالب بمبالغ مالية.",
        "crime_type": "ابتزاز إلكتروني",
        "evidence_list": [
            {"id": "e1", "type": "digital", "description": "رسائل التهديد والابتزاز", "relevance": "high"},
            {"id": "e2", "type": "digital", "description": "تتبع عنوان IP للمرسل", "relevance": "high"},
            {"id": "e3", "type": "financial", "description": "حوالات مالية من الضحية للمبتز", "relevance": "high"},
            {"id": "e4", "type": "witness", "description": "شهادة الضحية", "relevance": "high"},
            {"id": "e5", "type": "irrelevant", "description": "منشورات عامة على انستقرام", "relevance": "none"}
        ],
        "suspects": [
            {"id": "s1", "name": "عبدالله القحطاني", "description": "معرف إلكتروني مرتبط بالحساب المستخدم في الابتزاز", "is_culprit": True},
            {"id": "s2", "name": "ناصر العتيبي", "description": "صديق سابق للضحية", "is_culprit": False}
        ],
        "correct_accusation": "ابتزاز إلكتروني وتهديد",
        "correct_articles": ["نظام مكافحة الجرائم المعلوماتية - المادة 3", "نظام مكافحة الجرائم المعلوماتية - المادة 6"],
        "difficulty": "متوسط",
        "points": 150,
        "time_limit": 18
    },
    {
        "id": "scenario_4",
        "title": "القتل الخطأ",
        "case_summary": "حادث مروري على طريق الملك فهد أدى لوفاة شخص. السائق كان يقود بسرعة زائدة ويستخدم الجوال. تم ضبطه في الموقع.",
        "crime_type": "قتل خطأ",
        "evidence_list": [
            {"id": "e1", "type": "physical", "description": "تقرير الحادث المروري", "relevance": "high"},
            {"id": "e2", "type": "digital", "description": "سجل المكالمات يثبت استخدام الجوال وقت الحادث", "relevance": "high"},
            {"id": "e3", "type": "physical", "description": "تقرير الطبيب الشرعي", "relevance": "high"},
            {"id": "e4", "type": "witness", "description": "شهادة شهود عيان على السرعة الزائدة", "relevance": "high"},
            {"id": "e5", "type": "document", "description": "سجل مخالفات السائق السابقة", "relevance": "medium"},
            {"id": "e6", "type": "irrelevant", "description": "صور من كاميرا ساهر لمخالفات قديمة", "relevance": "none"}
        ],
        "suspects": [
            {"id": "s1", "name": "فيصل الشمري", "description": "سائق السيارة المتسببة في الحادث", "is_culprit": True}
        ],
        "correct_accusation": "قتل خطأ ناتج عن إهمال وتهور في القيادة",
        "correct_articles": ["نظام المرور - المادة 75", "القتل شبه العمد - النظام الجزائي"],
        "difficulty": "متقدم",
        "points": 200,
        "time_limit": 25
    },
    {
        "id": "scenario_5",
        "title": "غسيل الأموال",
        "case_summary": "شركة صرافة صغيرة تجري تحويلات مالية كبيرة ومتكررة دون توثيق مصدر الأموال. تم رصد نشاط مشبوه من قبل مؤسسة النقد.",
        "crime_type": "غسيل أموال",
        "evidence_list": [
            {"id": "e1", "type": "financial", "description": "سجلات التحويلات المالية المشبوهة", "relevance": "high"},
            {"id": "e2", "type": "document", "description": "عقود تجارية وهمية", "relevance": "high"},
            {"id": "e3", "type": "digital", "description": "مراسلات إلكترونية تكشف التنسيق", "relevance": "high"},
            {"id": "e4", "type": "financial", "description": "حسابات بنكية في الخارج", "relevance": "high"},
            {"id": "e5", "type": "witness", "description": "شهادة موظف سابق", "relevance": "medium"},
            {"id": "e6", "type": "irrelevant", "description": "إعلانات الشركة في الصحف", "relevance": "none"}
        ],
        "suspects": [
            {"id": "s1", "name": "عمر الغامدي", "description": "صاحب شركة الصرافة", "is_culprit": True},
            {"id": "s2", "name": "ماجد الزهراني", "description": "مدير العمليات في الشركة", "is_culprit": True},
            {"id": "s3", "name": "سالم الشهري", "description": "موظف استقبال جديد", "is_culprit": False}
        ],
        "correct_accusation": "غسيل أموال وتزوير مستندات تجارية",
        "correct_articles": ["نظام مكافحة غسل الأموال - المادة 2", "نظام مكافحة غسل الأموال - المادة 16", "نظام مكافحة التزوير - المادة 8"],
        "difficulty": "متقدم",
        "points": 250,
        "time_limit": 30
    }
]

# ==================== سيناريوهات لعبة المرافعة الذهبية ====================
GOLDEN_PLEADING_SCENARIOS = [
    {
        "id": "pleading_1",
        "title": "الدفاع عن متهم بالسرقة",
        "case_type": "جنائي",
        "difficulty": "مبتدئ",
        "situation": "موكلك متهم بسرقة هاتف محمول من متجر. كاميرات المراقبة أظهرت شخصاً يشبهه. موكلك يؤكد أنه كان في مكان آخر وقت الحادثة.",
        "your_role": "محامي الدفاع",
        "opponent_arguments": [
            "تسجيل الكاميرا يُظهر المتهم بوضوح",
            "المتهم كان قريباً من المتجر في نفس اليوم",
            "لم يقدم المتهم دليلاً على تواجده في مكان آخر"
        ],
        "available_defenses": [
            {"id": "d1", "text": "جودة تسجيل الكاميرا رديئة ولا تثبت هوية موكلي بشكل قاطع", "score": 25, "is_strong": True},
            {"id": "d2", "text": "لدى موكلي شهود يؤكدون تواجده في مكان آخر وقت الحادثة", "score": 30, "is_strong": True},
            {"id": "d3", "text": "موكلي شخص محترم ولا يمكن أن يسرق", "score": 5, "is_strong": False},
            {"id": "d4", "text": "التشابه في الملامح لا يعني أن موكلي هو الجاني", "score": 20, "is_strong": True},
            {"id": "d5", "text": "لم يتم العثور على المسروقات بحوزة موكلي", "score": 25, "is_strong": True},
            {"id": "d6", "text": "المتجر لم يتخذ إجراءات أمنية كافية", "score": 0, "is_strong": False}
        ],
        "winning_threshold": 70,
        "points": 100,
        "time_limit": 10
    },
    {
        "id": "pleading_2",
        "title": "قضية فسخ عقد إيجار",
        "case_type": "مدني",
        "difficulty": "متوسط",
        "situation": "موكلك (المؤجر) يريد فسخ عقد إيجار مع مستأجر تأخر عن دفع الإيجار لثلاثة أشهر متتالية. المستأجر يدعي أنه واجه ظروفاً مالية صعبة.",
        "your_role": "محامي المؤجر",
        "opponent_arguments": [
            "المستأجر واجه ظروفاً مالية قاهرة بسبب فقدان وظيفته",
            "المستأجر وعد بسداد المتأخرات خلال شهرين",
            "العقد لا ينص صراحة على الفسخ الفوري عند التأخر"
        ],
        "available_defenses": [
            {"id": "d1", "text": "التأخر عن دفع الإيجار لثلاثة أشهر يعد إخلالاً جوهرياً بالعقد", "score": 30, "is_strong": True},
            {"id": "d2", "text": "نظام الإيجار يمنح المؤجر حق الفسخ عند التأخر المتكرر", "score": 25, "is_strong": True},
            {"id": "d3", "text": "موكلي بحاجة للمال بشكل عاجل", "score": 5, "is_strong": False},
            {"id": "d4", "text": "الظروف المالية للمستأجر لا تعفيه من التزاماته التعاقدية", "score": 20, "is_strong": True},
            {"id": "d5", "text": "موكلي أرسل إنذارات متعددة قبل اللجوء للقضاء", "score": 20, "is_strong": True},
            {"id": "d6", "text": "المستأجر شخص غير مسؤول", "score": 0, "is_strong": False}
        ],
        "winning_threshold": 75,
        "points": 150,
        "time_limit": 12
    },
    {
        "id": "pleading_3",
        "title": "قضية تعويض عن حادث مروري",
        "case_type": "مدني",
        "difficulty": "متوسط",
        "situation": "موكلك أصيب في حادث مروري بسبب إهمال السائق الآخر الذي قطع الإشارة الحمراء. موكلك يطالب بتعويض عن الإصابات والأضرار.",
        "your_role": "محامي المصاب",
        "opponent_arguments": [
            "لم يكن هناك شهود على الحادث",
            "تقرير المرور لم يحدد المخطئ بشكل قاطع",
            "المصاب كان يسير بسرعة زائدة"
        ],
        "available_defenses": [
            {"id": "d1", "text": "تسجيل كاميرا ساهر يثبت قطع المتهم للإشارة الحمراء", "score": 30, "is_strong": True},
            {"id": "d2", "text": "التقارير الطبية تثبت حجم الإصابات الناتجة عن الحادث", "score": 25, "is_strong": True},
            {"id": "d3", "text": "موكلي شخص ملتزم بقواعد المرور دائماً", "score": 5, "is_strong": False},
            {"id": "d4", "text": "ادعاء السرعة الزائدة لم يُثبت بأي دليل", "score": 20, "is_strong": True},
            {"id": "d5", "text": "موكلي تكبد خسائر مادية موثقة (إصلاح السيارة + علاج)", "score": 20, "is_strong": True},
            {"id": "d6", "text": "السائق الآخر معروف بقيادته المتهورة", "score": 0, "is_strong": False}
        ],
        "winning_threshold": 75,
        "points": 150,
        "time_limit": 12
    },
    {
        "id": "pleading_4",
        "title": "الدفاع في قضية قذف وتشهير",
        "case_type": "جنائي",
        "difficulty": "متقدم",
        "situation": "موكلك متهم بنشر تغريدات مسيئة عن رجل أعمال معروف. المدعي يطالب بتعويض وعقوبة جنائية. موكلك يؤكد أن ما نشره كان رأياً مبنياً على وقائع.",
        "your_role": "محامي الدفاع",
        "opponent_arguments": [
            "التغريدات تضمنت اتهامات صريحة بالفساد",
            "انتشرت التغريدات بشكل واسع وأضرت بسمعة المدعي",
            "المتهم لم يتحقق من صحة المعلومات قبل نشرها"
        ],
        "available_defenses": [
            {"id": "d1", "text": "ما نشره موكلي كان تعليقاً على شأن عام يهم الرأي العام", "score": 25, "is_strong": True},
            {"id": "d2", "text": "المعلومات المنشورة مستندة إلى تقارير إعلامية سابقة", "score": 20, "is_strong": True},
            {"id": "d3", "text": "موكلي شخص محترم وله سمعة طيبة", "score": 5, "is_strong": False},
            {"id": "d4", "text": "حرية الرأي مكفولة بالنظام الأساسي للحكم", "score": 15, "is_strong": True},
            {"id": "d5", "text": "لم يذكر موكلي اسم المدعي صراحة في التغريدات", "score": 20, "is_strong": True},
            {"id": "d6", "text": "المدعي لم يثبت الضرر الفعلي الذي لحق به", "score": 15, "is_strong": True}
        ],
        "winning_threshold": 80,
        "points": 200,
        "time_limit": 15
    },
    {
        "id": "pleading_5",
        "title": "قضية نفقة بعد الطلاق",
        "case_type": "أحوال شخصية",
        "difficulty": "متقدم",
        "situation": "موكلتك (الزوجة المطلقة) تطالب بزيادة نفقة الأطفال. الزوج السابق يدعي عدم قدرته المالية رغم امتلاكه لعدة عقارات وسيارات فارهة.",
        "your_role": "محامي الزوجة",
        "opponent_arguments": [
            "الزوج السابق فقد وظيفته مؤخراً",
            "العقارات مرهونة للبنك",
            "النفقة الحالية كافية لاحتياجات الأطفال"
        ],
        "available_defenses": [
            {"id": "d1", "text": "سجلات العقار تثبت امتلاك الزوج لأصول غير مرهونة", "score": 25, "is_strong": True},
            {"id": "d2", "text": "مستوى معيشة الأطفال يجب أن يتناسب مع دخل الأب الفعلي", "score": 25, "is_strong": True},
            {"id": "d3", "text": "موكلتي تعاني مالياً وتحتاج المال", "score": 5, "is_strong": False},
            {"id": "d4", "text": "صور السيارات الفارهة على حسابات الزوج تثبت قدرته المالية", "score": 20, "is_strong": True},
            {"id": "d5", "text": "احتياجات الأطفال التعليمية والصحية ارتفعت", "score": 15, "is_strong": True},
            {"id": "d6", "text": "الزوج السابق يسافر للخارج بشكل متكرر", "score": 10, "is_strong": True}
        ],
        "winning_threshold": 80,
        "points": 200,
        "time_limit": 15
    }
]

# ==================== سيناريوهات لعبة الخطأ الإجرائي ====================
PROCEDURAL_ERROR_SCENARIOS = [
    {
        "id": "error_1",
        "title": "محاكمة بدون محامٍ",
        "difficulty": "مبتدئ",
        "case_description": "تمت محاكمة متهم بجريمة سرقة كبرى دون توفير محامٍ له رغم طلبه ذلك. المحكمة رفضت طلبه بحجة أن القضية بسيطة.",
        "court_proceedings": [
            "افتتح القاضي الجلسة وسأل المتهم عن التهمة",
            "طلب المتهم توكيل محامٍ للدفاع عنه",
            "رفض القاضي الطلب قائلاً إن القضية واضحة",
            "استمرت المحاكمة بدون محامٍ",
            "صدر الحكم بإدانة المتهم"
        ],
        "errors": [
            {"id": "e1", "description": "رفض طلب المتهم لتوكيل محامٍ في جريمة كبرى", "is_error": True, "explanation": "نظام الإجراءات الجزائية يكفل حق المتهم في الاستعانة بمحامٍ"},
            {"id": "e2", "description": "افتتاح الجلسة من قبل القاضي", "is_error": False, "explanation": "إجراء صحيح"},
            {"id": "e3", "description": "سؤال المتهم عن التهمة", "is_error": False, "explanation": "إجراء صحيح"},
            {"id": "e4", "description": "الاستمرار في المحاكمة بدون محامٍ", "is_error": True, "explanation": "يجب وقف المحاكمة حتى يتم توفير محامٍ"},
            {"id": "e5", "description": "إصدار الحكم في نفس الجلسة", "is_error": False, "explanation": "يجوز إصدار الحكم إذا اكتملت الإجراءات"}
        ],
        "points": 100,
        "time_limit": 8
    },
    {
        "id": "error_2",
        "title": "تفتيش بدون إذن",
        "difficulty": "مبتدئ",
        "case_description": "قام رجال الأمن بتفتيش منزل مشتبه به بناءً على بلاغ مجهول دون الحصول على إذن من النيابة. تم العثور على مواد مخدرة.",
        "court_proceedings": [
            "وصل رجال الأمن للمنزل بناءً على بلاغ",
            "طرقوا الباب وطلبوا الدخول",
            "رفض صاحب المنزل السماح بالتفتيش",
            "دخل رجال الأمن بالقوة وفتشوا المنزل",
            "تم العثور على مواد مخدرة واعتقال صاحب المنزل"
        ],
        "errors": [
            {"id": "e1", "description": "الذهاب للمنزل بناءً على بلاغ", "is_error": False, "explanation": "يجوز التحقق من البلاغات"},
            {"id": "e2", "description": "طرق الباب وطلب الدخول", "is_error": False, "explanation": "إجراء صحيح"},
            {"id": "e3", "description": "الدخول بالقوة دون إذن قضائي", "is_error": True, "explanation": "يجب الحصول على إذن من النيابة للتفتيش"},
            {"id": "e4", "description": "تفتيش المنزل بدون إذن", "is_error": True, "explanation": "التفتيش باطل لعدم وجود إذن"},
            {"id": "e5", "description": "اعتقال صاحب المنزل", "is_error": True, "explanation": "الاعتقال مبني على دليل باطل"}
        ],
        "points": 100,
        "time_limit": 8
    },
    {
        "id": "error_3",
        "title": "انتهاك سرية التحقيق",
        "difficulty": "متوسط",
        "case_description": "أثناء التحقيق مع متهم في قضية اختلاس، قام المحقق بتصوير الجلسة ونشرها على وسائل التواصل الاجتماعي قبل صدور الحكم.",
        "court_proceedings": [
            "بدأ التحقيق مع المتهم بحضور محاميه",
            "قام المحقق بتسجيل الجلسة بكاميرا هاتفه",
            "نشر المحقق مقاطع من التحقيق على تويتر",
            "انتشرت المقاطع وتم تحديد هوية المتهم",
            "طالب المحامي ببطلان التحقيق"
        ],
        "errors": [
            {"id": "e1", "description": "حضور المحامي أثناء التحقيق", "is_error": False, "explanation": "حق مكفول للمتهم"},
            {"id": "e2", "description": "تسجيل التحقيق بهاتف شخصي", "is_error": True, "explanation": "يجب أن يكون التسجيل رسمياً فقط"},
            {"id": "e3", "description": "نشر مقاطع التحقيق علناً", "is_error": True, "explanation": "انتهاك صريح لسرية التحقيق"},
            {"id": "e4", "description": "كشف هوية المتهم قبل الحكم", "is_error": True, "explanation": "المتهم بريء حتى تثبت إدانته"},
            {"id": "e5", "description": "طلب المحامي بطلان التحقيق", "is_error": False, "explanation": "حق قانوني للدفاع"}
        ],
        "points": 150,
        "time_limit": 10
    },
    {
        "id": "error_4",
        "title": "محاكمة قاصر كبالغ",
        "difficulty": "متوسط",
        "case_description": "تمت محاكمة حدث (15 سنة) في محكمة جزائية عادية بتهمة السرقة، وصدر بحقه حكم بالسجن مع بالغين.",
        "court_proceedings": [
            "تم القبض على الحدث متلبساً بالسرقة",
            "أحيل للنيابة العامة ثم للمحكمة الجزائية",
            "لم يتم استدعاء ولي أمره أثناء المحاكمة",
            "صدر الحكم بسجنه سنة في سجن عادي",
            "لم يُعرض على الأخصائي الاجتماعي"
        ],
        "errors": [
            {"id": "e1", "description": "القبض على الحدث متلبساً", "is_error": False, "explanation": "إجراء صحيح"},
            {"id": "e2", "description": "إحالته لمحكمة جزائية عادية بدلاً من محكمة الأحداث", "is_error": True, "explanation": "يجب محاكمة الأحداث في محاكم متخصصة"},
            {"id": "e3", "description": "عدم استدعاء ولي الأمر", "is_error": True, "explanation": "يجب حضور ولي الأمر في محاكمة الأحداث"},
            {"id": "e4", "description": "الحكم بسجنه مع البالغين", "is_error": True, "explanation": "يجب فصل الأحداث عن البالغين"},
            {"id": "e5", "description": "عدم عرضه على أخصائي اجتماعي", "is_error": True, "explanation": "إجراء إلزامي في قضايا الأحداث"}
        ],
        "points": 150,
        "time_limit": 10
    },
    {
        "id": "error_5",
        "title": "إكراه على الاعتراف",
        "difficulty": "متقدم",
        "case_description": "اعترف متهم بارتكاب جريمة قتل بعد احتجازه 48 ساعة متواصلة دون طعام أو نوم. لاحقاً تراجع عن اعترافه أمام المحكمة.",
        "court_proceedings": [
            "تم احتجاز المتهم للتحقيق",
            "استمر التحقيق 48 ساعة متواصلة",
            "حُرم المتهم من الطعام والنوم",
            "اعترف المتهم تحت الضغط",
            "تراجع عن اعترافه أمام القاضي",
            "قبل القاضي الاعتراف الأول كدليل"
        ],
        "errors": [
            {"id": "e1", "description": "احتجاز المتهم للتحقيق", "is_error": False, "explanation": "إجراء جائز قانوناً"},
            {"id": "e2", "description": "التحقيق لمدة 48 ساعة متواصلة", "is_error": True, "explanation": "يجب إعطاء فترات راحة كافية"},
            {"id": "e3", "description": "حرمان المتهم من الطعام والنوم", "is_error": True, "explanation": "يعد تعذيباً نفسياً وجسدياً"},
            {"id": "e4", "description": "الاعتراف تحت الإكراه", "is_error": True, "explanation": "الاعتراف الناتج عن إكراه باطل"},
            {"id": "e5", "description": "قبول الاعتراف رغم التراجع عنه", "is_error": True, "explanation": "يجب التحقق من ظروف الاعتراف"},
            {"id": "e6", "description": "تراجع المتهم عن اعترافه", "is_error": False, "explanation": "حق مكفول للمتهم"}
        ],
        "points": 200,
        "time_limit": 12
    }
]

# API للحصول على سيناريوهات لعبة وكيل النيابة
@api_router.get("/virtual-court/prosecutor-game/scenarios")
async def get_prosecutor_scenarios(difficulty: Optional[str] = None):
    """جلب سيناريوهات لعبة وكيل النيابة"""
    scenarios = PROSECUTOR_SCENARIOS.copy()
    if difficulty:
        scenarios = [s for s in scenarios if s["difficulty"] == difficulty]
    
    # إرجاع البيانات بدون الإجابات الصحيحة
    safe_scenarios = []
    for s in scenarios:
        safe_s = s.copy()
        del safe_s["correct_accusation"]
        del safe_s["correct_articles"]
        # إخفاء من هو الجاني
        safe_s["suspects"] = [{"id": sus["id"], "name": sus["name"], "description": sus["description"]} for sus in s["suspects"]]
        safe_scenarios.append(safe_s)
    
    return {"scenarios": safe_scenarios}

@api_router.get("/virtual-court/prosecutor-game/scenario/{scenario_id}")
async def get_prosecutor_scenario(scenario_id: str):
    """جلب سيناريو محدد"""
    scenario = next((s for s in PROSECUTOR_SCENARIOS if s["id"] == scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="السيناريو غير موجود")
    
    # إرجاع بدون الإجابات
    safe_s = scenario.copy()
    del safe_s["correct_accusation"]
    del safe_s["correct_articles"]
    safe_s["suspects"] = [{"id": sus["id"], "name": sus["name"], "description": sus["description"]} for sus in scenario["suspects"]]
    
    return safe_s

class ProsecutorGameSubmission(BaseModel):
    scenario_id: str
    selected_culprits: List[str]  # IDs of selected culprits
    selected_evidence: List[str]  # IDs of selected evidence
    accusation: str
    selected_articles: List[str]
    time_taken: int  # بالثواني

@api_router.post("/virtual-court/prosecutor-game/submit")
async def submit_prosecutor_game(submission: ProsecutorGameSubmission, current_user: User = Depends(get_current_user)):
    """تقديم إجابة لعبة وكيل النيابة"""
    scenario = next((s for s in PROSECUTOR_SCENARIOS if s["id"] == submission.scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="السيناريو غير موجود")
    
    score = 0
    max_score = scenario["points"]
    feedback = []
    
    # حساب النقاط - اختيار الجناة الصحيحين (30%)
    correct_culprits = [sus["id"] for sus in scenario["suspects"] if sus.get("is_culprit", False)]
    culprit_score = 0
    if set(submission.selected_culprits) == set(correct_culprits):
        culprit_score = int(max_score * 0.3)
        feedback.append({"type": "success", "message": "ممتاز! اخترت الجناة بشكل صحيح"})
    elif any(c in correct_culprits for c in submission.selected_culprits):
        culprit_score = int(max_score * 0.15)
        feedback.append({"type": "partial", "message": "اخترت بعض الجناة بشكل صحيح"})
    else:
        feedback.append({"type": "error", "message": f"الجناة الصحيحون: {', '.join([sus['name'] for sus in scenario['suspects'] if sus.get('is_culprit', False)])}"})
    score += culprit_score
    
    # حساب النقاط - اختيار الأدلة المهمة (25%)
    relevant_evidence = [e["id"] for e in scenario["evidence_list"] if e["relevance"] in ["high", "medium"]]
    high_evidence = [e["id"] for e in scenario["evidence_list"] if e["relevance"] == "high"]
    evidence_score = 0
    selected_relevant = [e for e in submission.selected_evidence if e in relevant_evidence]
    selected_high = [e for e in submission.selected_evidence if e in high_evidence]
    
    if len(selected_high) == len(high_evidence) and not any(e for e in submission.selected_evidence if e not in relevant_evidence):
        evidence_score = int(max_score * 0.25)
        feedback.append({"type": "success", "message": "ممتاز! اخترت الأدلة المهمة بدقة"})
    elif len(selected_relevant) > 0:
        evidence_score = int(max_score * 0.25 * (len(selected_relevant) / len(relevant_evidence)))
        feedback.append({"type": "partial", "message": f"اخترت {len(selected_relevant)} من {len(relevant_evidence)} دليل مهم"})
    else:
        feedback.append({"type": "error", "message": "لم تختر الأدلة المهمة"})
    score += evidence_score
    
    # حساب النقاط - التهمة (25%)
    accusation_score = 0
    if submission.accusation.strip() and any(keyword in submission.accusation for keyword in scenario["correct_accusation"].split()):
        accusation_score = int(max_score * 0.25)
        feedback.append({"type": "success", "message": "التهمة صحيحة"})
    elif submission.accusation.strip():
        accusation_score = int(max_score * 0.1)
        feedback.append({"type": "partial", "message": f"التهمة الأدق: {scenario['correct_accusation']}"})
    else:
        feedback.append({"type": "error", "message": f"التهمة الصحيحة: {scenario['correct_accusation']}"})
    score += accusation_score
    
    # حساب النقاط - المواد القانونية (20%)
    articles_score = 0
    correct_articles = set(scenario["correct_articles"])
    selected_articles = set(submission.selected_articles)
    matched_articles = correct_articles.intersection(selected_articles)
    
    if len(matched_articles) == len(correct_articles):
        articles_score = int(max_score * 0.2)
        feedback.append({"type": "success", "message": "اخترت المواد القانونية الصحيحة"})
    elif len(matched_articles) > 0:
        articles_score = int(max_score * 0.2 * (len(matched_articles) / len(correct_articles)))
        feedback.append({"type": "partial", "message": f"اخترت {len(matched_articles)} من {len(correct_articles)} مادة قانونية صحيحة"})
    else:
        feedback.append({"type": "error", "message": f"المواد الصحيحة: {', '.join(correct_articles)}"})
    score += articles_score
    
    # مكافأة الوقت
    time_bonus = 0
    if submission.time_taken < scenario["time_limit"] * 30:  # أقل من نصف الوقت
        time_bonus = int(max_score * 0.1)
        feedback.append({"type": "bonus", "message": f"مكافأة سرعة: +{time_bonus} نقطة"})
    
    final_score = score + time_bonus
    passed = final_score >= (max_score * 0.5)
    
    # حفظ المحاولة في قاعدة البيانات
    attempt = {
        "id": str(uuid.uuid4()),
        "user_id": current_user.id,
        "user_name": current_user.full_name,
        "game_type": "prosecutor",
        "scenario_id": submission.scenario_id,
        "scenario_title": scenario["title"],
        "score": final_score,
        "max_score": max_score,
        "time_taken": submission.time_taken,
        "passed": passed,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.game_attempts.insert_one(attempt)
    
    # تحديث ملف اللاعب
    profile = await db.game_profiles.find_one({"user_id": current_user.id})
    if profile:
        update_data = {
            "total_xp": profile.get("total_xp", 0) + final_score,
            "games_played": profile.get("games_played", 0) + 1,
            "last_played": datetime.now(timezone.utc).isoformat()
        }
        if passed:
            update_data["games_won"] = profile.get("games_won", 0) + 1
        
        # حساب المستوى والرتبة
        new_xp = update_data["total_xp"]
        new_level = 1 + (new_xp // 500)
        ranks = ["مبتدئ", "متدرب", "مساعد نيابة", "وكيل نيابة", "رئيس نيابة", "مستشار قانوني", "خبير قانوني"]
        new_rank = ranks[min(new_level - 1, len(ranks) - 1)]
        update_data["level"] = new_level
        update_data["rank"] = new_rank
        
        await db.game_profiles.update_one({"user_id": current_user.id}, {"$set": update_data})
    else:
        new_profile = {
            "user_id": current_user.id,
            "user_name": current_user.full_name,
            "total_xp": final_score,
            "level": 1,
            "rank": "مبتدئ",
            "games_played": 1,
            "games_won": 1 if passed else 0,
            "badges": [],
            "streak_days": 1,
            "last_played": datetime.now(timezone.utc).isoformat()
        }
        await db.game_profiles.insert_one(new_profile)
    
    return {
        "score": final_score,
        "max_score": max_score,
        "passed": passed,
        "feedback": feedback,
        "correct_answers": {
            "culprits": [sus["name"] for sus in scenario["suspects"] if sus.get("is_culprit", False)],
            "accusation": scenario["correct_accusation"],
            "articles": scenario["correct_articles"]
        }
    }

@api_router.get("/virtual-court/leaderboard")
async def get_leaderboard(game_type: Optional[str] = None, limit: int = 10):
    """جلب لوحة المتصدرين"""
    query = {}
    if game_type:
        query["game_type"] = game_type
    
    # جلب أفضل النتائج
    pipeline = [
        {"$match": query},
        {"$group": {
            "_id": "$user_id",
            "user_name": {"$first": "$user_name"},
            "total_score": {"$sum": "$score"},
            "games_played": {"$sum": 1},
            "games_won": {"$sum": {"$cond": ["$passed", 1, 0]}},
            "best_score": {"$max": "$score"}
        }},
        {"$sort": {"total_score": -1}},
        {"$limit": limit}
    ]
    
    results = await db.game_attempts.aggregate(pipeline).to_list(length=limit)
    
    leaderboard = []
    for i, r in enumerate(results):
        leaderboard.append({
            "rank": i + 1,
            "user_id": r["_id"],
            "user_name": r["user_name"],
            "total_score": r["total_score"],
            "games_played": r["games_played"],
            "games_won": r["games_won"],
            "win_rate": round((r["games_won"] / r["games_played"]) * 100, 1) if r["games_played"] > 0 else 0,
            "best_score": r["best_score"]
        })
    
    return {"leaderboard": leaderboard}

@api_router.get("/virtual-court/my-profile")
async def get_my_game_profile(current_user: User = Depends(get_current_user)):
    """جلب ملف اللاعب"""
    profile = await db.game_profiles.find_one({"user_id": current_user.id}, {"_id": 0})
    
    if not profile:
        profile = {
            "user_id": current_user.id,
            "user_name": current_user.full_name,
            "total_xp": 0,
            "level": 1,
            "rank": "مبتدئ",
            "games_played": 0,
            "games_won": 0,
            "badges": [],
            "streak_days": 0,
            "last_played": None
        }
    
    # جلب المحاولات الأخيرة
    recent_attempts = await db.game_attempts.find(
        {"user_id": current_user.id},
        {"_id": 0}
    ).sort("created_at", -1).limit(5).to_list(length=5)
    
    profile["recent_attempts"] = recent_attempts
    
    # حساب الترتيب العام
    total_users = await db.game_profiles.count_documents({})
    higher_xp = await db.game_profiles.count_documents({"total_xp": {"$gt": profile.get("total_xp", 0)}})
    profile["global_rank"] = higher_xp + 1
    profile["total_players"] = total_users if total_users > 0 else 1
    
    return profile

@api_router.get("/virtual-court/my-attempts")
async def get_my_attempts(
    current_user: User = Depends(get_current_user),
    game_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 20
):
    """جلب محاولات اللاعب"""
    query = {"user_id": current_user.id}
    if game_type:
        query["game_type"] = game_type
    
    attempts = await db.game_attempts.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(length=limit)
    total = await db.game_attempts.count_documents(query)
    
    return {"attempts": attempts, "total": total}

# قائمة المواد القانونية للاختيار
LEGAL_ARTICLES = [
    {"id": "art_1", "text": "نظام مكافحة الاحتيال المالي - المادة 2", "category": "احتيال"},
    {"id": "art_2", "text": "نظام مكافحة الاحتيال المالي - المادة 4", "category": "احتيال"},
    {"id": "art_3", "text": "نظام العقوبات - المادة 321", "category": "سرقة"},
    {"id": "art_4", "text": "نظام مكافحة التزوير - المادة 5", "category": "تزوير"},
    {"id": "art_5", "text": "نظام مكافحة التزوير - المادة 8", "category": "تزوير"},
    {"id": "art_6", "text": "نظام مكافحة الجرائم المعلوماتية - المادة 3", "category": "إلكتروني"},
    {"id": "art_7", "text": "نظام مكافحة الجرائم المعلوماتية - المادة 6", "category": "إلكتروني"},
    {"id": "art_8", "text": "نظام المرور - المادة 75", "category": "مرور"},
    {"id": "art_9", "text": "القتل شبه العمد - النظام الجزائي", "category": "قتل"},
    {"id": "art_10", "text": "نظام العمل - المادة 80", "category": "عمل"},
    {"id": "art_11", "text": "نظام مكافحة غسل الأموال - المادة 2", "category": "غسيل أموال"},
    {"id": "art_12", "text": "نظام مكافحة غسل الأموال - المادة 16", "category": "غسيل أموال"},
    {"id": "art_13", "text": "نظام الإثبات - المادة 14", "category": "إثبات"},
    {"id": "art_14", "text": "نظام المرافعات الشرعية - المادة 22", "category": "مرافعات"}
]

@api_router.get("/virtual-court/legal-articles")
async def get_legal_articles(category: Optional[str] = None):
    """جلب المواد القانونية المتاحة للاختيار"""
    articles = LEGAL_ARTICLES.copy()
    if category:
        articles = [a for a in articles if a["category"] == category]
    return {"articles": articles}

# ==================== APIs لعبة المرافعة الذهبية ====================

@api_router.get("/virtual-court/golden-pleading/scenarios")
async def get_golden_pleading_scenarios(difficulty: Optional[str] = None):
    """جلب سيناريوهات لعبة المرافعة الذهبية"""
    scenarios = GOLDEN_PLEADING_SCENARIOS.copy()
    if difficulty:
        scenarios = [s for s in scenarios if s["difficulty"] == difficulty]
    
    # إرجاع بدون معلومات النقاط لكل دفاع
    safe_scenarios = []
    for s in scenarios:
        safe_s = {
            "id": s["id"],
            "title": s["title"],
            "case_type": s["case_type"],
            "difficulty": s["difficulty"],
            "situation": s["situation"],
            "your_role": s["your_role"],
            "opponent_arguments": s["opponent_arguments"],
            "available_defenses": [{"id": d["id"], "text": d["text"]} for d in s["available_defenses"]],
            "points": s["points"],
            "time_limit": s["time_limit"]
        }
        safe_scenarios.append(safe_s)
    
    return {"scenarios": safe_scenarios}

class GoldenPleadingSubmission(BaseModel):
    scenario_id: str
    selected_defenses: List[str]
    time_taken: int

@api_router.post("/virtual-court/golden-pleading/submit")
async def submit_golden_pleading(submission: GoldenPleadingSubmission, current_user: User = Depends(get_current_user)):
    """تقديم إجابة لعبة المرافعة الذهبية"""
    scenario = next((s for s in GOLDEN_PLEADING_SCENARIOS if s["id"] == submission.scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="السيناريو غير موجود")
    
    max_score = scenario["points"]
    total_defense_score = 0
    feedback = []
    strong_defenses_selected = 0
    weak_defenses_selected = 0
    
    for defense_id in submission.selected_defenses:
        defense = next((d for d in scenario["available_defenses"] if d["id"] == defense_id), None)
        if defense:
            total_defense_score += defense["score"]
            if defense["is_strong"]:
                strong_defenses_selected += 1
            else:
                weak_defenses_selected += 1
    
    # حساب النسبة المئوية من الحد الأقصى الممكن
    max_possible = sum(d["score"] for d in scenario["available_defenses"] if d["is_strong"])
    percentage = (total_defense_score / max_possible * 100) if max_possible > 0 else 0
    
    # تقييم الأداء
    if percentage >= 80:
        feedback.append({"type": "success", "message": "مرافعة ممتازة! اخترت أقوى الحجج"})
    elif percentage >= 60:
        feedback.append({"type": "success", "message": "مرافعة جيدة جداً"})
    elif percentage >= 40:
        feedback.append({"type": "partial", "message": "مرافعة مقبولة، يمكنك تحسينها"})
    else:
        feedback.append({"type": "error", "message": "مرافعة ضعيفة، حاول اختيار حجج أقوى"})
    
    if strong_defenses_selected > 0:
        feedback.append({"type": "success", "message": f"اخترت {strong_defenses_selected} حجة قوية"})
    
    if weak_defenses_selected > 0:
        feedback.append({"type": "partial", "message": f"اخترت {weak_defenses_selected} حجة ضعيفة"})
    
    # حساب النقاط النهائية
    final_score = int(max_score * (percentage / 100))
    
    # مكافأة السرعة
    if submission.time_taken < scenario["time_limit"] * 30:
        time_bonus = int(max_score * 0.1)
        final_score += time_bonus
        feedback.append({"type": "bonus", "message": f"مكافأة سرعة: +{time_bonus} نقطة"})
    
    passed = percentage >= scenario["winning_threshold"]
    
    # حفظ المحاولة
    attempt = {
        "id": str(uuid.uuid4()),
        "user_id": current_user.id,
        "user_name": current_user.full_name,
        "game_type": "golden_pleading",
        "scenario_id": submission.scenario_id,
        "scenario_title": scenario["title"],
        "score": final_score,
        "max_score": max_score,
        "time_taken": submission.time_taken,
        "passed": passed,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.game_attempts.insert_one(attempt)
    
    # تحديث ملف اللاعب
    await update_player_profile(current_user.id, current_user.full_name, final_score, passed)
    
    # الحجج القوية الصحيحة
    strong_defenses = [d for d in scenario["available_defenses"] if d["is_strong"]]
    
    return {
        "score": final_score,
        "max_score": max_score,
        "passed": passed,
        "percentage": round(percentage, 1),
        "feedback": feedback,
        "correct_answers": {
            "strong_defenses": [d["text"] for d in strong_defenses]
        }
    }

# ==================== APIs لعبة الخطأ الإجرائي ====================

@api_router.get("/virtual-court/procedural-error/scenarios")
async def get_procedural_error_scenarios(difficulty: Optional[str] = None):
    """جلب سيناريوهات لعبة الخطأ الإجرائي"""
    scenarios = PROCEDURAL_ERROR_SCENARIOS.copy()
    if difficulty:
        scenarios = [s for s in scenarios if s["difficulty"] == difficulty]
    
    # إرجاع بدون معلومات الإجابات الصحيحة
    safe_scenarios = []
    for s in scenarios:
        safe_s = {
            "id": s["id"],
            "title": s["title"],
            "difficulty": s["difficulty"],
            "case_description": s["case_description"],
            "court_proceedings": s["court_proceedings"],
            "errors": [{"id": e["id"], "description": e["description"]} for e in s["errors"]],
            "points": s["points"],
            "time_limit": s["time_limit"]
        }
        safe_scenarios.append(safe_s)
    
    return {"scenarios": safe_scenarios}

class ProceduralErrorSubmission(BaseModel):
    scenario_id: str
    selected_errors: List[str]
    time_taken: int

@api_router.post("/virtual-court/procedural-error/submit")
async def submit_procedural_error(submission: ProceduralErrorSubmission, current_user: User = Depends(get_current_user)):
    """تقديم إجابة لعبة الخطأ الإجرائي"""
    scenario = next((s for s in PROCEDURAL_ERROR_SCENARIOS if s["id"] == submission.scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="السيناريو غير موجود")
    
    max_score = scenario["points"]
    feedback = []
    
    # الأخطاء الحقيقية
    actual_errors = [e["id"] for e in scenario["errors"] if e["is_error"]]
    non_errors = [e["id"] for e in scenario["errors"] if not e["is_error"]]
    
    # حساب الإجابات الصحيحة
    correct_identifications = len([e for e in submission.selected_errors if e in actual_errors])
    false_positives = len([e for e in submission.selected_errors if e in non_errors])
    missed_errors = len([e for e in actual_errors if e not in submission.selected_errors])
    
    # حساب النقاط
    points_per_correct = max_score / len(actual_errors) if actual_errors else 0
    penalty_per_false = points_per_correct / 2
    
    score = (correct_identifications * points_per_correct) - (false_positives * penalty_per_false)
    score = max(0, int(score))
    
    # التقييم
    if correct_identifications == len(actual_errors) and false_positives == 0:
        feedback.append({"type": "success", "message": "ممتاز! حددت جميع الأخطاء بدقة"})
    elif correct_identifications > 0:
        feedback.append({"type": "partial", "message": f"حددت {correct_identifications} من {len(actual_errors)} أخطاء"})
    else:
        feedback.append({"type": "error", "message": "لم تحدد أي خطأ صحيح"})
    
    if false_positives > 0:
        feedback.append({"type": "error", "message": f"اخترت {false_positives} إجراء صحيح على أنه خطأ"})
    
    if missed_errors > 0:
        feedback.append({"type": "partial", "message": f"فاتك {missed_errors} أخطاء"})
    
    # مكافأة السرعة
    if submission.time_taken < scenario["time_limit"] * 30 and score > 0:
        time_bonus = int(max_score * 0.1)
        score += time_bonus
        feedback.append({"type": "bonus", "message": f"مكافأة سرعة: +{time_bonus} نقطة"})
    
    passed = score >= (max_score * 0.6)
    
    # حفظ المحاولة
    attempt = {
        "id": str(uuid.uuid4()),
        "user_id": current_user.id,
        "user_name": current_user.full_name,
        "game_type": "procedural_error",
        "scenario_id": submission.scenario_id,
        "scenario_title": scenario["title"],
        "score": score,
        "max_score": max_score,
        "time_taken": submission.time_taken,
        "passed": passed,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.game_attempts.insert_one(attempt)
    
    # تحديث ملف اللاعب
    await update_player_profile(current_user.id, current_user.full_name, score, passed)
    
    # الأخطاء الصحيحة مع التفسير
    correct_errors = [{"description": e["description"], "explanation": e["explanation"]} 
                      for e in scenario["errors"] if e["is_error"]]
    
    return {
        "score": score,
        "max_score": max_score,
        "passed": passed,
        "feedback": feedback,
        "correct_answers": {
            "errors": correct_errors,
            "total_errors": len(actual_errors)
        }
    }

# دالة مساعدة لتحديث ملف اللاعب
async def update_player_profile(user_id: str, user_name: str, score: int, passed: bool):
    profile = await db.game_profiles.find_one({"user_id": user_id})
    if profile:
        update_data = {
            "total_xp": profile.get("total_xp", 0) + score,
            "games_played": profile.get("games_played", 0) + 1,
            "last_played": datetime.now(timezone.utc).isoformat()
        }
        if passed:
            update_data["games_won"] = profile.get("games_won", 0) + 1
        
        new_xp = update_data["total_xp"]
        new_level = 1 + (new_xp // 500)
        ranks = ["مبتدئ", "متدرب", "مساعد نيابة", "وكيل نيابة", "رئيس نيابة", "مستشار قانوني", "خبير قانوني"]
        new_rank = ranks[min(new_level - 1, len(ranks) - 1)]
        update_data["level"] = new_level
        update_data["rank"] = new_rank
        
        await db.game_profiles.update_one({"user_id": user_id}, {"$set": update_data})
    else:
        new_profile = {
            "user_id": user_id,
            "user_name": user_name,
            "total_xp": score,
            "level": 1,
            "rank": "مبتدئ",
            "games_played": 1,
            "games_won": 1 if passed else 0,
            "badges": [],
            "streak_days": 1,
            "last_played": datetime.now(timezone.utc).isoformat()
        }
        await db.game_profiles.insert_one(new_profile)

# ==================== وظائف البريد الخارجي (IMAP/SMTP) ====================

def decode_email_header(header):
    """فك ترميز header البريد"""
    if not header:
        return ""
    decoded_parts = []
    for part, charset in decode_header(header):
        if isinstance(part, bytes):
            try:
                decoded_parts.append(part.decode(charset or 'utf-8', errors='replace'))
            except:
                decoded_parts.append(part.decode('utf-8', errors='replace'))
        else:
            decoded_parts.append(part)
    return ''.join(decoded_parts)

def get_email_body(msg):
    """استخراج نص البريد"""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    body = payload.decode(charset, errors='replace')
                    break
                except:
                    pass
            elif content_type == "text/html" and "attachment" not in content_disposition and not body:
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    body = payload.decode(charset, errors='replace')
                except:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            body = payload.decode(charset, errors='replace')
        except:
            body = str(msg.get_payload())
    return body

def get_email_attachments(msg):
    """استخراج المرفقات"""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    filename = decode_email_header(filename)
                    payload = part.get_payload(decode=True)
                    if payload:
                        attachments.append({
                            "name": filename,
                            "type": part.get_content_type(),
                            "size": len(payload),
                            "data": base64.b64encode(payload).decode('utf-8')
                        })
    return attachments

def sync_fetch_external_emails():
    """جلب الرسائل من IMAP بشكل متزامن"""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return []
    
    emails_data = []
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        mail.select('INBOX')
        
        # جلب آخر 50 رسالة
        status, messages = mail.search(None, 'ALL')
        if status == 'OK':
            email_ids = messages[0].split()
            # آخر 50 رسالة
            recent_ids = email_ids[-50:] if len(email_ids) > 50 else email_ids
            
            for email_id in reversed(recent_ids):
                try:
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    if status == 'OK':
                        raw_email = msg_data[0][1]
                        msg = email_lib.message_from_bytes(raw_email)
                        
                        # استخراج البيانات
                        subject = decode_email_header(msg.get('Subject', ''))
                        from_header = decode_email_header(msg.get('From', ''))
                        to_header = decode_email_header(msg.get('To', ''))
                        date_header = msg.get('Date', '')
                        message_id = msg.get('Message-ID', str(uuid.uuid4()))
                        
                        # تحويل التاريخ
                        try:
                            from email.utils import parsedate_to_datetime
                            sent_date = parsedate_to_datetime(date_header)
                        except:
                            sent_date = datetime.now(timezone.utc)
                        
                        # استخراج اسم وبريد المرسل
                        sender_name = from_header
                        sender_email = from_header
                        if '<' in from_header:
                            parts = from_header.split('<')
                            sender_name = parts[0].strip().strip('"')
                            sender_email = parts[1].strip('>')
                        
                        body = get_email_body(msg)
                        attachments = get_email_attachments(msg)
                        
                        emails_data.append({
                            "message_id": message_id,
                            "subject": subject or "(بدون موضوع)",
                            "sender_name": sender_name,
                            "sender_email": sender_email,
                            "to": to_header,
                            "body": body,
                            "attachments": attachments,
                            "sent_at": sent_date.isoformat(),
                            "imap_id": email_id.decode() if isinstance(email_id, bytes) else str(email_id)
                        })
                except Exception as e:
                    logging.error(f"Error processing email {email_id}: {e}")
                    continue
        
        mail.logout()
    except Exception as e:
        logging.error(f"IMAP connection error: {e}")
    
    return emails_data

def sync_send_external_email(to_email: str, subject: str, body: str, attachments: list = None):
    """إرسال بريد خارجي عبر SMTP بشكل متزامن"""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        raise Exception("بيانات SMTP غير مكتملة")
    
    try:
        msg = MIMEMultipart('alternative')
        # تنسيق From header بشكل صحيح لتجنب رفض Gmail
        from email.header import Header
        from email.utils import formataddr
        msg['From'] = formataddr((str(Header('HK Law Firm', 'utf-8')), EMAIL_ADDRESS))
        msg['To'] = to_email
        msg['Subject'] = subject
        msg['Reply-To'] = EMAIL_ADDRESS
        msg['Message-ID'] = f"<{uuid.uuid4()}@hklaw.sa>"
        msg['Date'] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        msg['X-Mailer'] = "Legal Suite - HK Law Firm"
        msg['MIME-Version'] = "1.0"
        
        # إضافة النص العادي
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        # إضافة نسخة HTML للرسالة (تحسين التوصيل)
        html_body = f"""
        <html dir="rtl">
        <head><meta charset="utf-8"></head>
        <body style="font-family: Arial, sans-serif; direction: rtl;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="white-space: pre-wrap;">{body}</div>
                <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
                <p style="color: #666; font-size: 12px;">
                    مكتب المحامي هشام يوسف الخياط<br>
                    البريد: info@hklaw.sa
                </p>
            </div>
        </body>
        </html>
        """
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        # إضافة المرفقات
        if attachments:
            for att in attachments:
                if att.get('data'):
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(base64.b64decode(att['data']))
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', f'attachment; filename="{att.get("name", "attachment")}"')
                    msg.attach(part)
        
        # الاتصال وإرسال
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        server.quit()
        
        return True
    except Exception as e:
        logging.error(f"SMTP send error: {e}")
        raise e

class ExternalEmailInput(BaseModel):
    to_email: str
    subject: str
    body: str
    attachments: Optional[List[dict]] = []

@api_router.get("/emails/external/sync")
async def sync_external_emails(current_user: User = Depends(get_current_user)):
    """مزامنة الرسائل من البريد الخارجي"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    # جلب الرسائل من IMAP في thread منفصل
    loop = asyncio.get_event_loop()
    external_emails = await loop.run_in_executor(None, sync_fetch_external_emails)
    
    synced_count = 0
    for ext_email in external_emails:
        # تحقق من عدم وجود الرسالة مسبقاً
        existing = await db.emails.find_one({"external_message_id": ext_email["message_id"]})
        if existing:
            continue
        
        # إنشاء البريد في النظام
        email_id = str(uuid.uuid4())
        email_doc = {
            "id": email_id,
            "sender_id": None,
            "sender_name": ext_email["sender_name"],
            "sender_email": ext_email["sender_email"],
            "recipients": [{"name": "البريد الرئيسي", "email": EMAIL_ADDRESS, "type": "to"}],
            "subject": ext_email["subject"],
            "body": ext_email["body"],
            "body_html": None,
            "attachments": ext_email["attachments"],
            "priority": "normal",
            "related_task_id": None,
            "is_external": True,
            "external_email": ext_email["sender_email"],
            "external_message_id": ext_email["message_id"],
            "thread_id": str(uuid.uuid4()),
            "reply_to_id": None,
            "is_reply": False,
            "is_forwarded": False,
            "status": "received",
            "sent_at": ext_email["sent_at"],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        await db.emails.insert_one(email_doc)
        
        # إنشاء سجل للمستلمين (جميع المدراء والمحامين)
        staff = await db.users.find({"role": {"$in": ["admin", "lawyer"]}}, {"_id": 0, "id": 1, "email": 1}).to_list(100)
        for user in staff:
            recipient_record = {
                "id": str(uuid.uuid4()),
                "email_id": email_id,
                "user_id": user["id"],
                "user_email": user["email"],
                "recipient_type": "to",
                "is_read": False,
                "is_starred": False,
                "is_deleted": False,
                "folder": "inbox"
            }
            await db.email_recipients.insert_one(recipient_record)
        
        synced_count += 1
    
    return {"message": f"تم مزامنة {synced_count} رسالة جديدة", "synced_count": synced_count}

@api_router.post("/emails/external/send")
async def send_external_email(email_input: ExternalEmailInput, current_user: User = Depends(get_current_user)):
    """إرسال بريد خارجي"""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    try:
        # إرسال البريد في thread منفصل
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, 
            sync_send_external_email, 
            email_input.to_email, 
            email_input.subject, 
            email_input.body,
            email_input.attachments
        )
        
        # حفظ في قاعدة البيانات
        email_id = str(uuid.uuid4())
        email_doc = {
            "id": email_id,
            "sender_id": current_user.id,
            "sender_name": current_user.full_name,
            "sender_email": EMAIL_ADDRESS,
            "recipients": [{"name": email_input.to_email, "email": email_input.to_email, "type": "to"}],
            "subject": email_input.subject,
            "body": email_input.body,
            "body_html": None,
            "attachments": email_input.attachments or [],
            "priority": "normal",
            "related_task_id": None,
            "is_external": True,
            "external_email": email_input.to_email,
            "thread_id": str(uuid.uuid4()),
            "reply_to_id": None,
            "is_reply": False,
            "is_forwarded": False,
            "status": "sent",
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        await db.emails.insert_one(email_doc)
        
        # سجل للمرسل
        sender_record = {
            "id": str(uuid.uuid4()),
            "email_id": email_id,
            "user_id": current_user.id,
            "user_email": current_user.email,
            "recipient_type": "sender",
            "is_read": True,
            "is_starred": False,
            "is_deleted": False,
            "folder": "sent"
        }
        await db.email_recipients.insert_one(sender_record)
        
        return {"message": "تم إرسال البريد بنجاح", "email_id": email_id}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"فشل إرسال البريد: {str(e)}")

@api_router.get("/emails/external/test")
async def test_email_connection(current_user: User = Depends(get_current_user)):
    """اختبار الاتصال بخادم البريد"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="للمدير فقط")
    
    results = {"imap": False, "smtp": False, "errors": []}
    
    # اختبار IMAP
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        mail.logout()
        results["imap"] = True
    except Exception as e:
        results["errors"].append(f"IMAP: {str(e)}")
    
    # اختبار SMTP
    try:
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.quit()
        results["smtp"] = True
    except Exception as e:
        results["errors"].append(f"SMTP: {str(e)}")
    
    return results

app.include_router(api_router)

# Health Check Endpoint
@app.get("/api/health")
async def health_check():
    """نقطة فحص صحة التطبيق"""
    try:
        # فحص اتصال قاعدة البيانات
        await db.command("ping")
        return {
            "status": "healthy",
            "database": "connected",
            "version": "1.0.0",
            "app": "Al-Khayat Law Firm Management System"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e)
        }

@app.on_event("startup")
async def create_admin_user():
    admin_exists = await db.users.find_one({"role": UserRole.ADMIN}, {"_id": 0})
    if not admin_exists:
        hashed_password = get_password_hash("الخياط")
        now_str = datetime.now(timezone.utc).isoformat()
        admin_user = UserInDB(
            id=str(uuid.uuid4()),
            email="admin@alkhayat.com",
            full_name="هشام",
            role=UserRole.ADMIN,
            created_at=now_str,
            hashed_password=hashed_password
        )
        doc = admin_user.model_dump()
        await db.users.insert_one(doc)
        logger.info("Admin user created successfully")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
