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
MYSQL_DB = os.environ.get("MYSQL_DATABASE", "legal_suite")

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
    is_active: bool = True
    first_login: bool = True
    created_at: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class LoginRequest(BaseModel):
    email: str
    password: str

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class ClientRequestCreate(BaseModel):
    request_type: str
    client_name: str
    client_phone: Optional[str] = None
    client_email: Optional[str] = None
    national_id: Optional[str] = None
    subject: str
    description: Optional[str] = None
    priority: str = "medium"
    referral_source: Optional[str] = None

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    task_type: Optional[str] = None
    priority: str = "medium"
    assigned_to: Optional[str] = None
    case_id: Optional[str] = None
    request_id: Optional[str] = None
    due_date: Optional[str] = None

class EmailCreate(BaseModel):
    recipients: List[dict]
    subject: str
    body: str
    save_as_draft: bool = False

class AttendanceRecord(BaseModel):
    action: str  # clock_in or clock_out
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None

# =====================================================
# دوال المساعدة
# =====================================================
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="بيانات الاعتماد غير صالحة",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await execute_query(
        "SELECT * FROM users WHERE id = %s AND is_active = 1",
        (user_id,),
        fetch_one=True
    )
    if user is None:
        raise credentials_exception
    
    # Convert to dict and fix boolean fields
    user_dict = dict(user)
    user_dict['is_active'] = bool(user_dict.get('is_active', 1))
    user_dict['first_login'] = bool(user_dict.get('first_login', 1))
    return user_dict

def generate_id():
    return str(uuid.uuid4())

def generate_number(prefix: str, num: int):
    return f"{prefix}-{datetime.now().year}-{str(num).zfill(5)}"

# =====================================================
# APIs المصادقة
# =====================================================
@api_router.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await execute_query(
        "SELECT * FROM users WHERE email = %s",
        (form_data.username,),
        fetch_one=True
    )
    
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="بيانات الدخول غير صحيحة")
    
    if not user["is_active"]:
        raise HTTPException(status_code=401, detail="الحساب معطل")
    
    access_token = create_access_token(data={"sub": user["id"]})
    
    user_data = {
        "id": user["id"],
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"],
        "phone": user["phone"],
        "first_login": user["first_login"]
    }
    
    return {"access_token": access_token, "token_type": "bearer", "user": user_data}

@api_router.post("/auth/register")
async def register(user: UserCreate):
    # التحقق من وجود الإيميل
    existing = await execute_query(
        "SELECT id FROM users WHERE email = %s",
        (user.email,),
        fetch_one=True
    )
    if existing:
        raise HTTPException(status_code=400, detail="البريد الإلكتروني مسجل مسبقاً")
    
    # التحقق من رقم الهوية للعملاء
    if user.role == "client" and user.national_id:
        existing_id = await execute_query(
            "SELECT id FROM users WHERE national_id = %s",
            (user.national_id,),
            fetch_one=True
        )
        if existing_id:
            raise HTTPException(status_code=400, detail="رقم الهوية مسجل مسبقاً")
    
    user_id = generate_id()
    hashed_password = get_password_hash(user.password)
    
    await execute_query(
        """INSERT INTO users (id, email, hashed_password, full_name, phone, role, national_id, is_active, first_login, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, TRUE, NOW())""",
        (user_id, user.email, hashed_password, user.full_name, user.phone, user.role, user.national_id)
    )
    
    return {"message": "تم إنشاء الحساب بنجاح", "user_id": user_id}

@api_router.post("/auth/change-password")
async def change_password(data: PasswordChange, current_user: dict = Depends(get_current_user)):
    user = await execute_query(
        "SELECT hashed_password FROM users WHERE id = %s",
        (current_user["id"],),
        fetch_one=True
    )
    
    if not verify_password(data.current_password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="كلمة المرور الحالية غير صحيحة")
    
    new_hashed = get_password_hash(data.new_password)
    await execute_query(
        "UPDATE users SET hashed_password = %s, first_login = 0 WHERE id = %s",
        (new_hashed, current_user["id"])
    )
    
    return {"message": "تم تغيير كلمة المرور بنجاح"}

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

# =====================================================
# APIs الموظفين
# =====================================================
@api_router.get("/employees")
async def get_employees(
    include_admins: bool = False,
    current_user: dict = Depends(get_current_user)
):
    if include_admins:
        query = "SELECT * FROM users WHERE role != 'client' ORDER BY created_at DESC"
    else:
        query = "SELECT * FROM users WHERE role NOT IN ('client', 'admin') ORDER BY created_at DESC"
    
    employees = await execute_query(query, fetch_all=True)
    
    result = []
    for emp in employees:
        result.append({
            "id": emp["id"],
            "email": emp["email"],
            "full_name": emp["full_name"],
            "phone": emp["phone"],
            "role": emp["role"],
            "is_active": emp["is_active"]
        })
    
    return result

@api_router.post("/employees")
async def create_employee(user: UserCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    existing = await execute_query(
        "SELECT id FROM users WHERE email = %s",
        (user.email,),
        fetch_one=True
    )
    if existing:
        raise HTTPException(status_code=400, detail="البريد الإلكتروني مسجل مسبقاً")
    
    user_id = generate_id()
    hashed_password = get_password_hash(user.password)
    
    await execute_query(
        """INSERT INTO users (id, email, hashed_password, full_name, phone, role, is_active, first_login, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, TRUE, TRUE, NOW())""",
        (user_id, user.email, hashed_password, user.full_name, user.phone, user.role)
    )
    
    return {"message": "تم إنشاء الموظف بنجاح", "user_id": user_id}

@api_router.delete("/admin/delete-user/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    await execute_query("DELETE FROM users WHERE id = %s", (user_id,))
    return {"message": "تم حذف المستخدم بنجاح"}

# =====================================================
# APIs طلبات العملاء
# =====================================================
@api_router.get("/client-requests")
async def get_client_requests(
    request_type: Optional[str] = None,
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    query = "SELECT * FROM client_requests WHERE 1=1"
    params = []
    
    if request_type:
        query += " AND request_type = %s"
        params.append(request_type)
    
    if status:
        query += " AND status = %s"
        params.append(status)
    
    if current_user["role"] == "client":
        query += " AND client_id = %s"
        params.append(current_user["id"])
    
    query += " ORDER BY created_at DESC"
    
    requests = await execute_query(query, tuple(params) if params else None, fetch_all=True)
    return requests or []

@api_router.post("/client-requests")
async def create_client_request(request: ClientRequestCreate, current_user: dict = Depends(get_current_user)):
    # الحصول على رقم الطلب التالي
    last_request = await execute_query(
        "SELECT request_number FROM client_requests ORDER BY created_at DESC LIMIT 1",
        fetch_one=True
    )
    
    if last_request and last_request["request_number"]:
        try:
            last_num = int(last_request["request_number"].split("-")[-1])
        except:
            last_num = 0
    else:
        last_num = 0
    
    request_id = generate_id()
    request_number = generate_number("REQ", last_num + 1)
    
    await execute_query(
        """INSERT INTO client_requests 
           (id, request_number, request_type, client_id, client_name, client_phone, client_email, 
            national_id, subject, description, status, priority, referral_source, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'new', %s, %s, NOW())""",
        (request_id, request_number, request.request_type, current_user["id"], request.client_name,
         request.client_phone, request.client_email, request.national_id, request.subject,
         request.description, request.priority, request.referral_source)
    )
    
    return {"message": "تم إنشاء الطلب بنجاح", "request_id": request_id, "request_number": request_number}

@api_router.put("/client-requests/{request_id}/status")
async def update_request_status(
    request_id: str,
    status: str = Query(...),
    current_user: dict = Depends(get_current_user)
):
    await execute_query(
        "UPDATE client_requests SET status = %s, updated_at = NOW() WHERE id = %s",
        (status, request_id)
    )
    return {"message": "تم تحديث الحالة بنجاح"}

@api_router.delete("/client-requests/{request_id}")
async def delete_client_request(request_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    await execute_query("DELETE FROM client_requests WHERE id = %s", (request_id,))
    return {"message": "تم حذف الطلب بنجاح"}

# =====================================================
# APIs المهام
# =====================================================
@api_router.get("/tasks")
async def get_tasks(
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    query = "SELECT * FROM tasks WHERE 1=1"
    params = []
    
    if status:
        query += " AND status = %s"
        params.append(status)
    
    if assigned_to:
        query += " AND assigned_to = %s"
        params.append(assigned_to)
    elif current_user["role"] not in ["admin"]:
        query += " AND assigned_to = %s"
        params.append(current_user["id"])
    
    query += " ORDER BY created_at DESC"
    
    tasks = await execute_query(query, tuple(params) if params else None, fetch_all=True)
    return tasks or []

@api_router.get("/my-tasks")
async def get_my_tasks(current_user: dict = Depends(get_current_user)):
    tasks = await execute_query(
        "SELECT * FROM tasks WHERE assigned_to = %s ORDER BY created_at DESC",
        (current_user["id"],),
        fetch_all=True
    )
    return tasks or []

@api_router.post("/tasks")
async def create_task(task: TaskCreate, current_user: dict = Depends(get_current_user)):
    # الحصول على رقم المهمة التالي
    last_task = await execute_query(
        "SELECT task_number FROM tasks ORDER BY created_at DESC LIMIT 1",
        fetch_one=True
    )
    
    if last_task and last_task["task_number"]:
        try:
            last_num = int(last_task["task_number"].split("-")[-1])
        except:
            last_num = 0
    else:
        last_num = 0
    
    task_id = generate_id()
    task_number = generate_number("TASK", last_num + 1)
    
    await execute_query(
        """INSERT INTO tasks 
           (id, task_number, title, description, task_type, status, priority, 
            assigned_to, assigned_by, case_id, request_id, due_date, created_at)
           VALUES (%s, %s, %s, %s, %s, 'pending', %s, %s, %s, %s, %s, %s, NOW())""",
        (task_id, task_number, task.title, task.description, task.task_type,
         task.priority, task.assigned_to, current_user["id"], task.case_id, task.request_id, task.due_date)
    )
    
    # إنشاء إشعار للموظف المكلف
    if task.assigned_to:
        notif_id = generate_id()
        await execute_query(
            """INSERT INTO notifications (id, user_id, title, message, notification_type, link, created_at)
               VALUES (%s, %s, %s, %s, 'task', '/my-tasks', NOW())""",
            (notif_id, task.assigned_to, "مهمة جديدة", f"تم تكليفك بمهمة: {task.title}")
        )
    
    return {"message": "تم إنشاء المهمة بنجاح", "task_id": task_id, "task_number": task_number}

@api_router.put("/tasks/{task_id}/status")
async def update_task_status(
    task_id: str,
    status: str = Query(...),
    current_user: dict = Depends(get_current_user)
):
    completed_at = "NOW()" if status == "completed" else "NULL"
    
    await execute_query(
        f"UPDATE tasks SET status = %s, completed_at = {completed_at}, updated_at = NOW() WHERE id = %s",
        (status, task_id)
    )
    return {"message": "تم تحديث حالة المهمة بنجاح"}

# =====================================================
# APIs الحضور والانصراف
# =====================================================
@api_router.get("/attendance/today")
async def get_today_attendance(current_user: dict = Depends(get_current_user)):
    today = datetime.now().strftime("%Y-%m-%d")
    
    record = await execute_query(
        "SELECT * FROM attendance WHERE user_id = %s AND date = %s",
        (current_user["id"], today),
        fetch_one=True
    )
    
    return record

@api_router.post("/attendance/record")
async def record_attendance(record: AttendanceRecord, current_user: dict = Depends(get_current_user)):
    today = datetime.now().strftime("%Y-%m-%d")
    
    existing = await execute_query(
        "SELECT * FROM attendance WHERE user_id = %s AND date = %s",
        (current_user["id"], today),
        fetch_one=True
    )
    
    if record.action == "clock_in":
        if existing and existing["clock_in_time"]:
            raise HTTPException(status_code=400, detail="تم تسجيل الحضور مسبقاً")
        
        if existing:
            await execute_query(
                """UPDATE attendance SET clock_in_time = NOW(), 
                   clock_in_location_lat = %s, clock_in_location_lng = %s, clock_in_address = %s
                   WHERE id = %s""",
                (record.latitude, record.longitude, record.address, existing["id"])
            )
        else:
            att_id = generate_id()
            await execute_query(
                """INSERT INTO attendance 
                   (id, user_id, user_name, date, clock_in_time, clock_in_location_lat, 
                    clock_in_location_lng, clock_in_address, status, created_at)
                   VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s, 'present', NOW())""",
                (att_id, current_user["id"], current_user["full_name"], today,
                 record.latitude, record.longitude, record.address)
            )
        
        return {"message": "تم تسجيل الحضور بنجاح"}
    
    elif record.action == "clock_out":
        if not existing or not existing["clock_in_time"]:
            raise HTTPException(status_code=400, detail="لم يتم تسجيل الحضور بعد")
        
        if existing["clock_out_time"]:
            raise HTTPException(status_code=400, detail="تم تسجيل الانصراف مسبقاً")
        
        await execute_query(
            """UPDATE attendance SET clock_out_time = NOW(),
               clock_out_location_lat = %s, clock_out_location_lng = %s, clock_out_address = %s
               WHERE id = %s""",
            (record.latitude, record.longitude, record.address, existing["id"])
        )
        
        return {"message": "تم تسجيل الانصراف بنجاح"}

@api_router.get("/attendance/history")
async def get_attendance_history(
    user_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    query = "SELECT * FROM attendance WHERE 1=1"
    params = []
    
    if current_user["role"] != "admin":
        query += " AND user_id = %s"
        params.append(current_user["id"])
    elif user_id:
        query += " AND user_id = %s"
        params.append(user_id)
    
    if start_date:
        query += " AND date >= %s"
        params.append(start_date)
    
    if end_date:
        query += " AND date <= %s"
        params.append(end_date)
    
    query += " ORDER BY date DESC LIMIT 30"
    
    records = await execute_query(query, tuple(params) if params else None, fetch_all=True)
    return records or []

# =====================================================
# APIs الإشعارات
# =====================================================
@api_router.get("/notifications")
async def get_notifications(current_user: dict = Depends(get_current_user)):
    notifications = await execute_query(
        "SELECT * FROM notifications WHERE user_id = %s ORDER BY created_at DESC LIMIT 50",
        (current_user["id"],),
        fetch_all=True
    )
    return notifications or []

@api_router.get("/notifications/unread-count")
async def get_unread_count(current_user: dict = Depends(get_current_user)):
    result = await execute_query(
        "SELECT COUNT(*) as count FROM notifications WHERE user_id = %s AND is_read = FALSE",
        (current_user["id"],),
        fetch_one=True
    )
    return {"count": result["count"] if result else 0}

@api_router.put("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, current_user: dict = Depends(get_current_user)):
    await execute_query(
        "UPDATE notifications SET is_read = TRUE WHERE id = %s AND user_id = %s",
        (notification_id, current_user["id"])
    )
    return {"message": "تم تحديث الإشعار"}

@api_router.put("/notifications/mark-all-read")
async def mark_all_read(current_user: dict = Depends(get_current_user)):
    await execute_query(
        "UPDATE notifications SET is_read = TRUE WHERE user_id = %s",
        (current_user["id"],)
    )
    return {"message": "تم تحديث جميع الإشعارات"}

# =====================================================
# APIs البريد الإلكتروني الداخلي
@api_router.get("/emails/stats/unread")
async def get_email_stats(current_user: dict = Depends(get_current_user)):
    unread = await execute_query(
        """SELECT COUNT(*) as count FROM email_recipients er
           JOIN emails e ON e.id = er.email_id
           WHERE er.recipient_id = %s AND er.is_read = FALSE AND er.is_deleted = FALSE AND e.is_sent = TRUE""",
        (current_user["id"],),
        fetch_one=True
    )
    drafts = await execute_query(
        "SELECT COUNT(*) as count FROM emails WHERE sender_id = %s AND is_sent = FALSE",
        (current_user["id"],),
        fetch_one=True
    )
    return {"unread": unread["count"] if unread else 0, "drafts": drafts["count"] if drafts else 0}

# =====================================================
@api_router.get("/emails/inbox")
async def get_inbox(current_user: dict = Depends(get_current_user)):
    emails = await execute_query(
        """SELECT e.*, er.is_read, er.id as recipient_record_id
           FROM emails e
           JOIN email_recipients er ON e.id = er.email_id
           WHERE er.recipient_id = %s AND er.is_deleted = FALSE AND e.is_sent = TRUE
           ORDER BY e.sent_at DESC""",
        (current_user["id"],),
        fetch_all=True
    )
    return emails or []

@api_router.get("/emails/sent")
async def get_sent(current_user: dict = Depends(get_current_user)):
    emails = await execute_query(
        "SELECT * FROM emails WHERE sender_id = %s AND is_sent = TRUE ORDER BY sent_at DESC",
        (current_user["id"],),
        fetch_all=True
    )
    return emails or []

@api_router.post("/emails/send")
async def send_email(email: EmailCreate, current_user: dict = Depends(get_current_user)):
    email_id = generate_id()
    
    await execute_query(
        """INSERT INTO emails (id, sender_id, sender_name, sender_email, subject, body, 
           is_draft, is_sent, sent_at, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())""",
        (email_id, current_user["id"], current_user["full_name"], current_user["email"],
         email.subject, email.body, email.save_as_draft, not email.save_as_draft)
    )
    
    # إضافة المستلمين
    for recipient in email.recipients:
        rec_id = generate_id()
        await execute_query(
            """INSERT INTO email_recipients (id, email_id, recipient_id, recipient_name, recipient_email, recipient_type)
               VALUES (%s, %s, %s, %s, %s, 'to')""",
            (rec_id, email_id, recipient.get("id"), recipient.get("name"), recipient.get("email"))
        )
        
        # إشعار المستلم
        if not email.save_as_draft and recipient.get("id"):
            notif_id = generate_id()
            await execute_query(
                """INSERT INTO notifications (id, user_id, title, message, notification_type, link, created_at)
                   VALUES (%s, %s, %s, %s, 'email', '/email', NOW())""",
                (notif_id, recipient.get("id"), "بريد جديد", f"رسالة من {current_user.get('full_name')}: {email.subject}")
            )
    
    return {"message": "تم إرسال البريد بنجاح", "email_id": email_id}

@api_router.put("/emails/{email_id}/read")
async def mark_email_read(email_id: str, current_user: dict = Depends(get_current_user)):
    await execute_query(
        "UPDATE email_recipients SET is_read = TRUE, read_at = NOW() WHERE email_id = %s AND recipient_id = %s",
        (email_id, current_user["id"])
    )
    return {"message": "تم تحديث البريد"}

# =====================================================
# APIs المحكمة الافتراضية
# =====================================================

# سيناريوهات لعبة التحدي القانوني
PROSECUTOR_SCENARIOS = [
    {
        "id": "scenario_1",
        "title": "سرقة المتجر",
        "case_summary": "تم الإبلاغ عن سرقة متجر إلكترونيات في حي الملز.",
        "crime_type": "سرقة",
        "evidence_list": [
            {"id": "e1", "type": "video", "description": "تسجيل كاميرا المراقبة", "relevance": "high"},
            {"id": "e2", "type": "physical", "description": "أجهزة مسروقة في سيارة المشتبه به", "relevance": "high"},
            {"id": "e3", "type": "witness", "description": "شهادة صاحب المتجر", "relevance": "medium"},
        ],
        "suspects": [
            {"id": "s1", "name": "خالد محمد", "description": "موظف سابق", "is_culprit": True},
            {"id": "s2", "name": "أحمد علي", "description": "زبون", "is_culprit": False}
        ],
        "correct_accusation": "جريمة سرقة موصوفة",
        "correct_articles": ["نظام العقوبات - المادة 321"],
        "difficulty": "مبتدئ",
        "points": 100,
        "time_limit": 15
    }
]

GOLDEN_PLEADING_SCENARIOS = [
    {
        "id": "pleading_1",
        "title": "الدفاع عن متهم بالسرقة",
        "case_type": "جنائي",
        "difficulty": "مبتدئ",
        "situation": "موكلك متهم بسرقة هاتف محمول من متجر.",
        "your_role": "محامي الدفاع",
        "opponent_arguments": ["تسجيل الكاميرا يُظهر المتهم بوضوح"],
        "available_defenses": [
            {"id": "d1", "text": "جودة تسجيل الكاميرا رديئة", "score": 25, "is_strong": True},
            {"id": "d2", "text": "لدى موكلي شهود", "score": 30, "is_strong": True},
        ],
        "winning_threshold": 70,
        "points": 100,
        "time_limit": 10
    }
]

PROCEDURAL_ERROR_SCENARIOS = [
    {
        "id": "error_1",
        "title": "محاكمة بدون محامٍ",
        "difficulty": "مبتدئ",
        "case_description": "تمت محاكمة متهم بجريمة سرقة دون توفير محامٍ له.",
        "court_proceedings": [
            "افتتح القاضي الجلسة",
            "طلب المتهم توكيل محامٍ",
            "رفض القاضي الطلب",
        ],
        "errors": [
            {"id": "e1", "description": "رفض طلب المتهم لتوكيل محامٍ", "is_error": True, "explanation": "حق المتهم"},
            {"id": "e2", "description": "افتتاح الجلسة", "is_error": False, "explanation": "إجراء صحيح"},
        ],
        "points": 100,
        "time_limit": 8
    }
]

@api_router.get("/virtual-court/prosecutor-game/scenarios")
async def get_prosecutor_scenarios():
    safe_scenarios = []
    for s in PROSECUTOR_SCENARIOS:
        safe_s = {k: v for k, v in s.items() if k not in ["correct_accusation", "correct_articles"]}
        safe_s["suspects"] = [{"id": sus["id"], "name": sus["name"], "description": sus["description"]} for sus in s["suspects"]]
        safe_scenarios.append(safe_s)
    return {"scenarios": safe_scenarios}

@api_router.get("/virtual-court/golden-pleading/scenarios")
async def get_pleading_scenarios():
    safe_scenarios = []
    for s in GOLDEN_PLEADING_SCENARIOS:
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

@api_router.get("/virtual-court/procedural-error/scenarios")
async def get_error_scenarios():
    safe_scenarios = []
    for s in PROCEDURAL_ERROR_SCENARIOS:
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

@api_router.get("/virtual-court/leaderboard")
async def get_leaderboard():
    results = await execute_query(
        """SELECT user_id, user_name, SUM(score) as total_score, COUNT(*) as games_played,
           SUM(CASE WHEN passed = TRUE THEN 1 ELSE 0 END) as games_won
           FROM game_attempts
           GROUP BY user_id, user_name
           ORDER BY total_score DESC
           LIMIT 10""",
        fetch_all=True
    )
    
    leaderboard = []
    for i, r in enumerate(results or []):
        leaderboard.append({
            "rank": i + 1,
            "user_id": r["user_id"],
            "user_name": r["user_name"],
            "total_score": r["total_score"],
            "games_played": r["games_played"],
            "games_won": r["games_won"]
        })
    
    return {"leaderboard": leaderboard}

@api_router.get("/virtual-court/my-profile")
async def get_game_profile(current_user: dict = Depends(get_current_user)):
    profile = await execute_query(
        "SELECT * FROM game_profiles WHERE user_id = %s",
        (current_user["id"],),
        fetch_one=True
    )
    
    if not profile:
        return {
            "user_id": current_user["id"],
            "user_name": current_user["full_name"],
            "total_xp": 0,
            "level": 1,
            "rank": "مبتدئ",
            "games_played": 0,
            "games_won": 0
        }
    
    return profile

# =====================================================
# APIs الإحصائيات
# =====================================================
@api_router.get("/stats/dashboard")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="غير مصرح")
    
    total_users = await execute_query("SELECT COUNT(*) as count FROM users", fetch_one=True)
    total_requests = await execute_query("SELECT COUNT(*) as count FROM client_requests", fetch_one=True)
    total_tasks = await execute_query("SELECT COUNT(*) as count FROM tasks", fetch_one=True)
    pending_tasks = await execute_query("SELECT COUNT(*) as count FROM tasks WHERE status = 'pending'", fetch_one=True)
    
    return {
        "total_users": total_users["count"] if total_users else 0,
        "total_requests": total_requests["count"] if total_requests else 0,
        "total_tasks": total_tasks["count"] if total_tasks else 0,
        "pending_tasks": pending_tasks["count"] if pending_tasks else 0
    }

# =====================================================
# تضمين الراوتر والـ Health Check
# =====================================================

@app.on_event("shutdown")
async def shutdown():
    global pool
    if pool:
        pool.close()
        await pool.wait_closed()

# =====================================================
# وظائف البريد الخارجي (IMAP/SMTP)
# =====================================================
import imaplib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.header import decode_header, Header
from email.utils import formataddr, parsedate_to_datetime
import email as email_lib
import base64
import logging
import asyncio

IMAP_SERVER = os.environ.get('IMAP_SERVER', 'mail.hklaw.sa')
IMAP_PORT = int(os.environ.get('IMAP_PORT', 993))
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'mail.hklaw.sa')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 465))
EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', '')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')

def decode_email_header(header):
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
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return []
    emails_data = []
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        mail.select('INBOX')
        status, messages = mail.search(None, 'ALL')
        if status == 'OK':
            email_ids = messages[0].split()
            recent_ids = email_ids[-50:] if len(email_ids) > 50 else email_ids
            for email_id in reversed(recent_ids):
                try:
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    if status == 'OK':
                        raw_email = msg_data[0][1]
                        msg = email_lib.message_from_bytes(raw_email)
                        subject = decode_email_header(msg.get('Subject', ''))
                        from_header = decode_email_header(msg.get('From', ''))
                        to_header = decode_email_header(msg.get('To', ''))
                        date_header = msg.get('Date', '')
                        message_id = msg.get('Message-ID', str(uuid.uuid4()))
                        try:
                            sent_date = parsedate_to_datetime(date_header)
                        except:
                            sent_date = datetime.now(timezone.utc)
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
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        raise Exception("بيانات SMTP غير مكتملة")
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = formataddr((str(Header('HK Law Firm', 'utf-8')), EMAIL_ADDRESS))
        msg['To'] = to_email
        msg['Subject'] = subject
        msg['Reply-To'] = EMAIL_ADDRESS
        msg['Message-ID'] = f"<{uuid.uuid4()}@hklaw.sa>"
        msg['Date'] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        msg['X-Mailer'] = "Legal Suite - HK Law Firm"
        msg['MIME-Version'] = "1.0"
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        html_body = f"""
        <html dir="rtl">
        <head><meta charset="utf-8"></head>
        <body style="font-family: Arial, sans-serif; direction: rtl;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="white-space: pre-wrap;">{body}</div>
                <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
                <p style="color: #666; font-size: 12px;">مكتب المحامي هشام يوسف الخياط<br>البريد: info@hklaw.sa</p>
            </div>
        </body>
        </html>
        """
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        if attachments:
            for att in attachments:
                if att.get('data'):
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(base64.b64decode(att['data']))
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', f'attachment; filename="{att.get("name", "attachment")}"')
                    msg.attach(part)
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
async def sync_external_emails(current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "client":
        raise HTTPException(status_code=403, detail="غير مصرح")
    loop = asyncio.get_event_loop()
    external_emails = await loop.run_in_executor(None, sync_fetch_external_emails)
    synced_count = 0
    for ext_email in external_emails:
        existing = await execute_query(
            "SELECT id FROM emails WHERE external_message_id = %s",
            (ext_email["message_id"],), fetch_one=True
        )
        if existing:
            continue
        email_id = str(uuid.uuid4())
        await execute_query("""
            INSERT INTO emails (id, sender_id, sender_name, sender_email, subject, body, 
                              is_external, external_email, external_message_id, status, sent_at, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (email_id, None, ext_email["sender_name"], ext_email["sender_email"],
              ext_email["subject"], ext_email["body"], True, ext_email["sender_email"],
              ext_email["message_id"], "received", ext_email["sent_at"], 
              datetime.now(timezone.utc).isoformat()))
        staff = await execute_query(
            "SELECT id, email FROM users WHERE role IN ('admin', 'lawyer')",
            fetch_all=True
        )
        for user in staff:
            recipient_id = str(uuid.uuid4())
            await execute_query("""
                INSERT INTO email_recipients (id, email_id, user_id, user_email, recipient_type, is_read, folder)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (recipient_id, email_id, user["id"], user["email"], "to", False, "inbox"))
        synced_count += 1
    return {"message": f"تم مزامنة {synced_count} رسالة جديدة", "synced_count": synced_count}

@api_router.post("/emails/external/send")
async def send_external_email(email_input: ExternalEmailInput, current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "client":
        raise HTTPException(status_code=403, detail="غير مصرح")
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, sync_send_external_email, 
                                   email_input.to_email, email_input.subject, 
                                   email_input.body, email_input.attachments)
        email_id = str(uuid.uuid4())
        await execute_query("""
            INSERT INTO emails (id, sender_id, sender_name, sender_email, subject, body,
                              is_external, external_email, status, sent_at, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (email_id, current_user["id"], current_user["full_name"], EMAIL_ADDRESS,
              email_input.subject, email_input.body, True, email_input.to_email,
              "sent", datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()))
        return {"message": "تم إرسال البريد بنجاح", "email_id": email_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"فشل إرسال البريد: {str(e)}")

@api_router.get("/emails/external/test")
async def test_email_connection(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="للمدير فقط")
    results = {"imap": False, "smtp": False, "errors": []}
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        mail.logout()
        results["imap"] = True
    except Exception as e:
        results["errors"].append(f"IMAP: {str(e)}")
    try:
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.quit()
        results["smtp"] = True
    except Exception as e:
        results["errors"].append(f"SMTP: {str(e)}")
    return results
app.include_router(api_router)

@app.get("/api/health")
async def health_check():
    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT 1")
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return {
        "status": "healthy" if db_status == "connected" else "unhealthy",
        "database": db_status,
        "version": "2.0.0",
        "app": "Al-Khayat Law Firm Management System (MySQL)"
    }

@app.on_event("startup")
async def startup():
    try:
        await get_db_pool()
        print("✅ Connected to MySQL database")
    except Exception as e:
        print(f"❌ Failed to connect to MySQL: {e}")
