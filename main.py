import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

from pydantic import BaseModel, EmailStr, Field, ConfigDict

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    Table,
)
from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
    Session,
    relationship,
)


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./app.db"
)

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "super-secret-key-change-this"
)

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Doctor Patient Management API",
    description="""
    End-to-End Backend Application using FastAPI.

    Features:
    - JWT Authentication
    - Role Based Authorization
    - Doctor Management
    - Patient Management
    - Doctor Patient Assignment
    - SQLite Database
    - Pydantic Validation
    """,
    version="1.0.0",
)


# ============================================================
# DATABASE
# ============================================================

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    } if DATABASE_URL.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ============================================================
# DOCTOR - PATIENT ASSOCIATION TABLE
# ============================================================

doctor_patient = Table(
    "doctor_patient",
    Base.metadata,

    Column(
        "doctor_id",
        Integer,
        ForeignKey("doctors.id"),
        primary_key=True,
    ),

    Column(
        "patient_id",
        Integer,
        ForeignKey("patients.id"),
        primary_key=True,
    ),
)


# ============================================================
# DATABASE MODELS
# ============================================================

class User(Base):

    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    email = Column(
        String,
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash = Column(
        String,
        nullable=False,
    )

    role = Column(
        String,
        nullable=False,
        default="doctor",
    )

    is_active = Column(
        Boolean,
        default=True,
    )

    doctor = relationship(
        "Doctor",
        back_populates="user",
        uselist=False,
    )


class Doctor(Base):

    __tablename__ = "doctors"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    name = Column(
        String,
        nullable=False,
    )

    specialization = Column(
        String,
        nullable=False,
    )

    email = Column(
        String,
        unique=True,
        nullable=False,
        index=True,
    )

    is_active = Column(
        Boolean,
        default=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )

    user = relationship(
        "User",
        back_populates="doctor",
    )

    patients = relationship(
        "Patient",
        secondary=doctor_patient,
        back_populates="doctors",
    )


class Patient(Base):

    __tablename__ = "patients"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    name = Column(
        String,
        nullable=False,
    )

    age = Column(
        Integer,
        nullable=False,
    )

    phone = Column(
        String,
        nullable=False,
    )

    doctors = relationship(
        "Doctor",
        secondary=doctor_patient,
        back_populates="patients",
    )


# Create database tables
Base.metadata.create_all(bind=engine)


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password: str) -> str:

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100000,
    )

    return (
        salt.hex()
        + ":"
        + password_hash.hex()
    )


def verify_password(
    password: str,
    stored_hash: str,
) -> bool:

    try:

        salt_hex, hash_hex = stored_hash.split(":")

        salt = bytes.fromhex(salt_hex)

        expected_hash = bytes.fromhex(hash_hex)

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000,
        )

        return secrets.compare_digest(
            actual_hash,
            expected_hash,
        )

    except Exception:

        return False


# ============================================================
# JWT
# ============================================================

def create_access_token(
    user_id: int,
    role: str,
):

    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        security
    ),
    db: Session = Depends(get_db),
):

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
    )

    token = credentials.credentials

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = payload.get("sub")

        if not user_id:
            raise credentials_exception

        user = db.query(User).filter(
            User.id == int(user_id)
        ).first()

        if not user:
            raise credentials_exception

        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="User account is inactive",
            )

        return user

    except (
        JWTError,
        ValueError,
        TypeError,
    ):

        raise credentials_exception


def require_admin(
    current_user: User = Depends(
        get_current_user
    ),
):

    if current_user.role != "admin":

        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return current_user


# ============================================================
# PYDANTIC SCHEMAS
# ============================================================

class RegisterRequest(BaseModel):

    email: EmailStr

    password: str = Field(
        min_length=6,
        max_length=100,
    )

    role: str = "doctor"


class LoginRequest(BaseModel):

    email: EmailStr

    password: str


class TokenResponse(BaseModel):

    access_token: str

    token_type: str


class DoctorCreate(BaseModel):

    name: str = Field(
        min_length=1,
        max_length=100,
    )

    specialization: str = Field(
        min_length=1,
        max_length=100,
    )

    email: EmailStr


class DoctorUpdate(BaseModel):

    name: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    specialization: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    email: Optional[EmailStr] = None

    is_active: Optional[bool] = None


class DoctorResponse(BaseModel):

    model_config = ConfigDict(
        from_attributes=True
    )

    id: int
    name: str
    specialization: str
    email: EmailStr
    is_active: bool


class PatientCreate(BaseModel):

    name: str = Field(
        min_length=1,
        max_length=100,
    )

    age: int = Field(
        gt=0
    )

    phone: str = Field(
        pattern=r"^\d{10,15}$"
    )


class PatientResponse(BaseModel):

    model_config = ConfigDict(
        from_attributes=True
    )

    id: int
    name: str
    age: int
    phone: str


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "message": "Doctor Patient Management API",
        "version": "1.0.0",
        "documentation": "/docs",
    }


@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ============================================================
# AUTH - REGISTER
# ============================================================

@app.post(
    "/auth/register",
    status_code=201,
)
def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
):

    if data.role not in ["admin", "doctor"]:

        raise HTTPException(
            status_code=400,
            detail="Role must be admin or doctor",
        )

    existing_user = db.query(User).filter(
        User.email == data.email
    ).first()

    if existing_user:

        raise HTTPException(
            status_code=400,
            detail="Email already registered",
        )

    user = User(
        email=data.email,
        password_hash=hash_password(
            data.password
        ),
        role=data.role,
        is_active=True,
    )

    db.add(user)

    db.commit()

    db.refresh(user)

    # Automatically create doctor profile
    if data.role == "doctor":

        doctor = Doctor(
            name=data.email.split("@")[0],
            specialization="General",
            email=data.email,
            is_active=True,
            user_id=user.id,
        )

        db.add(doctor)

        db.commit()

    return {
        "message": "User registered successfully",
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
    }


# ============================================================
# AUTH - LOGIN
# ============================================================

@app.post(
    "/auth/login",
    response_model=TokenResponse,
)
def login(
    data: LoginRequest,
    db: Session = Depends(get_db),
):

    user = db.query(User).filter(
        User.email == data.email
    ).first()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    if not verify_password(
        data.password,
        user.password_hash,
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    if not user.is_active:

        raise HTTPException(
            status_code=403,
            detail="User account is inactive",
        )

    access_token = create_access_token(
        user.id,
        user.role,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


# ============================================================
# DOCTOR - CREATE
# ============================================================

@app.post(
    "/doctors",
    response_model=DoctorResponse,
    status_code=201,
)
def create_doctor(
    data: DoctorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_admin
    ),
):

    existing_doctor = db.query(
        Doctor
    ).filter(
        Doctor.email == data.email
    ).first()

    if existing_doctor:

        raise HTTPException(
            status_code=400,
            detail="Doctor email already exists",
        )

    doctor = Doctor(
        name=data.name,
        specialization=data.specialization,
        email=data.email,
        is_active=True,
    )

    db.add(doctor)

    db.commit()

    db.refresh(doctor)

    return doctor


# ============================================================
# DOCTOR - LIST
# ============================================================

@app.get(
    "/doctors",
    response_model=list[DoctorResponse],
)
def get_doctors(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

    return db.query(Doctor).filter(
        Doctor.is_active == True
    ).all()


# ============================================================
# DOCTOR - GET BY ID
# ============================================================

@app.get(
    "/doctors/{doctor_id}",
    response_model=DoctorResponse,
)
def get_doctor(
    doctor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

    doctor = db.query(Doctor).filter(
        Doctor.id == doctor_id,
        Doctor.is_active == True,
    ).first()

    if not doctor:

        raise HTTPException(
            status_code=404,
            detail="Doctor not found",
        )

    return doctor


# ============================================================
# DOCTOR - UPDATE
# ============================================================

@app.put(
    "/doctors/{doctor_id}",
    response_model=DoctorResponse,
)
def update_doctor(
    doctor_id: int,
    data: DoctorUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_admin
    ),
):

    doctor = db.query(Doctor).filter(
        Doctor.id == doctor_id
    ).first()

    if not doctor:

        raise HTTPException(
            status_code=404,
            detail="Doctor not found",
        )

    if data.email:

        duplicate = db.query(
            Doctor
        ).filter(
            Doctor.email == data.email,
            Doctor.id != doctor_id,
        ).first()

        if duplicate:

            raise HTTPException(
                status_code=400,
                detail="Email already belongs to another doctor",
            )

    update_data = data.model_dump(
        exclude_unset=True
    )

    for field, value in update_data.items():

        setattr(
            doctor,
            field,
            value,
        )

    db.commit()

    db.refresh(doctor)

    return doctor


# ============================================================
# DOCTOR - SOFT DELETE
# ============================================================

@app.delete(
    "/doctors/{doctor_id}"
)
def delete_doctor(
    doctor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_admin
    ),
):

    doctor = db.query(Doctor).filter(
        Doctor.id == doctor_id
    ).first()

    if not doctor:

        raise HTTPException(
            status_code=404,
            detail="Doctor not found",
        )

    doctor.is_active = False

    db.commit()

    return {
        "message": "Doctor deleted successfully"
    }


# ============================================================
# PATIENT - CREATE
# ============================================================

@app.post(
    "/patients",
    response_model=PatientResponse,
    status_code=201,
)
def create_patient(
    data: PatientCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

    patient = Patient(
        name=data.name,
        age=data.age,
        phone=data.phone,
    )

    db.add(patient)

    db.commit()

    db.refresh(patient)

    return patient


# ============================================================
# PATIENT - LIST
# ============================================================

@app.get(
    "/patients",
    response_model=list[PatientResponse],
)
def get_patients(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

    # Admin can see all patients
    if current_user.role == "admin":

        return db.query(Patient).all()

    # Doctor can only see assigned patients
    doctor = db.query(Doctor).filter(
        Doctor.user_id == current_user.id,
        Doctor.is_active == True,
    ).first()

    if not doctor:

        raise HTTPException(
            status_code=404,
            detail="Doctor profile not found",
        )

    return doctor.patients


# ============================================================
# PATIENT - GET BY ID
# ============================================================

@app.get(
    "/patients/{patient_id}",
    response_model=PatientResponse,
)
def get_patient(
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

    patient = db.query(Patient).filter(
        Patient.id == patient_id
    ).first()

    if not patient:

        raise HTTPException(
            status_code=404,
            detail="Patient not found",
        )

    # Admin can view every patient
    if current_user.role == "admin":

        return patient

    # Doctor can only view assigned patients
    doctor = db.query(Doctor).filter(
        Doctor.user_id == current_user.id,
        Doctor.is_active == True,
    ).first()

    if not doctor:

        raise HTTPException(
            status_code=404,
            detail="Doctor profile not found",
        )

    if patient not in doctor.patients:

        raise HTTPException(
            status_code=403,
            detail="You can only view assigned patients",
        )

    return patient


# ============================================================
# ASSIGN PATIENT TO DOCTOR
# ============================================================

@app.post(
    "/doctors/{doctor_id}/patients/{patient_id}"
)
def assign_patient(
    doctor_id: int,
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_admin
    ),
):

    doctor = db.query(Doctor).filter(
        Doctor.id == doctor_id,
        Doctor.is_active == True,
    ).first()

    if not doctor:

        raise HTTPException(
            status_code=404,
            detail="Doctor not found",
        )

    patient = db.query(Patient).filter(
        Patient.id == patient_id
    ).first()

    if not patient:

        raise HTTPException(
            status_code=404,
            detail="Patient not found",
        )

    if patient in doctor.patients:

        raise HTTPException(
            status_code=400,
            detail="Patient is already assigned to this doctor",
        )

    doctor.patients.append(patient)

    db.commit()

    return {
        "message": "Patient assigned successfully",
        "doctor_id": doctor_id,
        "patient_id": patient_id,
    }


# ============================================================
# GET DOCTOR'S PATIENTS
# ============================================================

@app.get(
    "/doctors/{doctor_id}/patients",
    response_model=list[PatientResponse],
)
def get_doctor_patients(
    doctor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

    doctor = db.query(Doctor).filter(
        Doctor.id == doctor_id,
        Doctor.is_active == True,
    ).first()

    if not doctor:

        raise HTTPException(
            status_code=404,
            detail="Doctor not found",
        )

    # Admin can see any doctor's patients
    if current_user.role == "admin":

        return doctor.patients

    # Doctor can only see their own patients
    if doctor.user_id != current_user.id:

        raise HTTPException(
            status_code=403,
            detail="Doctors can only view their own patients",
        )

    return doctor.patients


# ============================================================
# CURRENT USER
# ============================================================

@app.get("/auth/me")
def get_me(
    current_user: User = Depends(
        get_current_user
    ),
):

    return {
        "id": current_user.id,
        "email": current_user.email,
        "role": current_user.role,
        "is_active": current_user.is_active,
    }


# ============================================================
# APPLICATION INFORMATION
# ============================================================

@app.get("/api/info")
def api_info():

    return {
        "application": "Doctor Patient Management API",
        "version": "1.0.0",
        "authentication": "JWT",
        "database": "SQLite",
        "documentation": "/docs",
        "redoc": "/redoc",
    }