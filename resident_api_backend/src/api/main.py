import os
from datetime import datetime
from typing import List, Optional, Tuple

from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Column, DateTime, Integer, String, create_engine, func, or_
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from passlib.context import CryptContext
import jwt

# -----------------------------
# Configuration (env + defaults)
# -----------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "240"))

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "..", "..", "residents.db"
)
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", os.path.abspath(DEFAULT_DB_PATH))

DEFAULT_UPLOAD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "..", "..", "uploads"
)
UPLOAD_DIR = os.getenv("UPLOAD_DIR", os.path.abspath(DEFAULT_UPLOAD_DIR))

os.makedirs(os.path.dirname(SQLITE_DB_PATH), exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -----------------------------
# Database setup (SQLite fallback)
# -----------------------------
Base = declarative_base()
engine = create_engine(
    f"sqlite:///{SQLITE_DB_PATH}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class UserORM(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")  # "admin" | "user"
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class ResidentORM(Base):
    __tablename__ = "residents"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    address = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    email = Column(String, nullable=True, index=True)
    photo_url = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field("bearer", description="Token type; always 'bearer'")
    role: str = Field(..., description="User role (admin|user)")
    email: EmailStr = Field(..., description="Logged in user email")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=3, description="User password")


class MeResponse(BaseModel):
    email: EmailStr = Field(..., description="User email")
    role: str = Field(..., description="User role")


class ResidentBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="Resident name")
    address: Optional[str] = Field(None, max_length=500, description="Resident address")
    phone: Optional[str] = Field(None, max_length=50, description="Resident phone number")
    email: Optional[EmailStr] = Field(None, description="Resident email")
    photo_url: Optional[str] = Field(None, description="URL pointing to resident photo")


class ResidentCreate(ResidentBase):
    pass


class ResidentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200, description="Resident name")
    address: Optional[str] = Field(None, max_length=500, description="Resident address")
    phone: Optional[str] = Field(None, max_length=50, description="Resident phone number")
    email: Optional[EmailStr] = Field(None, description="Resident email")
    photo_url: Optional[str] = Field(None, description="URL pointing to resident photo")


class ResidentOut(ResidentBase):
    id: int = Field(..., description="Resident id")
    created_at: datetime = Field(..., description="Created timestamp")
    updated_at: datetime = Field(..., description="Updated timestamp")

    class Config:
        from_attributes = True


class ResidentListResponse(BaseModel):
    items: List[ResidentOut] = Field(..., description="Residents page items")
    page: int = Field(..., description="Current page (1-based)")
    page_size: int = Field(..., description="Page size")
    total: int = Field(..., description="Total matching records")


class UploadResponse(BaseModel):
    photo_url: str = Field(..., description="URL to the uploaded photo")


# PUBLIC_INTERFACE
def create_app() -> FastAPI:
    """Create and configure the FastAPI app."""
    openapi_tags = [
        {"name": "Health", "description": "Service health and metadata."},
        {"name": "Auth", "description": "Email/password login and current user info."},
        {"name": "Residents", "description": "Resident directory endpoints."},
        {"name": "Uploads", "description": "Photo upload and static file serving."},
        {"name": "Demo", "description": "Utilities for quick demo usage."},
    ]

    app = FastAPI(
        title="Resident Management System API",
        description=(
            "Backend API for a Resident Directory with JWT authentication and role-based access control.\n\n"
            "- Public: list/search residents, get resident by id\n"
            "- Admin: create/update/delete residents, upload photos\n"
            "- Auth: email/password JWT sessions\n\n"
            "WebSocket: none."
        ),
        version="1.0.0",
        openapi_tags=openapi_tags,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[FRONTEND_ORIGIN],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Serve uploaded files
    app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

    @app.get("/", tags=["Health"], summary="Health check", operation_id="health_check")
    # PUBLIC_INTERFACE
    def health_check():
        """Health check endpoint.

        Returns:
            JSON with a simple "Healthy" message.
        """
        return {"message": "Healthy"}

    @app.get(
        "/docs/websocket",
        tags=["Health"],
        summary="WebSocket usage help (none)",
        operation_id="websocket_usage_help",
    )
    # PUBLIC_INTERFACE
    def websocket_help():
        """WebSocket usage help.

        This project does not expose any WebSocket endpoints.
        """
        return {"websocket": "not supported"}

    # Ensure DB tables exist and seed demo data if empty
    Base.metadata.create_all(bind=engine)
    _ensure_seed_data()

    # -----------------------------
    # Dependencies
    # -----------------------------
    def get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def _create_access_token(sub: str, role: str) -> str:
        exp = datetime.utcnow().timestamp() + (JWT_EXPIRE_MINUTES * 60)
        payload = {"sub": sub, "role": role, "exp": exp}
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    def _decode_token(token: str) -> dict:
        try:
            return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from exc
        except jwt.InvalidTokenError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    def get_current_user(
        authorization: Optional[str] = None,
        db: Session = Depends(get_db),
    ) -> Tuple[UserORM, dict]:
        """
        Bearer token auth dependency.

        NOTE: We do not use fastapi.security helpers to keep dependencies minimal.
        """
        if not authorization:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")

        if not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization header")

        token = authorization.split(" ", 1)[1].strip()
        payload = _decode_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

        user = db.query(UserORM).filter(UserORM.email == email).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

        return user, payload

    def require_admin(user_and_payload: Tuple[UserORM, dict] = Depends(get_current_user)) -> UserORM:
        user, payload = user_and_payload
        role = payload.get("role")
        if role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
        return user

    # -----------------------------
    # Auth routes
    # -----------------------------
    @app.post(
        "/auth/login",
        response_model=TokenResponse,
        tags=["Auth"],
        summary="Login with email/password",
        operation_id="login",
    )
    # PUBLIC_INTERFACE
    def login(payload: LoginRequest, db: Session = Depends(get_db)):
        """Authenticate a user and return a JWT.

        Parameters:
            payload: LoginRequest containing email and password
        Returns:
            TokenResponse with access token, role, and email
        """
        user = db.query(UserORM).filter(UserORM.email == payload.email).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        if not pwd_context.verify(payload.password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = _create_access_token(sub=user.email, role=user.role)
        return TokenResponse(access_token=token, role=user.role, email=user.email)

    @app.get(
        "/auth/me",
        response_model=MeResponse,
        tags=["Auth"],
        summary="Get current logged-in user",
        operation_id="me",
    )
    # PUBLIC_INTERFACE
    def me(user_and_payload: Tuple[UserORM, dict] = Depends(get_current_user)):
        """Return current user identity and role."""
        user, payload = user_and_payload
        return MeResponse(email=user.email, role=payload.get("role", user.role))

    # -----------------------------
    # Resident routes
    # -----------------------------
    @app.get(
        "/residents",
        response_model=ResidentListResponse,
        tags=["Residents"],
        summary="List/search residents (public)",
        operation_id="list_residents",
    )
    # PUBLIC_INTERFACE
    def list_residents(
        q: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        db: Session = Depends(get_db),
    ):
        """List residents with pagination and basic search.

        Parameters:
            q: optional search term matched against name/email
            page: 1-based page number
            page_size: page size (max 50)
        """
        if page < 1:
            raise HTTPException(status_code=400, detail="page must be >= 1")
        page_size = max(1, min(page_size, 50))

        query = db.query(ResidentORM)
        if q:
            like = f"%{q.strip()}%"
            query = query.filter(or_(ResidentORM.name.ilike(like), ResidentORM.email.ilike(like)))

        total = query.with_entities(func.count(ResidentORM.id)).scalar() or 0
        items = (
            query.order_by(ResidentORM.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        return ResidentListResponse(
            items=[_resident_to_out(r) for r in items],
            page=page,
            page_size=page_size,
            total=total,
        )

    @app.get(
        "/residents/{resident_id}",
        response_model=ResidentOut,
        tags=["Residents"],
        summary="Get resident by id (public)",
        operation_id="get_resident",
    )
    # PUBLIC_INTERFACE
    def get_resident(resident_id: int, db: Session = Depends(get_db)):
        """Get a single resident by id."""
        resident = db.query(ResidentORM).filter(ResidentORM.id == resident_id).first()
        if not resident:
            raise HTTPException(status_code=404, detail="Resident not found")
        return _resident_to_out(resident)

    @app.post(
        "/residents",
        response_model=ResidentOut,
        tags=["Residents"],
        summary="Create resident (admin only)",
        operation_id="create_resident",
        status_code=201,
    )
    # PUBLIC_INTERFACE
    def create_resident(
        payload: ResidentCreate,
        db: Session = Depends(get_db),
        _admin: UserORM = Depends(require_admin),
    ):
        """Create a resident (admin only)."""
        now = datetime.utcnow()
        resident = ResidentORM(
            name=payload.name,
            address=payload.address,
            phone=payload.phone,
            email=str(payload.email) if payload.email else None,
            photo_url=payload.photo_url,
            created_at=now,
            updated_at=now,
        )
        db.add(resident)
        db.commit()
        db.refresh(resident)
        return _resident_to_out(resident)

    @app.put(
        "/residents/{resident_id}",
        response_model=ResidentOut,
        tags=["Residents"],
        summary="Update resident (admin only)",
        operation_id="update_resident",
    )
    # PUBLIC_INTERFACE
    def update_resident(
        resident_id: int,
        payload: ResidentUpdate,
        db: Session = Depends(get_db),
        _admin: UserORM = Depends(require_admin),
    ):
        """Update a resident (admin only)."""
        resident = db.query(ResidentORM).filter(ResidentORM.id == resident_id).first()
        if not resident:
            raise HTTPException(status_code=404, detail="Resident not found")

        # Only set provided fields
        if payload.name is not None:
            resident.name = payload.name
        if payload.address is not None:
            resident.address = payload.address
        if payload.phone is not None:
            resident.phone = payload.phone
        if payload.email is not None:
            resident.email = str(payload.email)
        if payload.photo_url is not None:
            resident.photo_url = payload.photo_url

        resident.updated_at = datetime.utcnow()
        db.add(resident)
        db.commit()
        db.refresh(resident)
        return _resident_to_out(resident)

    @app.delete(
        "/residents/{resident_id}",
        tags=["Residents"],
        summary="Delete resident (admin only)",
        operation_id="delete_resident",
        status_code=204,
    )
    # PUBLIC_INTERFACE
    def delete_resident(
        resident_id: int,
        db: Session = Depends(get_db),
        _admin: UserORM = Depends(require_admin),
    ):
        """Delete a resident (admin only)."""
        resident = db.query(ResidentORM).filter(ResidentORM.id == resident_id).first()
        if not resident:
            raise HTTPException(status_code=404, detail="Resident not found")
        db.delete(resident)
        db.commit()
        return None

    # -----------------------------
    # Upload routes (admin only)
    # -----------------------------
    @app.post(
        "/uploads/photo",
        response_model=UploadResponse,
        tags=["Uploads"],
        summary="Upload resident photo (admin only)",
        operation_id="upload_photo",
    )
    # PUBLIC_INTERFACE
    async def upload_photo(
        file: UploadFile = File(..., description="Image file to upload"),
        _admin: UserORM = Depends(require_admin),
    ):
        """Upload a photo and return a photo_url.

        Stores the file in UPLOAD_DIR and returns a URL under /uploads.
        """
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")

        # Basic allowlist check by content-type (not bulletproof, but good for demo)
        if file.content_type and not file.content_type.startswith("image/"):
            raise HTTPException(status_code=400, detail="Only image uploads are supported")

        ext = os.path.splitext(file.filename)[1].lower() or ".bin"
        safe_ext = ext if len(ext) <= 10 else ".bin"
        ts = int(datetime.utcnow().timestamp() * 1000)
        out_name = f"photo_{ts}{safe_ext}"
        out_path = os.path.join(UPLOAD_DIR, out_name)

        data = await file.read()
        if not data:
            raise HTTPException(status_code=400, detail="Empty file")

        with open(out_path, "wb") as f:
            f.write(data)

        return UploadResponse(photo_url=f"/uploads/{out_name}")

    @app.get(
        "/uploads/raw/{filename}",
        tags=["Uploads"],
        summary="Get uploaded file (raw) - convenience",
        operation_id="get_uploaded_file_raw",
    )
    # PUBLIC_INTERFACE
    def get_uploaded_file_raw(filename: str):
        """Serve an uploaded file by filename (convenience).

        StaticFiles already serves /uploads/*, but this endpoint is useful
        if you want an explicit documented route.
        """
        path = os.path.join(UPLOAD_DIR, filename)
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="File not found")
        return FileResponse(path)

    # -----------------------------
    # Demo utilities
    # -----------------------------
    @app.post(
        "/demo/reset",
        tags=["Demo"],
        summary="Reset DB to demo seed (admin only)",
        operation_id="demo_reset",
    )
    # PUBLIC_INTERFACE
    def demo_reset(
        db: Session = Depends(get_db),
        _admin: UserORM = Depends(require_admin),
    ):
        """Reset residents table to demo seed data (admin only)."""
        db.query(ResidentORM).delete()
        db.commit()
        _seed_residents(db)
        return {"status": "ok", "message": "Demo data reset"}

    return app


app = create_app()


def _resident_to_out(resident: ResidentORM) -> ResidentOut:
    """Convert ORM resident record to API output schema."""
    return ResidentOut(
        id=resident.id,
        name=resident.name,
        address=resident.address,
        phone=resident.phone,
        email=resident.email,
        photo_url=resident.photo_url,
        created_at=resident.created_at,
        updated_at=resident.updated_at,
    )


def _ensure_seed_data() -> None:
    """Seed users/residents if DB is empty."""
    db = SessionLocal()
    try:
        users_count = db.query(UserORM).count()
        if users_count == 0:
            # Demo accounts:
            # admin@example.com / admin123
            # user@example.com / user123
            admin = UserORM(
                email="admin@example.com",
                password_hash=pwd_context.hash("admin123"),
                role="admin",
            )
            user = UserORM(
                email="user@example.com",
                password_hash=pwd_context.hash("user123"),
                role="user",
            )
            db.add_all([admin, user])
            db.commit()

        residents_count = db.query(ResidentORM).count()
        if residents_count == 0:
            _seed_residents(db)
    finally:
        db.close()


def _seed_residents(db: Session) -> None:
    """Insert some demo residents."""
    now = datetime.utcnow()
    demo = [
        ResidentORM(
            name="Alex Johnson",
            email="alex.johnson@example.com",
            phone="(555) 010-1001",
            address="101 Main St",
            photo_url=None,
            created_at=now,
            updated_at=now,
        ),
        ResidentORM(
            name="Bianca Rivera",
            email="bianca.rivera@example.com",
            phone="(555) 010-1002",
            address="202 Oak Ave",
            photo_url=None,
            created_at=now,
            updated_at=now,
        ),
        ResidentORM(
            name="Chris Lee",
            email="chris.lee@example.com",
            phone="(555) 010-1003",
            address="303 Pine Rd",
            photo_url=None,
            created_at=now,
            updated_at=now,
        ),
    ]
    db.add_all(demo)
    db.commit()
