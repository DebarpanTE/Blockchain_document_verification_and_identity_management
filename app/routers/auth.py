"""Authentication endpoints."""
import uuid
import time
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.database import get_db, User
from app.models.schemas import UserRegister, TokenResponse, UserOut
from app.services.auth import hash_password, verify_password, create_access_token, get_current_user
from app.services.blockchain import KeyManager

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=UserOut, status_code=201)
async def register(data: UserRegister, db: AsyncSession = Depends(get_db)):
    # Check duplicates
    existing = await db.execute(
        select(User).where((User.username == data.username) | (User.email == data.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username or email already registered")

    private_pem, public_pem = KeyManager.generate_key_pair()

    user = User(
        id=str(uuid.uuid4()),
        username=data.username,
        email=data.email,
        full_name=data.full_name,
        hashed_password=hash_password(data.password),
        public_key=public_pem,
        private_key_encrypted=private_pem,  # In prod: encrypt with user's password
        created_at=time.time(),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User).where((User.username == form.username) | (User.email == form.username))
    )
    user = result.scalar_one_or_none()
    if not user or not verify_password(form.password, str(user.hashed_password)):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user.id})
    return TokenResponse(access_token=token, user_id=str(user.id), username=str(user.username))


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user