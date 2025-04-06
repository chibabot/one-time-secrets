# main.py
import os
from datetime import datetime, timedelta
from typing import Optional

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Header, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import redis
import asyncpg
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="Secret Service API",
    description="API for storing and retrieving one-time secrets",
    version="1.0.0",
)

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set")
FERNET = Fernet(SECRET_KEY.encode())

DEFAULT_TTL = int(os.getenv("DEFAULT_TTL_SECONDS", 300))  # 5 minutes

# Database connection pool
_db_pool = None

# Redis client
_redis_client = None


class SecretCreate(BaseModel):
    secret: str = Field(..., min_length=1, max_length=4096)
    passphrase: Optional[str] = Field(None, min_length=1, max_length=256)
    ttl_seconds: Optional[int] = Field(None, ge=60, le=86400)  # 1 min to 1 day


class SecretResponse(BaseModel):
    secret: str


class DeleteSecretRequest(BaseModel):
    passphrase: Optional[str] = Field(None, min_length=1, max_length=256)


class StatusResponse(BaseModel):
    status: str


async def get_db_pool():
    global _db_pool
    if _db_pool is None:
        _db_pool = await asyncpg.create_pool(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", 5432)),
            database=os.getenv("POSTGRES_DB", "secrets_db"),
            user=os.getenv("POSTGRES_USER", "secrets_user"),
            password=os.getenv("POSTGRES_PASSWORD", ""),
        )
    return _db_pool


def get_redis_client():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            db=0,
            decode_responses=False,
        )
    return _redis_client


@app.on_event("startup")
async def startup():
    await get_db_pool()
    get_redis_client()


@app.on_event("shutdown")
async def shutdown():
    if _db_pool:
        await _db_pool.close()
    if _redis_client:
        _redis_client.close()


async def log_action(
    secret_key: str,
    action: str,
    request: Request,
    metadata: Optional[dict] = None,
):
    db_pool = await get_db_pool()
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO access_logs (
                secret_key, action, ip_address, user_agent, metadata
            ) VALUES ($1, $2, $3, $4, $5)
            """,
            secret_key,
            action,
            request.client.host if request.client else None,
            request.headers.get("user-agent"),
            metadata,
        )


def encrypt_secret(secret: str) -> str:
    return FERNET.encrypt(secret.encode()).decode()


def decrypt_secret(encrypted_secret: str) -> str:
    return FERNET.decrypt(encrypted_secret.encode()).decode()


@app.post("/secret", response_model=dict)
async def create_secret(
    secret_data: SecretCreate,
    request: Request,
):
    redis_client = get_redis_client()
    
    # Generate unique key
    secret_key = os.urandom(16).hex()
    
    # Calculate expiration time
    ttl = secret_data.ttl_seconds if secret_data.ttl_seconds else DEFAULT_TTL
    expires_at = datetime.utcnow() + timedelta(seconds=ttl)
    
    # Encrypt the secret
    encrypted_secret = encrypt_secret(secret_data.secret)
    
    # Store in Redis
    redis_client.setex(
        name=f"secret:{secret_key}",
        time=ttl,
        value=encrypted_secret,
    )
    
    # Store metadata in PostgreSQL
    db_pool = await get_db_pool()
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO secrets (
                secret_key, encrypted_secret, passphrase_hash, expires_at
            ) VALUES ($1, $2, $3, $4)
            """,
            secret_key,
            encrypted_secret,
            secret_data.passphrase,
            expires_at,
        )
    
    # Log the action
    await log_action(
        secret_key=secret_key,
        action="create",
        request=request,
        metadata={
            "ttl_seconds": ttl,
            "has_passphrase": bool(secret_data.passphrase),
        },
    )
    
    return {"secret_key": secret_key}


@app.get("/secret/{secret_key}", response_model=SecretResponse)
async def get_secret(
    secret_key: str,
    request: Request,
):
    redis_client = get_redis_client()
    
    # Try to get from Redis first
    encrypted_secret = redis_client.get(f"secret:{secret_key}")
    
    if not encrypted_secret:
        # Check if secret exists in DB but is already used
        db_pool = await get_db_pool()
        async with db_pool.acquire() as conn:
            record = await conn.fetchrow(
                """
                SELECT is_used, is_deleted FROM secrets
                WHERE secret_key = $1
                """,
                secret_key,
            )
        
        if record:
            if record["is_used"]:
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Secret has already been accessed",
                )
            if record["is_deleted"]:
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Secret has been deleted",
                )
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found or expired",
        )
    
    # Mark as used in DB
    db_pool = await get_db_pool()
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE secrets
            SET is_used = TRUE
            WHERE secret_key = $1
            """,
            secret_key,
        )
    
    # Delete from Redis
    redis_client.delete(f"secret:{secret_key}")
    
    # Log the action
    await log_action(
        secret_key=secret_key,
        action="read",
        request=request,
    )
    
    # Decrypt and return the secret
    return {"secret": decrypt_secret(encrypted_secret)}


@app.delete("/secret/{secret_key}", response_model=StatusResponse)
async def delete_secret(
    secret_key: str,
    request: Request,
    delete_request: Optional[DeleteSecretRequest] = None,
):
    redis_client = get_redis_client()
    db_pool = await get_db_pool()
    
    async with db_pool.acquire() as conn:
        # Check if secret exists and verify passphrase if needed
        record = await conn.fetchrow(
            """
            SELECT passphrase_hash, is_deleted
            FROM secrets
            WHERE secret_key = $1
            """,
            secret_key,
        )
        
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Secret not found",
            )
        
        if record["is_deleted"]:
            return {"status": "already_deleted"}
        
        if record["passphrase_hash"]:
            if not delete_request or not delete_request.passphrase:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Passphrase is required to delete this secret",
                )
            
            if delete_request.passphrase != record["passphrase_hash"]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid passphrase",
                )
        
        # Mark as deleted in DB
        await conn.execute(
            """
            UPDATE secrets
            SET is_deleted = TRUE
            WHERE secret_key = $1
            """,
            secret_key,
        )
    
    # Delete from Redis if exists
    redis_client.delete(f"secret:{secret_key}")
    
    # Log the action
    await log_action(
        secret_key=secret_key,
        action="delete",
        request=request,
    )
    
    return {"status": "secret_deleted"}


@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# Database initialization (for first run)
async def init_db():
    db_pool = await get_db_pool()
    async with db_pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id SERIAL PRIMARY KEY,
                secret_key VARCHAR(255) UNIQUE NOT NULL,
                encrypted_secret TEXT NOT NULL,
                passphrase_hash VARCHAR(255),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP WITH TIME ZONE,
                is_used BOOLEAN DEFAULT FALSE,
                is_deleted BOOLEAN DEFAULT FALSE
            );
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id SERIAL PRIMARY KEY,
                secret_key VARCHAR(255) NOT NULL,
                action VARCHAR(50) NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                metadata JSONB
            );
        """)
        
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_secrets_key ON secrets(secret_key);
        """)
        
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_secret_key ON access_logs(secret_key);
        """)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
