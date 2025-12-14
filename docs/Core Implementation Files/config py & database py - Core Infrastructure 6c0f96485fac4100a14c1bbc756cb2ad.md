# config.py & database.py - Core Infrastructure

# Core Infrastructure - Configuration & Database

## File 1: `src/core/[config.py](http://config.py)`

```python
"""
PCI Scope Guard - Configuration Management
Environment-based configuration with validation
"""

from typing import Optional, List
from pydantic import BaseSettings, Field, validator, SecretStr
from functools import lru_cache
import os

class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application
    ENV: str = Field(default="development", env="ENV")
    DEBUG: bool = Field(default=False, env="DEBUG")
    APP_NAME: str = "PCI Scope Guard"
    APP_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api/v1"
    
    # Security
    SECRET_KEY: SecretStr = Field(..., env="SECRET_KEY")
    SIGNING_KEY_PATH: str = Field(..., env="SIGNING_KEY_PATH")
    SIGNING_ALGORITHM: str = Field(default="ES256", env="SIGNING_ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # Database
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    DATABASE_POOL_SIZE: int = Field(default=20, env="DATABASE_POOL_SIZE")
    DATABASE_MAX_OVERFLOW: int = Field(default=10, env="DATABASE_MAX_OVERFLOW")
    DATABASE_ECHO: bool = Field(default=False, env="DATABASE_ECHO")
    
    # Redis
    REDIS_URL: str = Field(..., env="REDIS_URL")
    REDIS_MAX_CONNECTIONS: int = Field(default=50, env="REDIS_MAX_CONNECTIONS")
    CACHE_TTL: int = Field(default=300, env="CACHE_TTL")  # 5 minutes
    
    # AWS Configuration
    AWS_REGION: Optional[str] = Field(default=None, env="AWS_REGION")
    AWS_ACCESS_KEY_ID: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY: Optional[SecretStr] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    AWS_ENABLE_FLOW_LOGS: bool = Field(default=True, env="AWS_ENABLE_FLOW_LOGS")
    AWS_FLOW_LOG_GROUP: str = Field(default="/aws/vpc/flowlogs", env="AWS_FLOW_LOG_GROUP")
    
    # Azure Configuration
    AZURE_SUBSCRIPTION_ID: Optional[str] = Field(default=None, env="AZURE_SUBSCRIPTION_ID")
    AZURE_TENANT_ID: Optional[str] = Field(default=None, env="AZURE_TENANT_ID")
    AZURE_CLIENT_ID: Optional[str] = Field(default=None, env="AZURE_CLIENT_ID")
    AZURE_CLIENT_SECRET: Optional[SecretStr] = Field(default=None, env="AZURE_CLIENT_SECRET")
    
    # GCP Configuration
    GCP_PROJECT_ID: Optional[str] = Field(default=None, env="GCP_PROJECT_ID")
    GCP_CREDENTIALS_PATH: Optional[str] = Field(default=None, env="GCP_CREDENTIALS_PATH")
    
    # GRC Integrations
    VANTA_API_KEY: Optional[SecretStr] = Field(default=None, env="VANTA_API_KEY")
    VANTA_API_URL: str = Field(default="[https://api.vanta.com/v1](https://api.vanta.com/v1)", env="VANTA_API_URL")
    DRATA_API_KEY: Optional[SecretStr] = Field(default=None, env="DRATA_API_KEY")
    DRATA_API_URL: str = Field(default="[https://api.drata.com/v1](https://api.drata.com/v1)", env="DRATA_API_URL")
    SECUREFRAME_API_KEY: Optional[SecretStr] = Field(default=None, env="SECUREFRAME_API_KEY")
    SECUREFRAME_API_URL: str = Field(default="[https://api.secureframe.com/v1](https://api.secureframe.com/v1)", env="SECUREFRAME_API_URL")
    
    # Evidence Storage
    EVIDENCE_STORAGE_TYPE: str = Field(default="s3", env="EVIDENCE_STORAGE_TYPE")  # s3, azure_blob, gcs
    EVIDENCE_BUCKET_NAME: str = Field(..., env="EVIDENCE_BUCKET_NAME")
    EVIDENCE_RETENTION_YEARS: int = Field(default=7, env="EVIDENCE_RETENTION_YEARS")
    
    # Celery (Task Queue)
    CELERY_BROKER_URL: str = Field(..., env="CELERY_BROKER_URL")
    CELERY_RESULT_BACKEND: str = Field(..., env="CELERY_RESULT_BACKEND")
    
    # Monitoring
    PROMETHEUS_PORT: int = Field(default=9090, env="PROMETHEUS_PORT")
    JAEGER_AGENT_HOST: Optional[str] = Field(default=None, env="JAEGER_AGENT_HOST")
    JAEGER_AGENT_PORT: int = Field(default=6831, env="JAEGER_AGENT_PORT")
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    
    # API Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE")
    
    # CORS
    CORS_ORIGINS: List[str] = Field(
        default=["[http://localhost:3000](http://localhost:3000)", "[http://localhost:8080](http://localhost:8080)"],
        env="CORS_ORIGINS"
    )
    
    # Scan Configuration
    SCAN_BATCH_SIZE: int = Field(default=100, env="SCAN_BATCH_SIZE")
    SCAN_TIMEOUT_SECONDS: int = Field(default=3600, env="SCAN_TIMEOUT_SECONDS")  # 1 hour
    MAX_CONCURRENT_SCANS: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    
    # Classification
    ML_MODEL_PATH: Optional[str] = Field(default=None, env="ML_MODEL_PATH")
    CLASSIFICATION_CONFIDENCE_THRESHOLD: float = Field(default=0.8, env="CLASSIFICATION_CONFIDENCE_THRESHOLD")
    AUTO_CLASSIFY: bool = Field(default=True, env="AUTO_CLASSIFY")
    
    @validator("ENV")
    def validate_env(cls, v):
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"ENV must be one of {allowed}")
        return v
    
    @validator("LOG_LEVEL")
    def validate_log_level(cls, v):
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v.upper()
    
    @validator("EVIDENCE_STORAGE_TYPE")
    def validate_storage_type(cls, v):
        allowed = ["s3", "azure_blob", "gcs", "local"]
        if v not in allowed:
            raise ValueError(f"EVIDENCE_STORAGE_TYPE must be one of {allowed}")
        return v
    
    @validator("CORS_ORIGINS", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()

# Convenience accessors
settings = get_settings()
```

## File 2: `src/core/[database.py](http://database.py)`

```python
"""
PCI Scope Guard - Database Layer
SQLAlchemy session management with connection pooling
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool, QueuePool
from contextlib import contextmanager
from typing import Generator
import logging

from .config import settings
from .models import Base

logger = logging.getLogger(__name__)

# Create engine with connection pooling
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_pre_ping=True,  # Verify connections before using
    echo=settings.DATABASE_ECHO,
    poolclass=QueuePool if settings.ENV == "production" else NullPool,
)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)

# Event listeners for connection management
@event.listens_for(engine, "connect")
def receive_connect(dbapi_conn, connection_record):
    """Set connection parameters on connect"""
    # Set statement timeout (30 seconds)
    dbapi_conn.execute("SET statement_timeout = 30000")
    # Set timezone to UTC
    dbapi_conn.execute("SET timezone = 'UTC'")
    logger.debug("Database connection established")

@event.listens_for(engine, "checkin")
def receive_checkin(dbapi_conn, connection_record):
    """Reset connection state on checkin"""
    logger.debug("Database connection returned to pool")

def init_db():
    """Initialize database schema"""
    [logger.info](http://logger.info)("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    
    # Enable TimescaleDB hypertable for data_flows
    try:
        with engine.connect() as conn:
            conn.execute(
                "SELECT create_hypertable('data_flows', 'observed_at', "
                "if_not_exists => TRUE, migrate_data => TRUE)"
            )
            conn.commit()
            [logger.info](http://logger.info)("TimescaleDB hypertable created for data_flows")
    except Exception as e:
        logger.warning(f"Could not create TimescaleDB hypertable: {e}")
    
    [logger.info](http://logger.info)("Database schema initialized successfully")

def get_db() -> Generator[Session, None, None]:
    """
    Dependency injection for database sessions (FastAPI)
    
    Usage:
        @app.get("/resources")
        def get_resources(db: Session = Depends(get_db)):
            return db.query(Resource).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@contextmanager
def get_db_context():
    """
    Context manager for database sessions (standalone scripts)
    
    Usage:
        with get_db_context() as db:
            resources = db.query(Resource).all()
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

class DatabaseHealthCheck:
    """Database health check for monitoring"""
    
    @staticmethod
    def check() -> dict:
        """Check database connectivity and basic functionality"""
        try:
            with engine.connect() as conn:
                # Test connection
                result = conn.execute("SELECT 1").scalar()
                
                # Get pool statistics
                pool = engine.pool
                pool_status = {
                    "size": pool.size(),
                    "checked_in": pool.checkedin(),
                    "checked_out": pool.checkedout(),
                    "overflow": pool.overflow(),
                }
                
                return {
                    "status": "healthy" if result == 1 else "unhealthy",
                    "pool": pool_status,
                    "database": settings.DATABASE_URL.split("@")[-1],  # Hide credentials
                }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
            }

# Redis connection
from redis import Redis
from redis.connection import ConnectionPool

redis_pool = ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=settings.REDIS_MAX_CONNECTIONS,
    decode_responses=True,
)

redis_client = Redis(connection_pool=redis_pool)

class CacheManager:
    """Redis cache manager with TTL support"""
    
    def __init__(self, client: Redis = redis_client):
        self.client = client
    
    def get(self, key: str):
        """Get value from cache"""
        try:
            return self.client.get(key)
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None
    
    def set(self, key: str, value: str, ttl: int = None):
        """Set value in cache with optional TTL"""
        try:
            if ttl is None:
                ttl = settings.CACHE_TTL
            self.client.setex(key, ttl, value)
        except Exception as e:
            logger.error(f"Cache set error: {e}")
    
    def delete(self, key: str):
        """Delete key from cache"""
        try:
            self.client.delete(key)
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
    
    def flush_pattern(self, pattern: str):
        """Delete all keys matching pattern"""
        try:
            keys = self.client.keys(pattern)
            if keys:
                self.client.delete(*keys)
        except Exception as e:
            logger.error(f"Cache flush error: {e}")
    
    def health_check(self) -> dict:
        """Check Redis connectivity"""
        try:
            [self.client.ping](http://self.client.ping)()
            info = [self.client.info](http://self.client.info)()
            return {
                "status": "healthy",
                "used_memory": info.get("used_memory_human"),
                "connected_clients": info.get("connected_clients"),
            }
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
            }

cache = CacheManager()
```

---

**Key Features:**

1. **Type-Safe Configuration**: Pydantic validates all environment variables
2. **Secrets Management**: SecretStr type prevents accidental logging of sensitive data
3. **Connection Pooling**: Optimized for production with pre-ping health checks
4. **Multi-Cloud Support**: Configuration for AWS, Azure, GCP
5. **GRC Integration Ready**: Built-in support for Vanta, Drata, SecureFrame
6. **Health Checks**: Database and Redis health monitoring
7. **Cache Layer**: Redis integration with TTL support
8. **TimescaleDB**: Automatic hypertable creation for time-series data
9. **Session Management**: Both FastAPI dependency injection and context managers
10. **Production-Ready**: Connection timeouts, timezone handling, graceful error handling

---

**Document Version**: 1.0

**Last Updated**: December 2025

**Author**: Scott Norton