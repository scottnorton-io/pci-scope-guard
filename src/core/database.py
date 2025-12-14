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
    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    
    # Enable TimescaleDB hypertable for data_flows
    try:
        with engine.connect() as conn:
            conn.execute(
                "SELECT create_hypertable('data_flows', 'observed_at', "
                "if_not_exists => TRUE, migrate_data => TRUE)"
            )
            conn.commit()
            logger.info("TimescaleDB hypertable created for data_flows")
    except Exception as e:
        logger.warning(f"Could not create TimescaleDB hypertable: {e}")
    
    logger.info("Database schema initialized successfully")

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
            self.client.ping()
            info = self.client.info()
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
