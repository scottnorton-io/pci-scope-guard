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
    VANTA_API_URL: str = Field(default="https://api.vanta.com/v1", env="VANTA_API_URL")
    DRATA_API_KEY: Optional[SecretStr] = Field(default=None, env="DRATA_API_KEY")
    DRATA_API_URL: str = Field(default="https://api.drata.com/v1", env="DRATA_API_URL")
    SECUREFRAME_API_KEY: Optional[SecretStr] = Field(default=None, env="SECUREFRAME_API_KEY")
    SECUREFRAME_API_URL: str = Field(default="https://api.secureframe.com/v1", env="SECUREFRAME_API_URL")
    
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
        default=["http://localhost:3000", "http://localhost:8080"],
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
