from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
import os


class Settings(BaseSettings):
    # Application
    APP_ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "change-me-in-production"
    API_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./cloudguard.db"

    # Security
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_PASSWORD: str = "change-me"

    # CORS
    FRONTEND_URL: str = "http://localhost:3000"

    # Detection & Response
    AUTOMATED_RESPONSE_ENABLED: bool = False
    DEMO_MODE_ENABLED: bool = False

    # Telemetry
    USE_SIMULATED_TELEMETRY: bool = True
    TELEMETRY_INTERVAL_SECONDS: int = 5
    KNOWN_DESTINATIONS: str = ""
    MODEL_PATH: str = "./model-store/isolation_forest.joblib"

    # Application metadata
    APP_NAME: str = "CloudGuard"
    APP_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")


settings = Settings()
