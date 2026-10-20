"""Configuration. All tunables live here so they can be overridden by .env."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Optional Groq (used only when --explain is passed) ---
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "openai/gpt-oss-20b"
    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    GROQ_TIMEOUT_SECONDS: int = Field(default=60, ge=1, le=300)
    GROQ_MAX_RETRIES: int = Field(default=2, ge=0, le=5)
    GROQ_RETRY_BASE_SECONDS: float = Field(default=0.5, ge=0, le=10)
    GROQ_RETRY_MAX_SECONDS: float = Field(default=4.0, ge=0, le=30)

    # --- Generation ---
    TEMPERATURE: float = Field(default=0.2, ge=0, le=2)
    MAX_TOKENS: int = Field(default=1024, ge=1, le=32768)

    # --- Chunking ---
    LINES_PER_CHUNK: int = Field(default=150, ge=1, le=10000)
    MAX_CHUNKS_FOR_LLM: int = Field(default=4, ge=1, le=100)
    MAX_CONCURRENT_LLM_CALLS: int = Field(default=2, ge=1, le=100)

    # --- Cache ---
    CACHE_ENABLED: bool = True
    CACHE_DB_PATH: str = ""   # empty -> ~/.cache/log-triage/cache.db
    CACHE_TTL_HOURS: int = 24

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()