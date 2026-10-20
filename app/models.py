"""Pydantic models + severity helpers shared across the whole app."""
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    FATAL = "FATAL"
    SECURITY = "SECURITY"

    @classmethod
    def from_token(cls, token: str) -> "SeverityLevel":
        mapping = {
            "DEBUG": cls.DEBUG,
            "INFO": cls.INFO,
            "WARN": cls.WARNING,
            "WARNING": cls.WARNING,
            "ERROR": cls.ERROR,
            "ERR": cls.ERROR,
            "FATAL": cls.FATAL,
            "CRITICAL": cls.FATAL,
            "SECURITY": cls.SECURITY,
            "SEC": cls.SECURITY,
        }
        return mapping.get(token.strip().upper(), cls.INFO)


INCIDENT_SEVERITIES = {
    SeverityLevel.FATAL.value,
    SeverityLevel.ERROR.value,
    SeverityLevel.SECURITY.value,
}


class LogAnalysisRequest(BaseModel):
    log_text: Optional[str] = None
    analysis_type: str = "full"
    model_config = ConfigDict(from_attributes=True)

    @field_validator("analysis_type")
    @classmethod
    def validate_analysis_type(cls, v: str) -> str:
        valid = ["quick", "fast", "full", "detailed"]
        if v.lower() not in valid:
            raise ValueError(f"analysis_type must be one of {valid}")
        return v.lower()


class HealthStatus(BaseModel):
    status: str
    model: str
    available_models: List[str] = Field(default_factory=list)
    provider: str = "groq"
    api_reachable: bool = False
    cache_enabled: bool = True
    last_check: datetime = Field(default_factory=datetime.now)


def create_success_response(data: Dict[str, Any], message: Optional[str] = None) -> Dict[str, Any]:
    return {
        "success": True,
        "data": data,
        "message": message or "Operation completed successfully",
        "timestamp": datetime.now().isoformat(),
    }


def create_error_response(message: str, error: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    response = {
        "success": False,
        "message": message,
        "error": error,
        "timestamp": datetime.now().isoformat(),
    }
    response.update(kwargs)
    return response