"""Application configuration using Pydantic settings."""

from enum import Enum
from typing import Dict, List
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # LLM Provider Configuration
    llm_provider: str = "ollama"  # Options: ollama, openai, groq, anthropic
    llm_model: str = "default"  # Model name (defaults per provider)
    
    # API Keys (optional based on provider)
    anthropic_api_key: str = ""  # Required if provider=anthropic
    openai_api_key: str = ""  # Required if provider=openai
    groq_api_key: str = ""  # Required if provider=groq
    abuseipdb_api_key: str = ""

    # Ollama Configuration (for local LLM)
    ollama_base_url: str = "http://localhost:11434"  # Default Ollama URL

    # Database
    database_url: str

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Qdrant
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = ""

    # Environment
    environment: str = "development"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()


class OperatingMode(str, Enum):
    """Operating modes for the SOC system."""

    COPILOT = "copilot"  # Suggestions only, human approves all
    SEMI_AUTONOMOUS = "semi_autonomous"  # Auto triage/enrich, human approves responses
    AUTONOMOUS_LAB = "autonomous_lab"  # Full auto in test environment


class AutomationGuardrails(BaseModel):
    """Guardrails for automation based on operating mode."""

    mode: OperatingMode = OperatingMode.SEMI_AUTONOMOUS

    # What can be auto-executed per mode
    allowed_auto_actions: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "copilot": [],
            "semi_autonomous": [
                "block_external_ip",
                "quarantine_file",
                "disable_standard_user",
                "create_ticket",
            ],
            "autonomous_lab": [
                "block_external_ip",
                "quarantine_file",
                "disable_standard_user",
                "disable_admin_account",
                "isolate_endpoint",
                "create_ticket",
                "send_notification",
            ],
        }
    )

    # Thresholds for auto-execution
    min_confidence_for_auto: float = 0.85
    max_severity_for_auto: str = "medium"  # Don't auto-respond to critical without approval

    # Require approval for
    always_require_approval: List[str] = Field(
        default_factory=lambda: [
            "isolate_critical_server",
            "disable_admin_account",
            "notify_external_parties",
            "legal_escalation",
        ]
    )


# Default guardrails
DEFAULT_GUARDRAILS = AutomationGuardrails(
    mode=OperatingMode.SEMI_AUTONOMOUS,
)

