"""Application configuration using Pydantic settings."""

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

    # Max seconds to wait for one LLM call before the agent falls back (see llm_factory.ainvoke_llm)
    llm_timeout_seconds: int = 300

    # Ollama Configuration (for local LLM)
    ollama_base_url: str = "http://localhost:11434"  # Default Ollama URL

    # Database
    database_url: str

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Qdrant
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = ""

    # Input limits for submitted logs
    max_upload_bytes: int = 5 * 1024 * 1024
    max_log_lines: int = 5000
    max_log_line_chars: int = 8192

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
