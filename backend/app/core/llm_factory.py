"""LLM Provider Factory - Supports multiple LLM providers."""

from typing import Optional
from langchain_core.language_models.chat_models import BaseChatModel

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def get_llm(
    model_name: Optional[str] = None,
    temperature: float = 0.1,
    provider: Optional[str] = None,
) -> BaseChatModel:
    """
    Get LLM instance based on provider configuration.
    
    Supported providers:
    - ollama: Free, local (requires Ollama installed)
    - openai: OpenAI API (free tier available)
    - groq: Groq API (free tier available)
    - anthropic: Claude API (paid)
    
    Args:
        model_name: Specific model name (optional, uses default for provider)
        temperature: Temperature setting
        provider: Provider name (optional, uses LLM_PROVIDER from config)
        
    Returns:
        BaseChatModel instance
    """
    provider = provider or settings.llm_provider.lower()
    model_name = model_name or settings.llm_model
    
    logger.info(f"Initializing LLM", provider=provider, model=model_name)
    
    if provider == "ollama":
        return _get_ollama_llm(model_name, temperature)
    elif provider == "openai":
        return _get_openai_llm(model_name, temperature)
    elif provider == "groq":
        return _get_groq_llm(model_name, temperature)
    elif provider == "anthropic":
        return _get_anthropic_llm(model_name, temperature)
    else:
        # Default to Ollama (free option)
        logger.warning(f"Unknown provider {provider}, defaulting to Ollama")
        return _get_ollama_llm(model_name, temperature)


def _get_ollama_llm(model_name: str, temperature: float) -> BaseChatModel:
    """Get Ollama LLM (free, local)."""
    try:
        from langchain_ollama import ChatOllama
        
        # Default models if not specified
        if not model_name or model_name == "default":
            model_name = "llama3.1"  # Good free model
        
        return ChatOllama(
            model=model_name,
            temperature=temperature,
            base_url=settings.ollama_base_url,
        )
    except ImportError:
        raise ImportError(
            "langchain-ollama not installed. Install with: pip install langchain-ollama"
        )


def _get_openai_llm(model_name: str, temperature: float) -> BaseChatModel:
    """Get OpenAI LLM (free tier available for GPT-3.5)."""
    try:
        from langchain_openai import ChatOpenAI
        
        if not model_name or model_name == "default":
            model_name = "gpt-3.5-turbo"  # Free tier model
        
        if not settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY not set in environment")
        
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=settings.openai_api_key,
        )
    except ImportError:
        raise ImportError(
            "langchain-openai not installed. Install with: pip install langchain-openai"
        )


def _get_groq_llm(model_name: str, temperature: float) -> BaseChatModel:
    """Get Groq LLM (free tier available, very fast)."""
    try:
        from langchain_groq import ChatGroq
        
        if not model_name or model_name == "default":
            model_name = "llama-3.1-70b-versatile"  # Fast free model
        
        if not settings.groq_api_key:
            raise ValueError("GROQ_API_KEY not set in environment")
        
        return ChatGroq(
            model=model_name,
            temperature=temperature,
            groq_api_key=settings.groq_api_key,
        )
    except ImportError:
        raise ImportError(
            "langchain-groq not installed. Install with: pip install langchain-groq"
        )


def _get_anthropic_llm(model_name: str, temperature: float) -> BaseChatModel:
    """Get Anthropic Claude LLM (paid)."""
    try:
        from langchain_anthropic import ChatAnthropic
        
        if not model_name or model_name == "default":
            model_name = "claude-sonnet-4-20250514"
        
        if not settings.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY not set in environment")
        
        return ChatAnthropic(
            model=model_name,
            temperature=temperature,
            anthropic_api_key=settings.anthropic_api_key,
        )
    except ImportError:
        raise ImportError(
            "langchain-anthropic not installed. Install with: pip install langchain-anthropic"
        )

