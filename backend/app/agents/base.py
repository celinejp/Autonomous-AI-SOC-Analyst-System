"""Base agent class and utilities."""

from typing import Any, Dict, List
from datetime import datetime
import time

from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage

from app.core.config import settings
from app.core.llm_factory import get_llm
from app.core.logging import get_logger

logger = get_logger(__name__)


class BaseAgent:
    """Base class for all SOC agents."""

    def __init__(self, name: str, system_prompt: str, tools: List[Any] = None, temperature: float = 0.1):
        """Initialize agent with LLM model and tools."""
        self.name = name
        self.system_prompt = system_prompt
        self.llm = get_llm(temperature=temperature)
        self.tools = tools or []
        if self.tools:
            self.llm = self.llm.bind_tools(self.tools)

    async def invoke(self, messages: List[BaseMessage]) -> BaseMessage:
        """Invoke the agent with messages."""
        start_time = time.time()
        try:
            response = await self.llm.ainvoke(messages)
            duration_ms = (time.time() - start_time) * 1000
            logger.info(
                f"Agent {self.name} completed",
                agent=self.name,
                duration_ms=duration_ms,
            )
            return response
        except Exception as e:
            logger.error(f"Agent {self.name} error", error=str(e), agent=self.name)
            raise

    def create_messages(
        self, user_input: str, context: Dict[str, Any] = None
    ) -> List[BaseMessage]:
        """Create message list for agent."""
        messages = [SystemMessage(content=self.system_prompt)]
        if context:
            messages.append(
                HumanMessage(content=f"Context: {context}\n\nTask: {user_input}")
            )
        else:
            messages.append(HumanMessage(content=user_input))
        return messages

    def log_execution(
        self,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
        tools_used: List[str] = None,
        reasoning: str = None,
        duration_ms: float = None,
    ) -> Dict[str, Any]:
        """Create execution log entry."""
        return {
            "agent_name": self.name,
            "timestamp": datetime.utcnow().isoformat(),
            "input_data": input_data,
            "output_data": output_data,
            "tools_used": tools_used or [],
            "reasoning": reasoning,
            "duration_ms": duration_ms,
        }

