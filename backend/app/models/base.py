"""Base model classes."""

from pydantic import BaseModel


class BaseResponse(BaseModel):
    """Base API response model."""

    success: bool = True
    message: str = ""


