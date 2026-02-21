"""Base interface for AI providers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class AIProviderError(Exception):
    """Raised when an AI provider operation fails."""

    def __init__(self, message: str, provider: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.provider = provider
        self.details = details or {}


class AIProvider(ABC):
    """Abstract base class for AI providers.

    All providers must implement the generate method.
    Providers should never log secrets (API keys, tokens, etc.).
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name for error reporting."""
        ...

    @abstractmethod
    def generate(self, prompt: str, json_mode: bool = False) -> str:
        """Generate a response from the AI model.

        Args:
            prompt: The input prompt to send to the model.
            json_mode: If True, request JSON-formatted output from the model.

        Returns:
            The generated text response.

        Raises:
            AIProviderError: If the provider fails to generate a response.
        """
        ...

    @abstractmethod
    def validate_config(self) -> Optional[str]:
        """Validate that the provider is properly configured.

        Returns:
            None if valid, or an error message string if invalid.
        """
        ...
