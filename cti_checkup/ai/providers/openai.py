"""OpenAI and Azure OpenAI provider implementation."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

import httpx

from cti_checkup.ai.providers.base import AIProvider, AIProviderError


class OpenAIProvider(AIProvider):
    """OpenAI API provider.

    Supports both OpenAI and Azure OpenAI endpoints via configuration.
    Never logs API keys or secrets.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: int = 60,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ):
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._temperature = temperature
        self._max_tokens = max_tokens

    @property
    def provider_name(self) -> str:
        return "openai"

    def validate_config(self) -> Optional[str]:
        """Validate OpenAI configuration."""
        if not self._api_key:
            return "Missing API key. Set CTICHECKUP_AI_OPENAI_API_KEY or configure ai.openai_api_key."
        if not self._model:
            return "Missing model. Configure ai.model."
        if not self._base_url:
            return "Missing base_url. Configure ai.base_url."
        return None

    def generate(self, prompt: str, json_mode: bool = False) -> str:
        """Generate response using OpenAI API.

        Args:
            prompt: The input prompt.
            json_mode: If True, request JSON output format.

        Returns:
            Generated text response.

        Raises:
            AIProviderError: On API errors or timeouts.
        """
        validation_error = self.validate_config()
        if validation_error:
            raise AIProviderError(validation_error, self.provider_name)

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        url = f"{self._base_url}/chat/completions"

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()

                choices = data.get("choices", [])
                if not choices:
                    raise AIProviderError(
                        "No choices in API response",
                        self.provider_name,
                        {"response": data},
                    )

                message = choices[0].get("message", {})
                content = message.get("content", "")
                if not content:
                    raise AIProviderError(
                        "Empty content in API response",
                        self.provider_name,
                        {"response": data},
                    )

                return content

        except httpx.TimeoutException as e:
            raise AIProviderError(
                f"Request timed out after {self._timeout}s",
                self.provider_name,
                {"timeout": self._timeout},
            ) from e
        except httpx.HTTPStatusError as e:
            # Never log the full request (contains API key in headers)
            error_body = ""
            try:
                error_body = e.response.text[:500]  # Truncate for safety
            except Exception:
                pass
            raise AIProviderError(
                f"HTTP {e.response.status_code}: {error_body}",
                self.provider_name,
                {"status_code": e.response.status_code},
            ) from e
        except httpx.RequestError as e:
            raise AIProviderError(
                f"Request failed: {str(e)}",
                self.provider_name,
            ) from e
        except json.JSONDecodeError as e:
            raise AIProviderError(
                "Invalid JSON in API response",
                self.provider_name,
            ) from e


class AzureOpenAIProvider(AIProvider):
    """Azure OpenAI API provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        deployment: str = "",
        base_url: str = "",
        api_version: str = "2024-02-15-preview",
        timeout_seconds: int = 60,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ):
        self._api_key = api_key
        self._deployment = deployment
        self._base_url = base_url.rstrip("/")
        self._api_version = api_version
        self._timeout = timeout_seconds
        self._temperature = temperature
        self._max_tokens = max_tokens

    @property
    def provider_name(self) -> str:
        return "azure_openai"

    def validate_config(self) -> Optional[str]:
        """Validate Azure OpenAI configuration."""
        if not self._api_key:
            return "Missing API key. Set CTICHECKUP_AI_AZURE_OPENAI_API_KEY."
        if not self._deployment:
            return "Missing deployment. Configure ai.azure_deployment."
        if not self._base_url:
            return "Missing base_url. Configure ai.base_url for Azure endpoint."
        return None

    def generate(self, prompt: str, json_mode: bool = False) -> str:
        """Generate response using Azure OpenAI API."""
        validation_error = self.validate_config()
        if validation_error:
            raise AIProviderError(validation_error, self.provider_name)

        headers = {
            "api-key": self._api_key,
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        url = (
            f"{self._base_url}/openai/deployments/{self._deployment}"
            f"/chat/completions?api-version={self._api_version}"
        )

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()

                choices = data.get("choices", [])
                if not choices:
                    raise AIProviderError(
                        "No choices in API response",
                        self.provider_name,
                        {"response": data},
                    )

                message = choices[0].get("message", {})
                content = message.get("content", "")
                if not content:
                    raise AIProviderError(
                        "Empty content in API response",
                        self.provider_name,
                        {"response": data},
                    )

                return content

        except httpx.TimeoutException as e:
            raise AIProviderError(
                f"Request timed out after {self._timeout}s",
                self.provider_name,
                {"timeout": self._timeout},
            ) from e
        except httpx.HTTPStatusError as e:
            error_body = ""
            try:
                error_body = e.response.text[:500]
            except Exception:
                pass
            raise AIProviderError(
                f"HTTP {e.response.status_code}: {error_body}",
                self.provider_name,
                {"status_code": e.response.status_code},
            ) from e
        except httpx.RequestError as e:
            raise AIProviderError(
                f"Request failed: {str(e)}",
                self.provider_name,
            ) from e
        except json.JSONDecodeError as e:
            raise AIProviderError(
                "Invalid JSON in API response",
                self.provider_name,
            ) from e


def create_provider(cfg: Dict[str, Any]) -> AIProvider:
    """Factory function to create an AI provider from configuration.

    Args:
        cfg: Full configuration dictionary.

    Returns:
        Configured AIProvider instance.

    Raises:
        AIProviderError: If provider configuration is invalid.
    """
    ai_cfg = cfg.get("ai") or {}
    provider_name = ai_cfg.get("provider", "openai")

    if provider_name == "openai":
        api_key = os.environ.get("CTICHECKUP_AI_OPENAI_API_KEY") or ai_cfg.get("openai_api_key")
        return OpenAIProvider(
            api_key=api_key,
            model=ai_cfg.get("model", "gpt-4o"),
            base_url=ai_cfg.get("base_url", "https://api.openai.com/v1"),
            timeout_seconds=int(ai_cfg.get("timeout_seconds", 60)),
            temperature=float(ai_cfg.get("temperature", 0.3)),
            max_tokens=int(ai_cfg.get("max_tokens", 4096)),
        )
    elif provider_name == "azure_openai":
        api_key = os.environ.get("CTICHECKUP_AI_AZURE_OPENAI_API_KEY") or ai_cfg.get(
            "azure_api_key"
        )
        return AzureOpenAIProvider(
            api_key=api_key,
            deployment=ai_cfg.get("azure_deployment", ""),
            base_url=ai_cfg.get("base_url", ""),
            api_version=ai_cfg.get("azure_api_version", "2024-02-15-preview"),
            timeout_seconds=int(ai_cfg.get("timeout_seconds", 60)),
            temperature=float(ai_cfg.get("temperature", 0.3)),
            max_tokens=int(ai_cfg.get("max_tokens", 4096)),
        )
    elif provider_name == "none":
        raise AIProviderError(
            "AI provider is set to 'none'. AI features are disabled.",
            "none",
        )
    else:
        raise AIProviderError(
            f"Unsupported AI provider: {provider_name}. Supported: openai, azure_openai, none",
            provider_name,
        )
