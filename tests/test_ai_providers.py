"""Tests for AI providers."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cti_checkup.ai.providers.base import AIProviderError
from cti_checkup.ai.providers.openai import (
    OpenAIProvider,
    AzureOpenAIProvider,
    create_provider,
)


class TestOpenAIProvider:
    """Tests for the OpenAI provider."""

    def test_validate_config_missing_api_key(self):
        """Test validation fails without API key."""
        provider = OpenAIProvider(api_key=None, model="gpt-4o")
        error = provider.validate_config()
        assert error is not None
        assert "api key" in error.lower()

    def test_validate_config_valid(self):
        """Test validation passes with valid config."""
        provider = OpenAIProvider(
            api_key="sk-test-key",
            model="gpt-4o",
            base_url="https://api.openai.com/v1",
        )
        error = provider.validate_config()
        assert error is None

    def test_provider_name(self):
        """Test provider name property."""
        provider = OpenAIProvider(api_key="test")
        assert provider.provider_name == "openai"

    @patch("httpx.Client")
    def test_generate_success(self, mock_client_class):
        """Test successful API call."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Test response"}}]
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
        result = provider.generate("Test prompt")

        assert result == "Test response"
        mock_client.post.assert_called_once()

    @patch("httpx.Client")
    def test_generate_json_mode(self, mock_client_class):
        """Test JSON mode is included in request."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"test": "response"}'}}]
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
        provider.generate("Test prompt", json_mode=True)

        # Verify response_format was included in the request
        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json")
        assert payload.get("response_format") == {"type": "json_object"}


class TestAzureOpenAIProvider:
    """Tests for the Azure OpenAI provider."""

    def test_validate_config_missing_deployment(self):
        """Test validation fails without deployment."""
        provider = AzureOpenAIProvider(
            api_key="test-key",
            deployment="",
            base_url="https://myresource.openai.azure.com",
        )
        error = provider.validate_config()
        assert error is not None
        assert "deployment" in error.lower()

    def test_validate_config_valid(self):
        """Test validation passes with valid config."""
        provider = AzureOpenAIProvider(
            api_key="test-key",
            deployment="gpt-4",
            base_url="https://myresource.openai.azure.com",
        )
        error = provider.validate_config()
        assert error is None

    def test_provider_name(self):
        """Test provider name property."""
        provider = AzureOpenAIProvider(api_key="test")
        assert provider.provider_name == "azure_openai"


class TestCreateProvider:
    """Tests for the provider factory function."""

    def test_create_openai_provider(self):
        """Test creating an OpenAI provider."""
        cfg = {
            "ai": {
                "provider": "openai",
                "model": "gpt-4o",
                "base_url": "https://api.openai.com/v1",
            }
        }
        with patch.dict("os.environ", {"CTICHECKUP_AI_OPENAI_API_KEY": "sk-test"}):
            provider = create_provider(cfg)
            assert isinstance(provider, OpenAIProvider)
            assert provider.provider_name == "openai"

    def test_create_azure_provider(self):
        """Test creating an Azure OpenAI provider."""
        cfg = {
            "ai": {
                "provider": "azure_openai",
                "azure_deployment": "gpt-4",
                "base_url": "https://myresource.openai.azure.com",
            }
        }
        with patch.dict("os.environ", {"CTICHECKUP_AI_AZURE_OPENAI_API_KEY": "test-key"}):
            provider = create_provider(cfg)
            assert isinstance(provider, AzureOpenAIProvider)
            assert provider.provider_name == "azure_openai"

    def test_create_none_provider(self):
        """Test that 'none' provider raises error."""
        cfg = {"ai": {"provider": "none"}}
        with pytest.raises(AIProviderError) as exc_info:
            create_provider(cfg)
        assert "disabled" in str(exc_info.value).lower()

    def test_create_unsupported_provider(self):
        """Test that unsupported provider raises error."""
        cfg = {"ai": {"provider": "anthropic"}}
        with pytest.raises(AIProviderError) as exc_info:
            create_provider(cfg)
        assert "unsupported" in str(exc_info.value).lower()


class TestAIProviderError:
    """Tests for the AIProviderError exception."""

    def test_error_has_provider(self):
        """Test that error includes provider name."""
        error = AIProviderError("Test error", "openai", {"key": "value"})
        assert error.provider == "openai"
        assert error.details == {"key": "value"}
        assert str(error) == "Test error"
