"""Configuration module for PromptFence.

All settings are read from environment variables with sensible defaults.
This module centralises configuration so that no module needs to hard-code
URLs, model names, timeouts, or credentials.

Environment variables
---------------------
PROMPTFENCE_OLLAMA_BASE_URL : str
    Base URL for the local Ollama instance.  Default: ``http://127.0.0.1:11434``
PROMPTFENCE_OLLAMA_MODEL : str
    Model name to request from Ollama.  Default: ``gemma4:e2b``
PROMPTFENCE_OLLAMA_CONNECT_TIMEOUT : float
    TCP connection timeout in seconds.  Default: ``5.0``
PROMPTFENCE_OLLAMA_READ_TIMEOUT : float
    Response read timeout in seconds.  Default: ``60.0``
PROMPTFENCE_MAX_INPUT_LENGTH : int
    Maximum characters accepted in a scan request.  Default: ``20000``
"""

from __future__ import annotations

import os


def _env_float(key: str, default: float) -> float:
    """Read a float from an environment variable, or return *default*."""
    raw = os.environ.get(key)
    if raw is None:
        return default
    try:
        return float(raw)
    except (ValueError, TypeError):
        return default


def _env_int(key: str, default: int) -> int:
    """Read an int from an environment variable, or return *default*."""
    raw = os.environ.get(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Ollama / LLM settings
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL: str = os.environ.get(
    "PROMPTFENCE_OLLAMA_BASE_URL", "http://127.0.0.1:11434"
)

OLLAMA_MODEL: str = os.environ.get(
    "PROMPTFENCE_OLLAMA_MODEL", "gemma4:e2b"
)

OLLAMA_CONNECT_TIMEOUT: float = _env_float(
    "PROMPTFENCE_OLLAMA_CONNECT_TIMEOUT", 5.0
)

OLLAMA_READ_TIMEOUT: float = _env_float(
    "PROMPTFENCE_OLLAMA_READ_TIMEOUT", 60.0
)

# ---------------------------------------------------------------------------
# Input limits
# ---------------------------------------------------------------------------

MAX_INPUT_LENGTH: int = _env_int(
    "PROMPTFENCE_MAX_INPUT_LENGTH", 20_000
)

#: Maximum input length forwarded to the LLM to prevent memory pressure or model denial of service.
MAX_LLM_INPUT_LENGTH: int = _env_int(
    "PROMPTFENCE_MAX_LLM_INPUT_LENGTH", 10_000
)
