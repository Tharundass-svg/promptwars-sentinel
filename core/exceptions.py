"""
Domain exception hierarchy for PromptWars Sentinel.
"""

from __future__ import annotations


class PromptWarsError(Exception):
    """Base exception for all PromptWars Sentinel errors."""
    pass


class ValidationError(PromptWarsError):
    """Raised when an incoming prompt or request fails validation."""
    pass


class PayloadTooLargeError(ValidationError):
    """Raised when a request or prompt exceeds maximum allowable size limits."""
    pass


class InvalidPersonaError(ValidationError):
    """Raised when an unrecognized persona context is specified."""
    pass


class SecurityScanError(PromptWarsError):
    """Raised when an internal error occurs during threat signature scanning."""
    pass
