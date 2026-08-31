"""Hierarchical exception classes for the RedOps framework.

Every error raised by the framework inherits from ``RedOpsError`` so that
callers can catch broad or narrow exception families as needed.
"""

from __future__ import annotations


class RedOpsError(Exception):
    """Base exception for all RedOps errors."""

    def __init__(self, message: str = "An unexpected RedOps error occurred") -> None:
        self.message = message
        super().__init__(self.message)


class ConfigurationError(RedOpsError):
    """Raised when application settings are invalid or missing."""

    def __init__(self, detail: str = "Invalid configuration") -> None:
        super().__init__(f"Configuration error: {detail}")


class MSFConnectionError(RedOpsError):
    """Raised when a connection to msfrpcd cannot be established."""

    def __init__(self, host: str = "", port: int = 0) -> None:
        target = f" ({host}:{port})" if host else ""
        super().__init__(f"Cannot connect to Metasploit RPC{target}")


class MSFModuleError(RedOpsError):
    """Raised when an MSF module cannot be loaded or executed."""

    def __init__(self, module_path: str = "", detail: str = "") -> None:
        msg = f"MSF module error: {module_path}"
        if detail:
            msg = f"{msg} — {detail}"
        super().__init__(msg)


class OllamaConnectionError(RedOpsError):
    """Raised when the Ollama API is unreachable."""

    def __init__(self, host: str = "", port: int = 0) -> None:
        target = f" ({host}:{port})" if host else ""
        super().__init__(f"Cannot connect to Ollama{target}")


class OllamaResponseError(RedOpsError):
    """Raised when the LLM returns an invalid or unparseable response."""

    def __init__(self, detail: str = "Malformed LLM response") -> None:
        super().__init__(f"Ollama response error: {detail}")


class ScanError(RedOpsError):
    """Raised when the scanning phase encounters an unrecoverable error."""

    def __init__(self, detail: str = "Scan failed") -> None:
        super().__init__(f"Scan error: {detail}")


class ExploitError(RedOpsError):
    """Raised when an exploitation attempt encounters an unrecoverable error."""

    def __init__(self, module_path: str = "", detail: str = "") -> None:
        msg = f"Exploit error"
        if module_path:
            msg = f"{msg} [{module_path}]"
        if detail:
            msg = f"{msg}: {detail}"
        super().__init__(msg)


class EvasionError(RedOpsError):
    """Raised when the evasion engine encounters an invalid parameter."""

    def __init__(self, detail: str = "Evasion engine failure") -> None:
        super().__init__(f"Evasion error: {detail}")


class ReportError(RedOpsError):
    """Raised when PDF report generation fails."""

    def __init__(self, detail: str = "Report generation failed") -> None:
        super().__init__(f"Report error: {detail}")


class PipelineTimeoutError(RedOpsError):
    """Raised when the pipeline exceeds the global timeout."""

    def __init__(self, timeout_seconds: int = 0) -> None:
        msg = "Pipeline timeout exceeded"
        if timeout_seconds:
            msg = f"{msg} ({timeout_seconds}s)"
        super().__init__(msg)


class CheckpointError(RedOpsError):
    """Raised when checkpoint read/write operations fail."""

    def __init__(self, path: str = "", detail: str = "") -> None:
        msg = "Checkpoint error"
        if path:
            msg = f"{msg} [{path}]"
        if detail:
            msg = f"{msg}: {detail}"
        super().__init__(msg)
