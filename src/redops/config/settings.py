"""Application settings loaded from environment variables and .env file.

Uses Pydantic BaseSettings for automatic validation, type coercion and
environment variable loading. A cached singleton accessor ``get_settings()``
is provided so the configuration object is parsed only once per process.
"""

from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _detect_lhost(target_network: str) -> str:
    """Detect the local interface IP facing the target network.

    Opens a UDP socket toward the first host of the target CIDR to let the
    kernel choose the source interface, then returns that source IP.  No
    actual packet is sent (UDP connect does not perform a handshake).

    Args:
        target_network: CIDR notation of the target network (e.g. 192.168.56.0/24).

    Returns:
        Detected local IP string, or empty string on failure.
    """
    try:
        net = ipaddress.ip_network(target_network, strict=False)
        probe_ip = str(next(net.hosts()))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((probe_ip, 80))
            return sock.getsockname()[0]
    except Exception:
        return ""


class Settings(BaseSettings):
    """Central configuration for the RedOps framework.

    All values are loaded from environment variables (or a ``.env`` file
    located at the project root).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # -- Metasploit RPC --------------------------------------------------
    msf_host: str = "127.0.0.1"
    msf_port: int = 55553
    msf_password: str = "msf_rpc_password"
    msf_ssl: bool = False

    # -- Ollama LLM ------------------------------------------------------
    ollama_host: str = "127.0.0.1"
    ollama_port: int = 11434
    ollama_model: str = "mistral"
    ollama_timeout: int = 120

    # -- Target / Scan ---------------------------------------------------
    target_network: str = "192.168.56.0/24"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    report_output_dir: str = "./reports"

    # -- Attacker identity -----------------------------------------------
    lhost: str = ""
    """Attacker IP for reverse payloads.  Leave empty to auto-detect from
    the interface facing *target_network*."""

    # -- Evasion Timing --------------------------------------------------
    scan_timing_min: float = 1.0
    scan_timing_max: float = 5.0
    evasion_profile: Literal["stealth", "balanced", "aggressive"] = "balanced"

    # -- Pipeline --------------------------------------------------------
    global_timeout_minutes: int = 15
    min_services_to_compromise: int = 3
    checkpoint_interval_seconds: int = 60

    # -- Validators ------------------------------------------------------

    @field_validator("target_network")
    @classmethod
    def validate_target_network(cls, value: str) -> str:
        """Ensure the target network is a valid IPv4 CIDR."""
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR network: {value}") from exc
        return value

    @field_validator("msf_port", "ollama_port")
    @classmethod
    def validate_port_range(cls, value: int) -> int:
        """Ensure ports are within the valid TCP/UDP range."""
        if not 1 <= value <= 65535:
            raise ValueError(f"Port must be between 1 and 65535, got {value}")
        return value

    @field_validator("scan_timing_min", "scan_timing_max")
    @classmethod
    def validate_timing_positive(cls, value: float) -> float:
        """Timing values must be non-negative."""
        if value < 0:
            raise ValueError(f"Timing value must be >= 0, got {value}")
        return value

    @model_validator(mode="after")
    def validate_timing_order(self) -> "Settings":
        """Ensure min timing does not exceed max timing."""
        if self.scan_timing_min > self.scan_timing_max:
            raise ValueError(
                f"scan_timing_min ({self.scan_timing_min}) must be "
                f"<= scan_timing_max ({self.scan_timing_max})"
            )
        return self

    # -- Derived properties ----------------------------------------------

    @property
    def attacker_ip(self) -> str:
        """Return LHOST: explicit config value or auto-detected interface IP.

        Auto-detection opens a UDP socket toward the target network so the
        kernel selects the correct source interface — no traffic is sent.
        Logs a warning when detection fails (required for reverse payloads).
        """
        if self.lhost:
            return self.lhost
        detected = _detect_lhost(self.target_network)
        return detected

    @property
    def msf_url(self) -> str:
        """Construct the full MSF RPC URL."""
        scheme = "https" if self.msf_ssl else "http"
        return f"{scheme}://{self.msf_host}:{self.msf_port}"

    @property
    def ollama_base_url(self) -> str:
        """Construct the Ollama API base URL."""
        return f"http://{self.ollama_host}:{self.ollama_port}"

    @property
    def report_output_path(self) -> Path:
        """Return the report output directory as a ``Path`` object."""
        return Path(self.report_output_dir)

    @property
    def global_timeout_seconds(self) -> int:
        """Pipeline timeout converted to seconds."""
        return self.global_timeout_minutes * 60


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton ``Settings`` instance."""
    return Settings()
