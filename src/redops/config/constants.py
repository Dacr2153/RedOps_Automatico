"""Enumerations, curated exploit catalogs and threshold constants.

Every magic number or configurable constant used across the framework lives
here so that no module ever hardcodes a value.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


# ── PTES phase lifecycle ────────────────────────────────────────────
class PTESPhase(str, Enum):
    """Phases of the Penetration Testing Execution Standard."""

    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    REPORT = "report"


# ── Evasion profiles ───────────────────────────────────────────────
class EvasionProfile(str, Enum):
    """IDS evasion aggressiveness levels."""

    STEALTH = "stealth"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


# ── Severity labels ────────────────────────────────────────────────
class Severity(str, Enum):
    """CVSSv3.1 qualitative severity ratings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ── Exploit result status ──────────────────────────────────────────
class ExploitStatus(str, Enum):
    """Possible outcomes of an exploit attempt."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


# ── Curated MSF Modules for Metasploitable2 ───────────────────────
MSF_MODULES_CATALOG: dict[str, dict[str, Any]] = {
    "vsftpd_234": {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "options": {"RHOSTS": None, "RPORT": 21},
        "payload": "cmd/unix/interact",
        "description": "vsftpd 2.3.4 backdoor (CVE-2011-2523)",
        "cvss_base": 10.0,
        "cve": "CVE-2011-2523",
        "service_match": "vsftpd",
        "port_match": 21,
    },
    "samba_usermap": {
        "module": "exploit/multi/samba/usermap_script",
        "options": {"RHOSTS": None, "RPORT": 139},
        "payload": "cmd/unix/reverse_netcat",
        "description": "Samba usermap_script (CVE-2007-2447)",
        "cvss_base": 10.0,
        "cve": "CVE-2007-2447",
        "service_match": "samba",
        "port_match": 139,
    },
    "distcc_exec": {
        "module": "exploit/unix/misc/distcc_exec",
        "options": {"RHOSTS": None, "RPORT": 3632},
        "payload": "cmd/unix/reverse_bash",
        "description": "DistCC Daemon Command Execution (CVE-2004-2687)",
        "cvss_base": 9.3,
        "cve": "CVE-2004-2687",
        "service_match": "distccd",
        "port_match": 3632,
    },
    "php_cgi": {
        "module": "exploit/multi/http/php_cgi_arg_injection",
        "options": {"RHOSTS": None, "RPORT": 80},
        "payload": "php/meterpreter/reverse_tcp",
        "description": "PHP CGI Argument Injection (CVE-2012-1823)",
        "cvss_base": 7.5,
        "cve": "CVE-2012-1823",
        "service_match": "http",
        "port_match": 80,
    },
    "unreal_ircd": {
        "module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "options": {"RHOSTS": None, "RPORT": 6667},
        "payload": "cmd/unix/reverse_bash",
        "description": "UnrealIRCd Backdoor (CVE-2010-2075)",
        "cvss_base": 7.5,
        "cve": "CVE-2010-2075",
        "service_match": "ircd",
        "port_match": 6667,
    },
}

# ── CVSS v3.1 severity thresholds ──────────────────────────────────
CVSS_THRESHOLDS: dict[str, tuple[float, float]] = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9),
    "INFO": (0.0, 0.0),
}

# ── Evasion profile timing configurations ──────────────────────────
EVASION_PROFILES: dict[EvasionProfile, dict[str, Any]] = {
    EvasionProfile.STEALTH: {
        "min_delay": 3.0,
        "max_delay": 8.0,
        "fragment_size": 8,
        "use_decoys": True,
    },
    EvasionProfile.BALANCED: {
        "min_delay": 1.0,
        "max_delay": 3.0,
        "fragment_size": 16,
        "use_decoys": False,
    },
    EvasionProfile.AGGRESSIVE: {
        "min_delay": 0.1,
        "max_delay": 0.5,
        "fragment_size": 32,
        "use_decoys": False,
    },
}

# ── Banner grab target ports ───────────────────────────────────────
BANNER_GRAB_PORTS: list[int] = [
    21, 22, 23, 25, 80, 139, 443, 445, 3306, 8080,
]

# ── UDP critical ports ─────────────────────────────────────────────
UDP_CRITICAL_PORTS: list[int] = [53, 67, 68, 69, 161, 162, 500]

# ── MITRE ATT&CK mapping for known exploits ───────────────────────
MITRE_ATTACK_MAP: dict[str, dict[str, str]] = {
    "CVE-2011-2523": {"technique": "T1190", "name": "Exploit Public-Facing Application"},
    "CVE-2007-2447": {"technique": "T1210", "name": "Exploitation of Remote Services"},
    "CVE-2004-2687": {"technique": "T1210", "name": "Exploitation of Remote Services"},
    "CVE-2012-1823": {"technique": "T1190", "name": "Exploit Public-Facing Application"},
    "CVE-2010-2075": {"technique": "T1190", "name": "Exploit Public-Facing Application"},
}
