from enum import Enum


class Severity(str, Enum):
    """Qualitative finding levels; they are not a scientific risk score."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
