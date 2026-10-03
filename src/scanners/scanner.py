"""Shared types and interface for analysis checks."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from src.enums.severity import Severity
from urllib.parse import SplitResult


@dataclass(frozen=True)
class Finding:
    """One understandable observation produced by a security check."""

    check_id: str
    severity: Severity
    title: str
    description: str
    evidence: str
    remediation: str


class Scanner(ABC):
    """Contract shared by scanners; scanners report findings, not terminal text."""

    @abstractmethod
    def scan(self, target: SplitResult) -> list[Finding]:
        """Analyze one validated target and return its findings."""
        raise NotImplementedError


class ScanError(Exception):
    """A target could not be scanned safely or the request failed."""
