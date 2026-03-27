import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ScanVulnerability:
    """Normalized vulnerability found by any scanner."""
    cve_id: str | None = None
    cvss_score: float = 0.0
    severity: str = "LOW"
    description: str = ""
    affected_host: str = ""
    affected_port: int | None = None
    affected_service: str | None = None
    solution: str = ""
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False
    source_scanner: str = ""
    raw_output: dict = field(default_factory=dict)


class ScannerAdapter(ABC):
    """Abstract base class for all scanner adapters."""

    name: str = "base"

    @abstractmethod
    def scan(self, target: str) -> list[ScanVulnerability]:
        """Run a scan against the target and return normalized vulnerabilities."""
        ...

    def is_available(self) -> bool:
        """Check if the scanner binary is available on the system."""
        return True

    def parse_severity(self, score: float) -> str:
        """Convert a CVSS score to severity string."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def extract_cves(self, text: str) -> list[str]:
        """Extract CVE IDs from text."""
        return re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
