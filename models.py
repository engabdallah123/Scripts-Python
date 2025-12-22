from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime

@dataclass
class VulnerabilityDto:
    type: str
    severity: int
    target: str
    payload: Optional[str]
    description: str
    recommendation: str
    isConfirmed: bool
    detectedAt: str
    scannerName: str


@dataclass
class ScanResultMessage:
    scanId: str
    vulnerabilities: List[VulnerabilityDto]
