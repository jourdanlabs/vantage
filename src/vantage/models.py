from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Issue:
    file: str
    severity: str          # HIGH | MED | LOW
    description: str
    fix: Optional[str] = None
    line: Optional[int] = None


@dataclass
class Breakdown:
    complexity_score: float
    dependency_score: float
    risk_score: float
    adversarial_score: float


@dataclass
class AuroraVerdict:
    verdict: str           # APPROVED | REJECTED
    score: float           # 0.0 – 1.0
    summary: str
    breakdown: Breakdown
    top_issues: List[Issue] = field(default_factory=list)


@dataclass
class VantageReport:
    verdict: str           # APPROVED | REJECTED
    score: float           # 0.0 – 1.0
    aurora: AuroraVerdict
    file_count: int = 0
    function_count: int = 0
    lines_of_code: int = 0
    todo_count: int = 0
    circular_dep_count: int = 0
    finding_count: int = 0
    raw: dict = field(default_factory=dict)

    @property
    def approved(self) -> bool:
        return self.verdict == "APPROVED"

    @property
    def score_pct(self) -> str:
        return f"{self.score * 100:.1f}%"
