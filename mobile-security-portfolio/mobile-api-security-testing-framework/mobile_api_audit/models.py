
from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    endpoint: str
    detail: str
    recommendation: str
    evidence: str = ""
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
