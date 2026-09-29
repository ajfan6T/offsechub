from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Engagement, Finding
from . import cvss


def next_finding_number(db: Session, engagement_id: int) -> int:
    current = db.scalar(select(func.max(Finding.number)).where(Finding.engagement_id == engagement_id))
    return (current or 0) + 1


def finding_ref(engagement: Engagement, finding: Finding) -> str:
    return f"{engagement.code}-{finding.number:03d}"


def apply_cvss(finding: Finding, vector: str | None, explicit_severity: str | None) -> None:
    """Set vector/score; derive severity from the score unless one was given explicitly.

    Raises ``cvss.CvssError`` for an invalid vector.
    """
    if vector is not None:
        vector = vector.strip()
        if vector:
            result = cvss.calculate(vector)
            finding.cvss_vector = result.vector
            finding.cvss_score = result.score
            if explicit_severity is None:
                finding.severity = result.severity
        else:
            finding.cvss_vector = ""
            finding.cvss_score = None
    if explicit_severity is not None:
        finding.severity = explicit_severity
