from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import (
    EngagementAccess,
    current_user,
    engagement_reader,
    engagement_writer,
    get_or_404,
)
from ..models import EngagementMember, Finding, Target, TestCase
from ..schemas import (
    ApplyMethodologyIn,
    MethodologyOut,
    TestCaseIn,
    TestCaseOut,
    TestCaseUpdate,
)
from ..services import audit
from ..services.methodologies import load_methodologies

router = APIRouter(tags=["testing"])


@router.get("/api/methodologies", response_model=list[MethodologyOut])
def list_methodologies(_=Depends(current_user)):
    return [
        MethodologyOut(
            id=m["id"],
            name=m["name"],
            description=m.get("description", ""),
            case_count=len(m["cases"]),
            categories=list(dict.fromkeys(c["category"] for c in m["cases"])),
        )
        for m in load_methodologies().values()
    ]


def _validate_links(db: Session, access: EngagementAccess, data: dict) -> None:
    eid = access.engagement.id
    if data.get("target_id") is not None:
        get_or_404(db, Target, data["target_id"], eid)
    if data.get("finding_id") is not None:
        get_or_404(db, Finding, data["finding_id"], eid)
    if data.get("assignee_id") is not None and db.get(EngagementMember, (eid, data["assignee_id"])) is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Assignee must be an engagement member")


prefix = "/api/engagements/{engagement_id}/tests"


@router.get(prefix, response_model=list[TestCaseOut])
def list_tests(access: EngagementAccess = Depends(engagement_reader), db: Session = Depends(get_db)):
    return db.scalars(
        select(TestCase)
        .where(TestCase.engagement_id == access.engagement.id)
        .order_by(TestCase.methodology, TestCase.id)
    ).all()


@router.post(prefix + "/apply", response_model=list[TestCaseOut], status_code=201)
def apply_methodology(body: ApplyMethodologyIn, request: Request,
                      access: EngagementAccess = Depends(engagement_writer),
                      db: Session = Depends(get_db)):
    """Copy a methodology's checklist into the engagement (idempotent per ref/target)."""
    methodology = load_methodologies().get(body.methodology_id)
    if methodology is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Methodology not found")
    eid = access.engagement.id
    if body.target_id is not None:
        get_or_404(db, Target, body.target_id, eid)
    existing = {
        (t.ref, t.target_id)
        for t in db.scalars(
            select(TestCase).where(TestCase.engagement_id == eid,
                                   TestCase.methodology == methodology["id"])
        )
    }
    created = []
    for case in methodology["cases"]:
        if (case["ref"], body.target_id) in existing:
            continue
        tc = TestCase(
            engagement_id=eid,
            methodology=methodology["id"],
            ref=case["ref"],
            category=case["category"],
            title=case["title"],
            description=case.get("description", ""),
            target_id=body.target_id,
        )
        db.add(tc)
        created.append(tc)
    db.flush()
    audit.record(db, user=access.user, action="create", entity_type="test_case",
                 engagement_id=eid,
                 summary=f"Applied {methodology['name']} ({len(created)} test cases)",
                 request=request)
    db.commit()
    return created


@router.post(prefix, response_model=TestCaseOut, status_code=201)
def create_test(body: TestCaseIn, request: Request,
                access: EngagementAccess = Depends(engagement_writer),
                db: Session = Depends(get_db)):
    data = body.model_dump()
    _validate_links(db, access, data)
    tc = TestCase(engagement_id=access.engagement.id, **data)
    db.add(tc)
    db.flush()
    audit.record(db, user=access.user, action="create", entity_type="test_case", entity_id=tc.id,
                 engagement_id=access.engagement.id, summary=f"Added test case {tc.title}",
                 request=request)
    db.commit()
    db.refresh(tc)
    return tc


@router.patch(prefix + "/{test_id}", response_model=TestCaseOut)
def update_test(test_id: int, body: TestCaseUpdate, request: Request,
                access: EngagementAccess = Depends(engagement_writer),
                db: Session = Depends(get_db)):
    tc = get_or_404(db, TestCase, test_id, access.engagement.id)
    # Nullable links may be cleared explicitly with null, so keep unset/None distinct.
    data = body.model_dump(exclude_unset=True)
    _validate_links(db, access, data)
    for k, v in data.items():
        if v is None and k not in ("assignee_id", "target_id", "finding_id"):
            continue
        setattr(tc, k, v)
    summary = f"Updated {tc.ref or 'test'} {tc.title}"
    if "status" in data:
        summary += f" -> {tc.status}"
    audit.record(db, user=access.user, action="update", entity_type="test_case", entity_id=tc.id,
                 engagement_id=access.engagement.id, summary=summary, request=request)
    db.commit()
    db.refresh(tc)
    return tc


@router.delete(prefix + "/{test_id}", status_code=204)
def delete_test(test_id: int, request: Request,
                access: EngagementAccess = Depends(engagement_writer),
                db: Session = Depends(get_db)):
    tc = get_or_404(db, TestCase, test_id, access.engagement.id)
    db.delete(tc)
    audit.record(db, user=access.user, action="delete", entity_type="test_case", entity_id=test_id,
                 engagement_id=access.engagement.id, summary=f"Deleted test case {tc.title}",
                 request=request)
    db.commit()
