from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_user, require_admin, require_lead
from ..models import Client, Engagement, EngagementMember, User
from ..schemas import ClientIn, ClientOut, ClientUpdate
from ..services import audit

router = APIRouter(prefix="/api/clients", tags=["clients"])


def _visible_engagements(user: User):
    q = select(Engagement.id, Engagement.client_id)
    if user.role not in ("admin", "lead"):
        q = q.join(EngagementMember).where(EngagementMember.user_id == user.id)
    return q


def _client_out(client: Client, count: int) -> ClientOut:
    out = ClientOut.model_validate(client)
    out.engagement_count = count
    return out


@router.get("", response_model=list[ClientOut])
def list_clients(user: User = Depends(current_user), db: Session = Depends(get_db)):
    visible = _visible_engagements(user).subquery()
    counts = dict(
        db.execute(select(visible.c.client_id, func.count()).group_by(visible.c.client_id)).all()
    )
    q = select(Client).order_by(Client.name)
    if user.role not in ("admin", "lead"):
        q = q.where(Client.id.in_(list(counts)))
    return [_client_out(c, counts.get(c.id, 0)) for c in db.scalars(q)]


@router.post("", response_model=ClientOut, status_code=201)
def create_client(body: ClientIn, request: Request, user: User = Depends(require_lead),
                  db: Session = Depends(get_db)):
    if db.scalar(select(Client).where(Client.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A client with that name already exists")
    client = Client(**body.model_dump())
    db.add(client)
    db.flush()
    audit.record(db, user=user, action="create", entity_type="client", entity_id=client.id,
                 summary=f"Created client {client.name}", request=request)
    db.commit()
    return _client_out(client, 0)


@router.patch("/{client_id}", response_model=ClientOut)
def update_client(client_id: int, body: ClientUpdate, request: Request,
                  user: User = Depends(require_lead), db: Session = Depends(get_db)):
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
    data = body.model_dump(exclude_unset=True, exclude_none=True)
    if "name" in data and data["name"] != client.name and db.scalar(
        select(Client).where(Client.name == data["name"])
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "A client with that name already exists")
    for k, v in data.items():
        setattr(client, k, v)
    audit.record(db, user=user, action="update", entity_type="client", entity_id=client.id,
                 summary=f"Updated client {client.name}", request=request)
    db.commit()
    return _client_out(client, len(client.engagements))


@router.delete("/{client_id}", status_code=204)
def delete_client(client_id: int, request: Request, user: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
    if client.engagements:
        raise HTTPException(status.HTTP_409_CONFLICT, "Client still has engagements")
    db.delete(client)
    audit.record(db, user=user, action="delete", entity_type="client", entity_id=client_id,
                 summary=f"Deleted client {client.name}", request=request)
    db.commit()
