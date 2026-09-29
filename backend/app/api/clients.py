from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Client, Engagement
from ..schemas import ClientIn, ClientOut, ClientUpdate
from ..services import audit

router = APIRouter(prefix="/api/clients", tags=["clients"])


def _client_out(client: Client, count: int) -> ClientOut:
    out = ClientOut.model_validate(client)
    out.engagement_count = count
    return out


def _get_client(db: Session, client_id: int) -> Client:
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
    return client


def _name_taken(db: Session, name: str) -> bool:
    return db.scalar(select(Client.id).where(Client.name == name)) is not None


@router.get("", response_model=list[ClientOut])
def list_clients(db: Session = Depends(get_db)):
    counts = dict(
        db.execute(select(Engagement.client_id, func.count()).group_by(Engagement.client_id)).all()
    )
    clients = db.scalars(select(Client).order_by(Client.name))
    return [_client_out(c, counts.get(c.id, 0)) for c in clients]


@router.post("", response_model=ClientOut, status_code=201)
def create_client(body: ClientIn, db: Session = Depends(get_db)):
    if _name_taken(db, body.name):
        raise HTTPException(status.HTTP_409_CONFLICT, "A client with that name already exists")
    client = Client(**body.model_dump())
    db.add(client)
    db.flush()
    audit.record(db, action="create", entity_type="client", entity_id=client.id,
                 summary=f"Created client {client.name}")
    db.commit()
    return _client_out(client, 0)


@router.patch("/{client_id}", response_model=ClientOut)
def update_client(client_id: int, body: ClientUpdate, db: Session = Depends(get_db)):
    client = _get_client(db, client_id)
    data = body.model_dump(exclude_unset=True, exclude_none=True)
    if "name" in data and data["name"] != client.name and _name_taken(db, data["name"]):
        raise HTTPException(status.HTTP_409_CONFLICT, "A client with that name already exists")
    for k, v in data.items():
        setattr(client, k, v)
    audit.record(db, action="update", entity_type="client", entity_id=client.id,
                 summary=f"Updated client {client.name}")
    db.commit()
    return _client_out(client, len(client.engagements))


@router.delete("/{client_id}", status_code=204)
def delete_client(client_id: int, db: Session = Depends(get_db)):
    client = _get_client(db, client_id)
    if client.engagements:
        raise HTTPException(status.HTTP_409_CONFLICT, "Client still has engagements")
    db.delete(client)
    audit.record(db, action="delete", entity_type="client", entity_id=client_id,
                 summary=f"Deleted client {client.name}")
    db.commit()
