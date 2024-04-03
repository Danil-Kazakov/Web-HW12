from typing import List
from db import get_db
from fastapi import Depends
from sqlalchemy.orm import Session
from models import Contacts
from schemas import ContactBase, ContactResponse


async def get_contacts(skip: int, limit: int, db: Session) -> List[Contacts]:
    return db.query(Contacts).offset(skip).limit(limit).all()


async def get_contact(contact_id: int, db: Session) -> Contacts:
    return db.query(Contacts).filter(Contacts.id == contact_id).first()


async def create_contact(body: ContactResponse, db: Session = Depends(get_db)) -> Contacts:
    contact_data = body.dict()
    contact = Contacts(**contact_data)
    db.add(contact)
    db.commit()
    db.refresh(contact)
    return contact


async def update_contact(contact_id: int, body: ContactResponse, db: Session) -> Contacts | None:
    contact = db.query(Contacts).filter(Contacts.id == contact_id).first()
    if contact:
        for attr, value in body.dict(exclude_unset=True).items():
            setattr(contact, attr, value)
        db.commit()
        db.refresh(contact)

    return contact


async def delete_contact(contact_id: int, db: Session) -> Contacts | None:
    contact = db.query(Contacts).filter(Contacts.id == contact_id).first()
    if contact:
        db.delete(contact)
        db.commit()
    return contact