from datetime import date

from pydantic import BaseModel, Field, EmailStr


class ContactBase(BaseModel):
    first_name: str
    last_name: str


class ContactResponse(ContactBase):
    id: int
    email: str | EmailStr
    phone_number: str
    born_date: int | date
    another_info: None
