from sqlalchemy import Column, Integer, String, Boolean, func, Table, create_engine
from sqlalchemy.orm import relationship
from sqlalchemy.sql.schema import ForeignKey
from sqlalchemy.sql.sqltypes import DateTime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Contacts(Base):
    __tablename__ = 'contacts'
    id = Column(Integer, primary_key=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String)
    phone_number = Column(Integer)
    born_date = Column(Integer)
    another_info = Column(String, default=None)


engine = create_engine('postgresql+psycopg2://postgres:567432@localhost:5432/hw')
Base.metadata.create_all(engine)
