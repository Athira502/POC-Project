from sqlalchemy import Column, String, Integer, DateTime, Boolean
from sqlalchemy.sql import func
from app.models.database import Base

class FilecheckerEntry(Base):
    __tablename__ = "file_checker"
    file_id = Column(Integer, primary_key=True, index=True)
    file_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    date = Column(DateTime, default=func.now())
    parser_value = Column(Boolean, default=False)
