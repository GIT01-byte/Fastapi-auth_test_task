from typing import Optional

from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base

class EmployeesOrm(Base):
    __tablename__ = 'employees' 
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    last_name: Mapped[str]
    phone: Mapped[int]
    image_url: Mapped[Optional[str]] = mapped_column(nullable=True)

