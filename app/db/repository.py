from sqlalchemy import Sequence, select
from sqlalchemy.orm import Session

from schemas.employees import EmpoloyeeAddScheme
from db.database import new_session 
from models.employees import EmployeesOrm
from models.users import UsersOrm

class EmpoloyeesRepo():
    @classmethod
    def select_all(cls):
        with new_session() as session:
            query = select(EmployeesOrm)
            result = session.execute(query)
            task_models = result.scalars().all()
            return task_models


    @classmethod
    def select_empoloyee_by_id(cls, empoloyee_id: int):
        with new_session() as session:
            query = select(EmployeesOrm).where(EmployeesOrm.id == empoloyee_id)
            result = session.execute(query)
            task = result.scalars().first()
            return task


    @classmethod
    def insert_empoloyee(cls, data: EmpoloyeeAddScheme):
        with new_session() as session:
            new_employee_dict = data.model_dump()
            new_employee = EmployeesOrm(**new_employee_dict)
            
            session.add(new_employee)
            session.flush()
            session.commit()
            return new_employee.id


class UsersRepo():
    @classmethod
    def select_user_by_username(cls, username: str):
        with new_session() as session:
            query = select(UsersOrm).where(UsersOrm.username == username)
            result = session.execute(query)
            user = result.scalars().first()
            return user


    @classmethod
    def add_user(cls, username: str, password: str):
        with new_session() as session:
            user = UsersOrm(username=username, password=password)

            session.add(user)
            session.commit()
            session.refresh(user)
            return user 
