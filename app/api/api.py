from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from db.repository import EmpoloyeesRepo, UsersRepo

from auth.auth import get_auth_user_username, auth_check_cookie

from schemas.users import UserScheme
from schemas.employees import EmpoloyeeAddScheme


api_router = APIRouter(
    prefix='/test_task/v1',
    )


@api_router.get('/team/get_employees',
    summary='Получить список сотрудников',
    tags=['Employees'],
    )
def get_employees(
    current_user: str = Depends(auth_check_cookie)
    ):
    employees = EmpoloyeesRepo.select_all()
    return {
        'message': f'Текущий пользователь: {current_user}',
        'data': employees,
    }


@api_router.post('/team/add_employees',
    summary='Добавить сотрудника в список сотрудников',
    tags=['Employees'],
    )
def add_employee(
    new_employee: EmpoloyeeAddScheme,
    current_user: str = Depends(auth_check_cookie),
    ):
    new_employee_id = EmpoloyeesRepo.insert_empoloyee(new_employee)
    return {
        'message': f'Текущий пользователь: {current_user}',
        'employee_id': new_employee_id,
    }


@api_router.post('/reg_user',
    summary='Зарегистрировать пользователя',
    tags=['Auth']
    )
def registr_user(user: UserScheme):
    UsersRepo.add_user(
        username=user.username,
        password=user.password,
        )
    
    return{
        'message': f'Добавлен пользователь: {user.username}',
    }

