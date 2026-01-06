import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from fastapi import FastAPI

from sqladmin import Admin, ModelView

from core.models.users import User


class UserAdminView(ModelView, model=User):
    can_create = True
    column_list = ("id", "username" "email", "avatar_links")
    form_columns = ("id", "username" "email", "avatar_links")


def setup_admin(app: FastAPI, engine):
    admin = Admin(app, engine, title="Admin panel")
    admin.add_view(UserAdminView)
