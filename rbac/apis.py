# -*- coding: utf-8 -*-
# @Author: Tide TAN

from .model import Role, User


def create_user(user_name, password):
    User(user_name, password)

def delete_user(user_name):
    user = User.get_user(user_name)
    user.delete_user()

def create_role(role_name):
    Role(role_name)

def delete_role(role_name):
    role = Role.get_role(role_name)
    role.delete_role()

def add_role_to_user(user_name, role_name):
    user = User.get_user(user_name)
    role = Role.get_role(role_name)
    user.add_role(role)

def authenticate(user_name, password):
    user = User.get_user(user_name)
    return user.authenticate(password)

def invalidate(auth_token):
    user = User.certify_token(auth_token)
    user.invalidate(auth_token)

def check_role(auth_token, role_name):
    user = User.certify_token(auth_token)
    role = Role.get_role(role_name)
    return user.check_role(role)

def all_roles(auth_token):
    user = User.certify_token(auth_token)
    return user.get_roles()