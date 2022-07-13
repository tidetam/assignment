# -*- coding: utf-8 -*-
# @Author: Tide TAN

import hashlib
import time
import base64

from Crypto.Cipher import AES


class Role(object):
    """role class
    """

    # a dict of role instances
    roles = {}

    def __init__(self, name):
        if name in Role.roles:
            raise Exception("role already exists")
        else:
            self.name = name
            Role.roles[name] = self

    def get_role(role_name):
        if role_name not in Role.roles:
            raise Exception("role doesn't exist")
        # add to role instances list after initial
        return Role.roles[role_name]

    def delete_role(self):
        del Role.roles[self.name]


class User(object):
    """user class
    """

    # a dict of user instances
    users = {}

    # key for generate and certify token(16 bytes)
    key = b"1234567812345678"

    # default expire time 2 hour
    EXPIRE = 7200

    def __init__(self, username, password):
        if username in User.users:
            raise Exception("user already exists")
        else:
            self.username = username
            self.password = hashlib.md5(
                bytes(password, encoding='utf8')).hexdigest()
            self.token = None
            self.invalid_token = set()
            self.roles = set()
            # add to user instances list after initial
            User.users[username] = self

    def get_user(user_name):
        if user_name not in User.users:
            raise Exception("user doesn't exist")
        return User.users[user_name]

    def delete_user(self):
        del User.users[self.username]

    def add_role(self, role):
        self.roles.add(role)

    def check_role(self, role):
        return True if role in self.roles else False

    def get_roles(self):
        # return roles' name seperated by ','
        return ','.join([role.name for role in self.roles])

    def authenticate(self, password):
        if hashlib.md5(bytes(password, encoding='utf8')).hexdigest() != self.password:
            raise Exception("authentication fail")
        return self.get_token()

    def get_token(self):
        expire_time = int(time.time()) + User.EXPIRE
        # store information of username and expire time in token
        plain_text = self.username + ':' + str(expire_time)
        plain_text = plain_text.encode('utf8')
        # padding
        while len(plain_text) % 16 != 0:
            plain_text += b'\x00'
        encrypt_text = AES.new(User.key, AES.MODE_ECB).encrypt(plain_text)
        token = base64.b64encode(encrypt_text).decode('utf8')
        return token

    def certify_token(token):
        try:
            encrypt_text = base64.b64decode(token)
            plain_text = AES.new(User.key, AES.MODE_ECB).decrypt(
                encrypt_text).decode('utf8').strip()
        except Exception:
            raise Exception("token is invalid")
        else:
            user_name, expire_time = plain_text.split(':')
            user = User.get_user(user_name)
            if token in user.invalid_token:
                raise Exception("token is invalid")
            if time.time() > int(expire_time):
                raise Exception("token is expired")
            return user

    def invalidate(self, token):
        self.invalid_token.add(token)
