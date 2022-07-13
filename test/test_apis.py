# -*- coding: utf-8 -*-
# @Author: Tide TAN

import unittest
import time

from rbac.apis import *


class TestApis(unittest.TestCase):

    def test_create_role(self):
        create_role('role1')
        self.assertTrue('role1' in Role.roles)

    def test_role_exists(self):
        with self.assertRaises(Exception) as context:
            create_role('role1')
        self.assertTrue("role already exists" in str(context.exception))

    def test_delete_role(self):
        with self.assertRaises(Exception) as context:
            create_role('role2')
            delete_role('role2')
            Role.get_role('role2')
        self.assertTrue("role doesn't exist" in str(context.exception))

    def test_create_user(self):
        create_user('user1', 'pwd1')
        self.assertTrue('user1' in User.users)

    def test_user_exists(self):
        with self.assertRaises(Exception) as context:
            create_user('user1', 'pwd1')
        self.assertTrue("user already exists" in str(context.exception))

    def test_delete_user(self):
        with self.assertRaises(Exception) as context:
            create_user('user2', 'pwd2')
            delete_user('user2')
            User.get_user('user2')
        self.assertTrue("user doesn't exist" in str(context.exception))

    def test_add_role_to_user(self):
        create_user('user3', 'pwd3')
        create_role('role3')
        create_role('role4')
        add_role_to_user('user3', 'role3')
        add_role_to_user('user3', 'role4')
        user = User.get_user('user3')
        assert user.roles == set(
            [Role.get_role('role3'), Role.get_role('role4')])

    def test_authenticate(self):
        create_user('user4', 'pwd4')
        with self.assertRaises(Exception) as context1:
            authenticate('user4', 'pwd3')
        self.assertTrue("authentication fail" in str(context1.exception))
        with self.assertRaises(Exception) as context2:
            authenticate('user_not_exist', 'pwd3')
        self.assertTrue("user doesn't exist" in str(context2.exception))
        token = authenticate('user4', 'pwd4')
        assert token is not None

    def test_token(self):
        create_user('user5', 'pwd5')
        token = authenticate('user5', 'pwd5')
        user = User.certify_token(token)
        assert user.username == 'user5'

    def test_token_expire(self):
        create_user('user6', 'pwd6')
        # modify expiry time to 2 seconds
        User.EXPIRE = 2
        token = authenticate('user6', 'pwd6')
        time.sleep(3)
        authenticate('user6', 'pwd6')
        with self.assertRaises(Exception) as context:
            user = User.certify_token(token)
        self.assertTrue("token is expired" in str(context.exception))

    def test_invalidate_token(self):
        create_user('user7', 'pwd7')
        token = authenticate('user7', 'pwd7')
        invalidate(token)
        with self.assertRaises(Exception) as context:
            user = User.certify_token(token)
        self.assertTrue("token is invalid" in str(context.exception))

    def test_check_role(self):
        create_user('user8', 'pwd8')
        create_role('role8')
        add_role_to_user('user8', 'role8')
        token = authenticate('user8', 'pwd8')
        self.assertTrue(check_role(token, 'role8'))
        create_role('role88')
        self.assertFalse(check_role(token, 'role88'))

    def test_all_roles(self):
        create_user('user9', 'pwd9')
        create_role('role9')
        add_role_to_user('user9', 'role9')
        create_role('role10')
        add_role_to_user('user9', 'role10')
        token = authenticate('user9', 'pwd9')
        # set have no order
        assert all_roles(token) == 'role9,role10' or all_roles(
            token) == 'role10,role9'
