# -*- coding: utf-8 -*-
# @Author: Tide TAN

from rbac.apis import *

create_role('role1')
create_role('role2')

create_role('role3')
delete_role('role3')

create_user('user1', 'psw1')
create_user('user2', 'psw2')

create_user('user3', 'psw3')
delete_user('user3')

add_role_to_user('user1', 'role1')
add_role_to_user('user1', 'role2')
token = authenticate('user1','psw1')
print(check_role(token, 'role1'))
print(all_roles(token))
invalidate(token)