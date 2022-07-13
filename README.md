# rbac demo

A simple role based authentication and authorization service.

## Installation

```bash
$ python3 -m venv venv/
# windows
$ .\venv\Scripts\activate
# unix
$ source ./venv/bin/activate 



# for symmetrical encryption
(venv)$ pip install pycryptodome
(venv)$ pip install pytest
```

## demo

enter the python shell
``` 
(venv)$ python3
```

role creation and assignment of role to a user with authentication and authorization 
```python
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
```

## test
use `py.test` for running the tests
```bash
# windows
$ .\venv\Scripts\py.test.exe
# unix
$ ./venv/bin/py.test
```

## performance

All search about user and role use `set` in python, O(1) complexity.