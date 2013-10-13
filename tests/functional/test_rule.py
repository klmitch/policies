# Copyright (C) 2013 by Kevin L. Mitchell <klmitch@mit.edu>
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see
# <http://www.gnu.org/licenses/>.

import policies

import tests


# Need a user class for our tests
class User(object):
    def __init__(self, name, groups=None, admin=False):
        self.name = name
        self.groups = set(groups or [])
        self.admin = admin

    def __eq__(self, other):
        return self.name == other.name

    def in_group(self, group):
        return group in self.groups


class TestRules(tests.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = policies.Policy()
        cls.policy['is_admin'] = """
            user.in_group("administrators") and user.admin
        """
        cls.policy['user_update'] = """
            user == target or rule("is_admin") {{
                payment=rule("is_admin"),
                name=user == target,
            }}
        """

        cls.alice = User('alice')
        cls.bob = User('bob')
        cls.charlie = User('charlie', ['administrators'])
        cls.charlie_admin = User('charlie', ['administrators'], True)
        cls.deborah = User('deborah', [], True)

    def evaluate(self, user, target):
        return self.policy.evaluate('user_update',
                                    {'user': user, 'target': target})

    def test_same_user(self):
        result = self.evaluate(self.alice, self.alice)

        self.assertTrue(result)
        self.assertFalse(result.payment)
        self.assertTrue(result.name)

    def test_other_user(self):
        result = self.evaluate(self.alice, self.bob)

        self.assertFalse(result)
        self.assertFalse(result.payment)
        self.assertFalse(result.name)

    def test_admin_user_only(self):
        result = self.evaluate(self.charlie, self.bob)

        self.assertFalse(result)
        self.assertFalse(result.payment)
        self.assertFalse(result.name)

    def test_user_privileges(self):
        result = self.evaluate(self.deborah, self.bob)

        self.assertFalse(result)
        self.assertFalse(result.payment)
        self.assertFalse(result.name)

    def test_admin_privileges(self):
        result = self.evaluate(self.charlie_admin, self.bob)

        self.assertTrue(result)
        self.assertTrue(result.payment)
        self.assertFalse(result.name)

    def test_no_rule(self):
        result = self.policy.evaluate('no_such',
                                      {'user': self.alice, 'target': self.bob})

        self.assertFalse(result)
        self.assertEqual(result.payment, None)
        self.assertEqual(result.name, None)
