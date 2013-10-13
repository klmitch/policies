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

from policies import authorization

import tests


class TestAuthorization(tests.TestCase):
    def test_init_true(self):
        authz = authorization.Authorization(1)

        self.assertEqual(authz._result, True)
        self.assertEqual(authz._attrs, {})

    def test_init_false(self):
        authz = authorization.Authorization('')

        self.assertEqual(authz._result, False)
        self.assertEqual(authz._attrs, {})

    def test_init_attrs_indep(self):
        attrs = {'a': 1, 'b': 2, 'c': 3}
        authz = authorization.Authorization('', attrs)

        attrs['d'] = 4

        self.assertEqual(authz._attrs, {'a': 1, 'b': 2, 'c': 3})

    def test_getattr(self):
        attrs = {'a': 1, 'b': 2, 'c': 3}
        authz = authorization.Authorization(True, attrs)

        self.assertEqual(authz.a, 1)
        self.assertEqual(authz.b, 2)
        self.assertEqual(authz.c, 3)
        self.assertEqual(authz.d, None)

        authz._attrs['d'] = 4

        self.assertEqual(authz.d, 4)

        self.assertRaises(AttributeError, getattr, authz, '_a')

    def test_setattr(self):
        authz = authorization.Authorization(True, {})

        self.assertRaises(AttributeError, setattr, authz, 'a', 1)

    def test_delattr(self):
        def del_attr(az):
            del az.a

        authz = authorization.Authorization(True, {})

        self.assertRaises(AttributeError, delattr, authz, 'a')

    def test_boolean_true(self):
        authz = authorization.Authorization(True, {})

        self.assertTrue(authz)

    def test_boolean_false(self):
        authz = authorization.Authorization(False, {})

        self.assertFalse(authz)
