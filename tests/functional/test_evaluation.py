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

import mock
import pyparsing

from policies import parser
from policies import policy

import tests


test_obj = mock.Mock(attr=5)


class TestEvaluation(tests.TestCase):
    rules = [
        # First element is the rule; second is a dictionary of
        # variables to feed to the computation; and third is the
        # expected result
        ('True', {}, True),
        ('False', {}, False),
        ('None', {}, None),
        ('23', {}, 23),
        ('-23', {}, -23),
        ('23.', {}, 23.0),
        ('23.1', {}, 23.1),
        ('-23e1', {}, -230.0),
        ('-23e+1', {}, -230.0),
        ('23e-1', {}, 2.3),
        ('"this is \\" a test"', {}, 'this is " a test'),
        ('foobar', {'foobar': 'foo'}, 'foo'),

        ('{}', {}, frozenset()),
        ('{1, 2, 3}', {}, frozenset([1, 2, 3])),
        ('{1, b, 3}', {'b': 2}, frozenset([1, 2, 3])),
        ('{a, b, c}', {'a': 1, 'b': 2, 'c': 3}, frozenset([1, 2, 3])),

        ('~3', {}, ~3),
        ('~a', {'a': 3}, ~3),

        ('+(3)', {}, +3),
        ('+a', {'a': 3}, +3),

        ('-(3)', {}, -3),
        ('-a', {'a': 3}, -3),

        ('not True', {}, False),
        ('not False', {}, True),
        ('not a', {'a': True}, False),
        ('not a', {'a': False}, True),

        ('3 ** 2', {}, 9),
        ('3 ** b', {'b': 2}, 9),
        ('a ** 2', {'a': 3}, 9),
        ('a ** b', {'a': 3, 'b': 2}, 9),

        ('3 * 2', {}, 6),
        ('3 * b', {'b': 2}, 6),
        ('a * 2', {'a': 3}, 6),
        ('a * b', {'a': 3, 'b': 2}, 6),

        ('3 / 2', {}, 1.5),
        ('3 / b', {'b': 2}, 1.5),
        ('a / 2', {'a': 3}, 1.5),
        ('a / b', {'a': 3, 'b': 2}, 1.5),

        ('3 // 2', {}, 1),
        ('3 // b', {'b': 2}, 1),
        ('a // 2', {'a': 3}, 1),
        ('a // b', {'a': 3, 'b': 2}, 1),

        ('3 % 2', {}, 1),
        ('3 % b', {'b': 2}, 1),
        ('a % 2', {'a': 3}, 1),
        ('a % b', {'a': 3, 'b': 2}, 1),

        ('3 + 2', {}, 5),
        ('3 + b', {'b': 2}, 5),
        ('a + 2', {'a': 3}, 5),
        ('a + b', {'a': 3, 'b': 2}, 5),

        ('3 - 2', {}, 1),
        ('3 - b', {'b': 2}, 1),
        ('a - 2', {'a': 3}, 1),
        ('a - b', {'a': 3, 'b': 2}, 1),

        ('3 << 2', {}, 12),
        ('3 << b', {'b': 2}, 12),
        ('a << 2', {'a': 3}, 12),
        ('a << b', {'a': 3, 'b': 2}, 12),

        ('3 >> 2', {}, 0),
        ('3 >> b', {'b': 2}, 0),
        ('a >> 2', {'a': 3}, 0),
        ('a >> b', {'a': 3, 'b': 2}, 0),

        ('3 & 2', {}, 2),
        ('3 & b', {'b': 2}, 2),
        ('a & 2', {'a': 3}, 2),
        ('a & b', {'a': 3, 'b': 2}, 2),

        ('3 ^ 2', {}, 1),
        ('3 ^ b', {'b': 2}, 1),
        ('a ^ 2', {'a': 3}, 1),
        ('a ^ b', {'a': 3, 'b': 2}, 1),

        ('2 | 1', {}, 3),
        ('2 | b', {'b': 1}, 3),
        ('a | 1', {'a': 2}, 3),
        ('a | b', {'a': 2, 'b': 1}, 3),

        ('3 in {1, 2, 3}', {}, True),
        ('3 in b', {'b': [1, 2, 3]}, True),
        ('a in {1, 2, 3}', {'a': 3}, True),
        ('a in b', {'a': 3, 'b': [1, 2, 3]}, True),
        ('4 in {1, 2, 3}', {}, False),
        ('4 in b', {'b': [1, 2, 3]}, False),
        ('a in {1, 2, 3}', {'a': 4}, False),
        ('a in b', {'a': 4, 'b': [1, 2, 3]}, False),

        ('3 not in {1, 2, 3}', {}, False),
        ('3 not in b', {'b': [1, 2, 3]}, False),
        ('a not in {1, 2, 3}', {'a': 3}, False),
        ('a not in b', {'a': 3, 'b': [1, 2, 3]}, False),
        ('4 not in {1, 2, 3}', {}, True),
        ('4 not in b', {'b': [1, 2, 3]}, True),
        ('a not in {1, 2, 3}', {'a': 4}, True),
        ('a not in b', {'a': 4, 'b': [1, 2, 3]}, True),

        ('3 is 3', {}, True),
        ('3 is b', {'b': 3}, True),
        ('a is 3', {'a': 3}, True),
        ('a is b', {'a': 3, 'b': 3}, True),
        ('3 is 4', {}, False),
        ('3 is b', {'b': 4}, False),
        ('a is 4', {'a': 3}, False),
        ('a is b', {'a': 3, 'b': 4}, False),

        ('3 is not 3', {}, False),
        ('3 is not b', {'b': 3}, False),
        ('a is not 3', {'a': 3}, False),
        ('a is not b', {'a': 3, 'b': 3}, False),
        ('3 is not 4', {}, True),
        ('3 is not b', {'b': 4}, True),
        ('a is not 4', {'a': 3}, True),
        ('a is not b', {'a': 3, 'b': 4}, True),

        ('3 < 4', {}, True),
        ('3 < b', {'b': 4}, True),
        ('a < 4', {'a': 3}, True),
        ('a < b', {'a': 3, 'b': 4}, True),
        ('3 < 3', {}, False),
        ('3 < b', {'b': 3}, False),
        ('a < 3', {'a': 3}, False),
        ('a < b', {'a': 3, 'b': 3}, False),
        ('3 < 2', {}, False),
        ('3 < b', {'b': 2}, False),
        ('a < 2', {'a': 3}, False),
        ('a < b', {'a': 3, 'b': 2}, False),

        ('3 > 4', {}, False),
        ('3 > b', {'b': 4}, False),
        ('a > 4', {'a': 3}, False),
        ('a > b', {'a': 3, 'b': 4}, False),
        ('3 > 3', {}, False),
        ('3 > b', {'b': 3}, False),
        ('a > 3', {'a': 3}, False),
        ('a > b', {'a': 3, 'b': 3}, False),
        ('3 > 2', {}, True),
        ('3 > b', {'b': 2}, True),
        ('a > 2', {'a': 3}, True),
        ('a > b', {'a': 3, 'b': 2}, True),

        ('3 <= 4', {}, True),
        ('3 <= b', {'b': 4}, True),
        ('a <= 4', {'a': 3}, True),
        ('a <= b', {'a': 3, 'b': 4}, True),
        ('3 <= 3', {}, True),
        ('3 <= b', {'b': 3}, True),
        ('a <= 3', {'a': 3}, True),
        ('a <= b', {'a': 3, 'b': 3}, True),
        ('3 <= 2', {}, False),
        ('3 <= b', {'b': 2}, False),
        ('a <= 2', {'a': 3}, False),
        ('a <= b', {'a': 3, 'b': 2}, False),

        ('3 >= 4', {}, False),
        ('3 >= b', {'b': 4}, False),
        ('a >= 4', {'a': 3}, False),
        ('a >= b', {'a': 3, 'b': 4}, False),
        ('3 >= 3', {}, True),
        ('3 >= b', {'b': 3}, True),
        ('a >= 3', {'a': 3}, True),
        ('a >= b', {'a': 3, 'b': 3}, True),
        ('3 >= 2', {}, True),
        ('3 >= b', {'b': 2}, True),
        ('a >= 2', {'a': 3}, True),
        ('a >= b', {'a': 3, 'b': 2}, True),

        ('3 != 4', {}, True),
        ('3 != b', {'b': 4}, True),
        ('a != 4', {'a': 3}, True),
        ('a != b', {'a': 3, 'b': 4}, True),
        ('3 != 3', {}, False),
        ('3 != b', {'b': 3}, False),
        ('a != 3', {'a': 3}, False),
        ('a != b', {'a': 3, 'b': 3}, False),

        ('3 == 4', {}, False),
        ('3 == b', {'b': 4}, False),
        ('a == 4', {'a': 3}, False),
        ('a == b', {'a': 3, 'b': 4}, False),
        ('3 == 3', {}, True),
        ('3 == b', {'b': 3}, True),
        ('a == 3', {'a': 3}, True),
        ('a == b', {'a': 3, 'b': 3}, True),

        ('1 and ""', {}, ''),
        ('0 and ""', {}, 0),
        ('1 and 2', {}, 2),
        ('0 and 2', {}, 0),
        ('1 and b', {'b': ''}, ''),
        ('0 and b', {'b': ''}, 0),
        ('1 and b', {'b': 2}, 2),
        ('0 and b', {'b': 2}, 0),
        ('0 and b', {}, 0),  # verify short-circuiting
        ('a and ""', {'a': 1}, ''),
        ('a and ""', {'a': 0}, 0),
        ('a and 2', {'a': 1}, 2),
        ('a and 2', {'a': 0}, 0),
        ('a and b', {'a': 1, 'b': ''}, ''),
        ('a and b', {'a': 0, 'b': ''}, 0),
        ('a and b', {'a': 1, 'b': 2}, 2),
        ('a and b', {'a': 0, 'b': 2}, 0),
        ('a and b', {'a': 0}, 0),  # verify short-circuiting

        ('1 or ""', {}, 1),
        ('0 or ""', {}, ''),
        ('1 or 2', {}, 1),
        ('0 or 2', {}, 2),
        ('1 or b', {'b': ''}, 1),
        ('0 or b', {'b': ''}, ''),
        ('1 or b', {'b': 2}, 1),
        ('0 or b', {'b': 2}, 2),
        ('1 or b', {}, 1),  # verify short-circuiting
        ('a or ""', {'a': 1}, 1),
        ('a or ""', {'a': 0}, ''),
        ('a or 2', {'a': 1}, 1),
        ('a or 2', {'a': 0}, 2),
        ('a or b', {'a': 1, 'b': ''}, 1),
        ('a or b', {'a': 0, 'b': ''}, ''),
        ('a or b', {'a': 1, 'b': 2}, 1),
        ('a or b', {'a': 0, 'b': 2}, 2),
        ('a or b', {'a': 1}, 1),  # verify short-circuiting

        ('"true" if 1 else "false"', {}, 'true'),
        ('"true" if 0 else "false"', {}, 'false'),
        ('1 + 1 if 1 else 2 + 2', {}, 2),
        ('1 + 1 if 0 else 2 + 2', {}, 4),
        ('"true" if a else "false"', {'a': 1}, 'true'),
        ('"true" if a else "false"', {'a': 0}, 'false'),
        ('1 + 1 if a else 2 + 2', {'a': 1}, 2),
        ('1 + 1 if a else 2 + 2', {'a': 0}, 4),
        # Verify short-circuiting
        ('true if 1 else false', {'true': 'true'}, 'true'),
        ('true if 0 else false', {'false': 'false'}, 'false'),
        ('true if a else false', {'a': 1, 'true': 'true'}, 'true'),
        ('true if a else false', {'a': 0, 'false': 'false'}, 'false'),

        ('1 + 2 * 3 + 4', {}, 11),
        ('a + b * c + d', {'a': 1, 'b': 2, 'c': 3, 'd': 4}, 11),
        ('1 * 2 + 3 * 4', {}, 14),
        ('a * b + c * d', {'a': 1, 'b': 2, 'c': 3, 'd': 4}, 14),

        ('a.attr', {'a': test_obj}, 5),

        ('a[2]', {'a': [0, 1, 2]}, 2),
        ('a[b]', {'a': [0, 1, 2], 'b': 2}, 2),
        ('"test"[2]', {}, 's'),

        ('a(10)', {'a': lambda x: x}, 10),
        ('a(6, 4)', {'a': lambda x, y: (x, y)}, (6, 4)),
        ('a(b)', {'a': lambda x: x, 'b': 10}, 10),
        ('a(b, c)', {'a': lambda x, y: (x, y), 'b': 6, 'c': 4}, (6, 4)),
    ]

    def test_evaluation(self):
        errors = 0
        for text, variables, expected in self.rules:
            try:
                insts = parser.parse_rule("test", text, do_raise=True)
            except pyparsing.ParseException as exc:
                # Print out a description of the unexpected failure
                print('')
                print("Failure to parse %r: %s" % (text, exc))
                print("  Line    : %s" % exc.line)
                print("  Location: %s^" % (" " * (exc.col - 1)))
                errors += 1
                continue

            # Allocate a context and inhibit error reporting
            ctxt = policy.PolicyContext(None, {}, variables)
            ctxt.reported = True

            try:
                with ctxt.push_rule('test'):
                    insts(ctxt, True)
            except Exception as exc:
                # Print out a description of the unexpected failure
                print('')
                print("Failure to evaluate %r: %s" % (text, exc))
                errors += 1
                continue

            # Compare the expected to the actual
            if ctxt.stack[-1] != expected:
                print('')
                print("Failure to evaluate %r: %r != %r" %
                      (text, ctxt.stack[-1], expected))
                errors += 1

        if errors > 0:
            self.fail("Evaluation failures encountered; see output "
                      "for information")
