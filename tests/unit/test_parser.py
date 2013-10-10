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

import pyparsing
import mock

from policies.instructions import *
from policies import parser

import tests


class TestUnaryConstruct(tests.TestCase):
    def test_call(self):
        result = parser.unary_construct([inv_op, Ident('a')])

        self.assertEqual(result, [Instructions([Ident('a'), inv_op])])


class TestBinaryConstruct(tests.TestCase):
    def test_one_sequence(self):
        result = parser.binary_construct([Ident('a'), add_op, Constant(2)])

        self.assertEqual(result, [Instructions([
            Ident('a'), Constant(2), add_op,
        ])])

    def test_multi_sequence(self):
        result = parser.binary_construct([
            Ident('a'), add_op, Constant(2), add_op, Ident('b'), add_op,
            Constant(3),
        ])

        self.assertEqual(result, [Instructions([
            Ident('a'), Constant(2), add_op, Ident('b'), add_op, Constant(3),
            add_op,
        ])])


class TestParseRule(tests.TestCase):
    @mock.patch('logging.getLogger')
    @mock.patch.object(parser.rule, 'parseString', return_value=['success'])
    def test_success(self, mock_parseString, mock_getLogger):
        result = parser.parse_rule('test', 'rule text')

        self.assertEqual(result, 'success')
        mock_parseString.assert_called_once_with('rule text', parseAll=True)
        self.assertFalse(mock_getLogger.called)

    @mock.patch('logging.getLogger')
    @mock.patch.object(parser.rule, 'parseString',
                       side_effect=pyparsing.ParseException(
                           "test rule string", loc=5, msg="trial error"))
    def test_failure(self, mock_parseString, mock_getLogger):
        result = parser.parse_rule('test', 'rule text')

        self.assertEqual(result, Instructions([Constant(False), set_authz]))
        mock_parseString.assert_called_once_with('rule text', parseAll=True)
        mock_getLogger.assert_called_once_with('policies')
        mock_getLogger.return_value.assert_has_calls([
            mock.call.warn("Failed to parse rule 'test': "
                           "trial error (at char 5), (line:1, col:6)"),
            mock.call.warn("Rule line: test rule string"),
            mock.call.warn("Location :      ^"),
        ])

    @mock.patch('logging.getLogger')
    @mock.patch.object(parser.rule, 'parseString',
                       side_effect=pyparsing.ParseException(
                           "test rule string", loc=5, msg="trial error"))
    def test_raise(self, mock_parseString, mock_getLogger):
        self.assertRaises(pyparsing.ParseException,
                          parser.parse_rule, 'test', 'rule text',
                          do_raise=True)

        mock_parseString.assert_called_once_with('rule text', parseAll=True)
        self.assertFalse(mock_getLogger.called)

    rules = [
        ('True', Instructions([Constant(True), set_authz])),
        ('False', Instructions([Constant(False), set_authz])),
        ('None', Instructions([Constant(None), set_authz])),
        ('23', Instructions([Constant(23), set_authz])),
        ('-23', Instructions([Constant(-23), set_authz])),
        ('23.', Instructions([Constant(23.0), set_authz])),
        ('23.1', Instructions([Constant(23.1), set_authz])),
        ('-23e1', Instructions([Constant(-230.0), set_authz])),
        ('-23e+1', Instructions([Constant(-230.0), set_authz])),
        ('23e-1', Instructions([Constant(2.3), set_authz])),
        ('"this is \\" a test"', Instructions([
            Constant('this is " a test'), set_authz,
        ])),
        ('"string " "concatenation"', Instructions([
            Constant('string concatenation'), set_authz,
        ])),
        ('foobar', Instructions([Ident('foobar'), set_authz])),
        ('~a', Instructions([Ident('a'), inv_op, set_authz])),
        ('+a', Instructions([Ident('a'), pos_op, set_authz])),
        ('-a', Instructions([Ident('a'), neg_op, set_authz])),
        ('not a', Instructions([Ident('a'), not_op, set_authz])),
        ('a ** b', Instructions([Ident('a'), Ident('b'), pow_op, set_authz])),
        ('a * b', Instructions([Ident('a'), Ident('b'), mul_op, set_authz])),
        ('a / b', Instructions([
            Ident('a'), Ident('b'), true_div_op, set_authz,
        ])),
        ('a // b', Instructions([
            Ident('a'), Ident('b'), floor_div_op, set_authz,
        ])),
        ('a % b', Instructions([Ident('a'), Ident('b'), mod_op, set_authz])),
        ('a + b', Instructions([Ident('a'), Ident('b'), add_op, set_authz])),
        ('a - b', Instructions([Ident('a'), Ident('b'), sub_op, set_authz])),
        ('a + -2', Instructions([
            Ident('a'), Constant(-2), add_op, set_authz,
        ])),
        ('a << b', Instructions([
            Ident('a'), Ident('b'), left_shift_op, set_authz,
        ])),
        ('a >> b', Instructions([
            Ident('a'), Ident('b'), right_shift_op, set_authz,
        ])),
        ('a & b', Instructions([
            Ident('a'), Ident('b'), bit_and_op, set_authz,
        ])),
        ('a ^ b', Instructions([
            Ident('a'), Ident('b'), bit_xor_op, set_authz,
        ])),
        ('a | b', Instructions([
            Ident('a'), Ident('b'), bit_or_op, set_authz,
        ])),
        ('a in b', Instructions([Ident('a'), Ident('b'), in_op, set_authz])),
        ('a not in b', Instructions([
            Ident('a'), Ident('b'), not_in_op, set_authz,
        ])),
        ('a is b', Instructions([Ident('a'), Ident('b'), is_op, set_authz])),
        ('a is not b', Instructions([
            Ident('a'), Ident('b'), is_not_op, set_authz,
        ])),
        ('a < b', Instructions([Ident('a'), Ident('b'), lt_op, set_authz])),
        ('a > b', Instructions([Ident('a'), Ident('b'), gt_op, set_authz])),
        ('a <= b', Instructions([Ident('a'), Ident('b'), le_op, set_authz])),
        ('a >= b', Instructions([Ident('a'), Ident('b'), ge_op, set_authz])),
        ('a != b', Instructions([Ident('a'), Ident('b'), ne_op, set_authz])),
        ('a == b', Instructions([Ident('a'), Ident('b'), eq_op, set_authz])),
        ('a and b', Instructions([Ident('a'), Ident('b'), and_op, set_authz])),
        ('a or b', Instructions([Ident('a'), Ident('b'), or_op, set_authz])),
        ('a if b else c', Instructions([
            Ident('b'), Ident('a'), Ident('c'), trinary_op, set_authz
        ])),
        ('a + b * c + d', Instructions([
            Ident('a'), Ident('b'), Ident('c'), mul_op, add_op, Ident('d'),
            add_op, set_authz,
        ])),
        ('a * b + c * d', Instructions([
            Ident('a'), Ident('b'), mul_op, Ident('c'), Ident('d'), mul_op,
            add_op, set_authz,
        ])),
        ('{}', Instructions([Constant(frozenset()), set_authz])),
        ('{,}', Instructions([Constant(frozenset()), set_authz])),
        ('{a}', Instructions([Ident('a'), SetOperator(1), set_authz])),
        ('{a, b, c}', Instructions([
            Ident('a'), Ident('b'), Ident('c'), SetOperator(3), set_authz,
        ])),
        ('{a, b, c,}', Instructions([
            Ident('a'), Ident('b'), Ident('c'), SetOperator(3), set_authz,
        ])),
        ('a.b', Instructions([Ident('a'), Attribute('b'), set_authz])),
        ('a[3]', Instructions([Ident('a'), Constant(3), item_op, set_authz])),
        ('a()', Instructions([Ident('a'), CallOperator(1), set_authz])),
        ('a(,)', Instructions([Ident('a'), CallOperator(1), set_authz])),
        ('a(1)', Instructions([
            Ident('a'), Constant(1), CallOperator(2), set_authz,
        ])),
        ('a(1, 2, 3)', Instructions([
            Ident('a'), Constant(1), Constant(2), Constant(3), CallOperator(4),
            set_authz,
        ])),
        ('a(1, 2, 3,)', Instructions([
            Ident('a'), Constant(1), Constant(2), Constant(3), CallOperator(4),
            set_authz,
        ])),
        ('True {{}}', Instructions([Constant(True), set_authz])),
        ('True {{,}}', Instructions([Constant(True), set_authz])),
        ('True {{a=1}}', Instructions([
            Constant(True), set_authz,
            Constant(1), AuthorizationAttr('a'),
        ])),
        ('True {{a=1,b=2,c=3}}', Instructions([
            Constant(True), set_authz,
            Constant(1), AuthorizationAttr('a'),
            Constant(2), AuthorizationAttr('b'),
            Constant(3), AuthorizationAttr('c'),
        ])),
        ('True {{a=1,b=2,c=3,}}', Instructions([
            Constant(True), set_authz,
            Constant(1), AuthorizationAttr('a'),
            Constant(2), AuthorizationAttr('b'),
            Constant(3), AuthorizationAttr('c'),
        ])),
        ('level > 400 {{ level=level }}', Instructions([
            Ident('level'), Constant(400), gt_op, set_authz,
            Ident('level'), AuthorizationAttr('level'),
        ])),
    ]

    def test_parse(self):
        errors = 0
        for text, expected in self.rules:
            try:
                result = parser.parse_rule("test", text, do_raise=True)
            except pyparsing.ParseException as exc:
                if expected is not None:
                    # Print out a description of the unexpected failure
                    print('')
                    print("Failure to parse %r: %s" % (text, exc))
                    print("  Line    : %s" % exc.line)
                    print("  Location: %s^" % (" " * (exc.col - 1)))
                    errors += 1
                continue

            # Compare the expected to the actual
            if result != expected:
                print('')
                print("Failure to parse %r: %r != %r" %
                      (text, result, expected))
                errors += 1

        if errors > 0:
            self.fail("Parse failures encountered; see output for information")
