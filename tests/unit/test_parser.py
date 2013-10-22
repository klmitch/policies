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
