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

from policies import rules

import tests


class TestRule(tests.TestCase):
    def test_init_basic(self):
        rule = rules.Rule('name')

        self.assertEqual(rule.name, 'name')
        self.assertEqual(rule.text, '')
        self.assertEqual(rule.attrs, {})
        self.assertEqual(rule._instructions, None)

    def test_init_full(self):
        rule = rules.Rule('name', 'text', {
            'name': 'eman',
            'text': 'txet',
            'other': 1,
            '_ignored': 'ignored',
            'none': None,
        })

        self.assertEqual(rule.name, 'name')
        self.assertEqual(rule.text, 'text')
        self.assertEqual(rule.attrs, {
            'name': 'eman',
            'text': 'txet',
            'other': 1,
        })
        self.assertEqual(rule._instructions, None)

    @mock.patch('policies.parser.parse_rule', return_value='instructions')
    def test_instructions_cached(self, mock_parse_rule):
        rule = rules.Rule('name', 'text')
        rule._instructions = 'cached'

        self.assertEqual(rule.instructions, 'cached')
        self.assertEqual(rule._instructions, 'cached')
        self.assertFalse(mock_parse_rule.called)

    @mock.patch('policies.parser.parse_rule', return_value='instructions')
    def test_instructions_uncached(self, mock_parse_rule):
        rule = rules.Rule('name', 'text')

        self.assertEqual(rule.instructions, 'instructions')
        self.assertEqual(rule._instructions, 'instructions')
        mock_parse_rule.assert_called_once_with('name', 'text')


class TestRuleDoc(tests.TestCase):
    def test_init_basic(self):
        rdoc = rules.RuleDoc('name')

        self.assertEqual(rdoc.name, 'name')
        self.assertEqual(rdoc.doc, None)
        self.assertEqual(rdoc.attr_docs, {})

    def test_init_full(self):
        rdoc = rules.RuleDoc('name', 'doc', {
            'name': 'eman',
            'text': 'txet',
            '_ignored': 'ignored',
            'none': '',
        })

        self.assertEqual(rdoc.name, 'name')
        self.assertEqual(rdoc.doc, 'doc')
        self.assertEqual(rdoc.attr_docs, {
            'name': 'eman',
            'text': 'txet',
        })
