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

from policies import parser


class Rule(object):
    """
    Describe one policy rule.  A policy rule has a name and some text
    in the policy language, along with optional default values for
    authorization attributes.  The instructions for the rule text can
    be retrieved with the ``instructions`` property, and the rule text
    is parsed on demand.
    """

    def __init__(self, name, text='', attrs=None):
        """
        Initializes a ``Rule`` object.

        :param name: The rule name.
        :param text: Optional; the text for the rule.  If not given,
                     will be the empty string, which evaluates to a
                     rule which always denies authorization.
        :param attrs: A dictionary of authorization attribute
                      defaults.  Overrides the default of ``None``.
                      Note that authorization attributes may not have
                      a leading underscore ("_").
        """

        # Store the essential data
        self.name = name
        self.text = text
        self.attrs = dict((k, v) for k, v in (attrs or {}).items()
                          if k[0] != '_' and v is not None)

        # The instructions will be parsed on demand
        self._instructions = None

    @property
    def instructions(self):
        """
        Retrieve the instructions for the rule.
        """

        if self._instructions is None:
            # Compile the rule into an Instructions instance; we do
            # this lazily to amortize the cost of the compilation,
            # then cache that result for efficiency...
            self._instructions = parser.parse_rule(self.name, self.text)

        return self._instructions
