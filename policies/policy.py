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

import collections
import logging

import pkg_resources

from policies import authorization
from policies import rules


class PolicyException(Exception):
    """
    An exception raised if an attempt is made to store a given rule in
    the wrong location in a ``Policy``.
    """

    pass


class PolicyContext(object):
    """
    A context object for evaluating authorization rules.  Contains a
    ``stack``--a simple list onto which values will be pushed and from
    which values will be popped--as well as providing storage for the
    final authorization object, ``authz``.  Also stores the ``Policy``
    object (``policy``), the ``variables`` for the evaluation, and
    ``attrs``, a dictionary of default values for authorization
    attributes.
    """

    def __init__(self, policy, attrs, variables):
        """
        Initialize a ``PolicyContext`` object.

        :param policy: The ``Policy`` object.
        :param attrs: A dictionary of authorization attribute default
                      values.
        :param variables: A dictionary of variables to be defined for
                          the evaluation.
        """

        # Save parameters
        self.policy = policy
        self.attrs = attrs
        self.variables = variables

        # Set up the stack
        self.stack = []
        self.authz = None

    def resolve(self, symbol):
        """
        Resolve a symbol encountered during a rule evaluation into the
        actual value for that symbol.

        :param symbol: The symbol being resolved.

        :returns: The value of that symbol.  If the symbol was not
                  declared in the ``variables`` parameter of the
                  constructor, a call will be made to the ``Policy``'s
                  ``resolve()`` method.
        """

        # Try the variables first
        if symbol in self.variables:
            return self.variables[symbol]

        return self.policy.resolve(symbol)


class Policy(collections.MutableMapping):
    """
    Maintain a mapping of rules, along with declared defaults and any
    documentation information.  Allows for access to any rule, as well
    as evaluation of a rule.
    """

    # Pre-populate the resolver cache with these special callables
    _builtins = {
        'abs': abs,
        'basestring': basestring,
        'bin': bin,
        'bool': bool,
        'bytes': bytes,
        'callable': callable,
        'chr': chr,
        'cmp': cmp,
        'complex': complex,
        'dict': dict,
        'divmod': divmod,
        'enumerate': enumerate,
        'float': float,
        'format': format,
        'frozenset': frozenset,
        'getattr': getattr,
        'hasattr': hasattr,
        'hash': hash,
        'hex': hex,
        'id': id,
        'int': int,
        'isinstance': isinstance,
        'issubclass': issubclass,
        'iter': iter,
        'len': len,
        'list': list,
        'long': long,
        'max': max,
        'min': min,
        'next': next,
        'object': object,
        'oct': oct,
        'ord': ord,
        'pow': pow,
        'range': range,
        'repr': repr,
        'reversed': reversed,
        'round': round,
        'set': set,
        'sorted': sorted,
        'str': str,
        'sum': sum,
        'tuple': tuple,
        'type': type,
        'unichr': unichr,
        'unicode': unicode,
        'xrange': xrange,
        'zip': zip,
    }

    def __init__(self, group=None, builtins=None):
        """
        Initialize a ``Policy`` object.

        :param group: An entrypoint group to search for unresolved
                      symbols.  This allows for extension of the
                      policy rules for a given application.  If not
                      given, unresolved symbols will resolve to
                      ``None``.
        :param builtins: A dictionary of "builtin" functions, which
                         overrides any symbols defined in the
                         entrypoint group.  If not provided, a default
                         of select Python builtins will be used
                         instead.
        """

        # Save the entrypoint group
        self._group = group

        # Set up the mappings
        self._defaults = {}
        self._docs = {}
        self._rules = {}

        # Seed the resolve cache
        if builtins is None:
            builtins = self._builtins
        self._resolve_cache = builtins.copy()

    def __getitem__(self, key):
        """
        Retrieve a ``Rule`` given its name.  Raises a ``KeyError`` if
        the rule is both undefined and undeclared.

        :param key: The name of the rule to get.

        :returns: The ``Rule`` object describing the rule.
        """

        # Check to see if the rule has been set
        if key in self._rules:
            return self._rules[key]

        # If it's been declared, return the default
        if key in self._defaults:
            return self._defaults[key]

        raise KeyError(key)

    def __setitem__(self, key, rule):
        """
        Set a ``Rule`` with a given name.  Raises a
        ``PolicyException`` if the key and the name of the rule don't
        match.

        :param key: The name of the rule to set.
        :param rule: Either a ``Rule`` object with a name matching
                     ``key``, or the text of the rule.
        """

        if isinstance(rule, basestring):
            # Construct the rule from the string
            rule = rules.Rule(key, rule)
        elif key != rule.name:
            raise PolicyException("key %r does not match rule name %r" %
                                  (key, rule.name))

        self._rules[key] = rule

    def __delitem__(self, key):
        """
        Reset a rule with a given name to its default.

        :param key: The name of the rule to reset.
        """

        del self._rules[key]

    def __iter__(self):
        """
        Iterate over the rule names.

        :returns: An iterator over the rule names.
        """

        return iter(set(self._defaults.keys()) | set(self._rules.keys()))

    def __len__(self):
        """
        Obtain the number of rules available on the ``Policy``.

        :returns: The number of independent rules on the ``Policy``.
        """

        return len(set(self._defaults.keys()) | set(self._rules.keys()))

    def declare(self, name, text='', doc=None, attrs=None, attr_docs=None):
        """
        Declare a rule.  This allows a default for a given rule to be
        set, along with default values for the authorization
        attributes.  This function can also include documentation for
        the rule and the authorization attributes, allowing a sample
        policy configuration file to be generated.

        :param name: The name of the rule.
        :param text: The text of the rule.  Defaults to the empty
                     string.
        :param doc: A string documenting the purpose of the rule.
        :param attrs: A dictionary of default values for the
                      authorization attributes.  Note that
                      authorization attributes cannot have names
                      beginning with an underscore ("_").
        :param attr_docs: A dictionary of strings for documenting the
                          purpose of the authorization attributes.
        """

        self._defaults[name] = rules.Rule(name, text, attrs)
        self._docs[name] = rules.RuleDoc(name, doc, attr_docs)

        return self._defaults[name]

    def set_rule(self, rule):
        """
        Stores a ``Rule`` object in the ``Policy``.

        :param rule: The rule to save.
        """

        self._rules[rule.name] = rule

    def del_rule(self, rule):
        """
        Deletes a ``Rule`` object from the ``Policy``.  This restores
        the rule to the default set using ``declare()``.

        :param rule: The rule to delete.
        """

        del self._rules[rule.name]

    def get_doc(self, name):
        """
        Retrieve a ``RuleDoc`` object from the ``Policy`` with the
        given name.  This object contains all documentation for the
        named rule.

        :param name: The name of the rule to retrieve the
                     documentation for.

        :returns: A ``RuleDoc`` object containing the documentation
                  for the rule.
        """

        # Create one if there isn't one already
        if name not in self._docs:
            self._docs[name] = rules.RuleDoc(name)

        return self._docs[name]

    def resolve(self, symbol):
        """
        Resolve a symbol using the entrypoint group.

        :param symbol: The symbol being resolved.

        :returns: The value of that symbol.  If the symbol cannot be
                  found, or if no entrypoint group was passed to the
                  constructor, will return ``None``.
        """

        # Search for a corresponding symbol
        if symbol not in self._resolve_cache:
            result = None

            # Search through entrypoints only if we have a group
            if self._group is not None:
                for ep in pkg_resources.iter_entry_points(self._group, symbol):
                    try:
                        result = ep.load()
                    except (ImportError, AttributeError,
                            pkg_resources.UnknownExtra):
                        continue

                    # We found the result we were looking for
                    break

            # Cache the result
            self._resolve_cache[symbol] = result

        return self._resolve_cache[symbol]

    def evaluate(self, name, variables=None):
        """
        Evaluate a named rule.

        :param name: The name of the rule to evaluate.
        :param variables: An optional dictionary of variables to make
                          available during evaluation of the rule.

        :returns: An instance of
                  ``policies.authorization.Authorization`` with the
                  result of the rule evaluation.  This will include
                  any authorization attributes.
        """

        # Get the rule and predeclaration
        rule = self._rules.get(name)
        default = self._defaults.get(name)

        # Short-circuit if we don't have either
        if rule is None and default is None:
            return authorization.Authorization(False)

        # Marry the attribute defaults
        attrs = {}
        if default:
            attrs.update(default.attrs)
        if rule:
            attrs.update(rule.attrs)

        # Select the rule we'll actually use
        if rule is None:
            rule = default

        # Construct the context
        ctxt = PolicyContext(self, attrs, variables or {})

        # Execute the rule
        try:
            rule.instructions(ctxt)
        except Exception as exc:
            # Get the logger and emit a log message
            log = logging.getLogger('policies')
            log.warn("Exception raised while evaluating rule %r: %s" %
                     (name, exc))

            # Fail closed
            return authorization.Authorization(False, attrs)

        # Return the authorization result
        return ctxt.authz