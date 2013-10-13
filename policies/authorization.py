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


class Authorization(object):
    """
    The authorization result.  Evaluates as either ``True`` or
    ``False``, depending on what the result of the policy evaluation
    was.  Can also have attributes set by the policy rule, which will
    default to ``None`` unless another default is provided.
    """

    def __init__(self, result, defaults=None):
        """
        Initialize an ``Authorization`` object.

        :param result: The result of the authorization evaluation.
                       Will be converted to boolean using the
                       ``bool()`` function.
        :param defaults: A dictionary of default values for the
                         authorization attributes.  If not provided,
                         authorization attributes default to ``None``.
        """

        super(Authorization, self).__setattr__('_result', bool(result))
        super(Authorization, self).__setattr__('_attrs', defaults.copy()
                                               if defaults else {})

    def __getattr__(self, name):
        """
        Retrieve a named authorization attribute.  If the
        authorization attribute has not been set, returns ``None``.

        :param name: The name of the authorization attribute to
                     return.

        :returns: The value of the authorization attribute.
        """

        # Prohibit access to internal attributes, so users don't get
        # any ideas...
        if name[0] == '_':
            raise AttributeError("%r object has no attribute %r" %
                                 (self.__class__.__name__, name))

        return self._attrs.get(name)

    def __setattr__(self, name, value):
        """
        Prohibits setting authorization attributes.  Authorization
        attributes are immutable.

        :param name: The name of the authorization attribute to set.
        :param value: The value to set the authorization attribute to.
        """

        raise AttributeError("%r object does not allow setting attribute %r" %
                             (self.__class__.__name__, name))

    def __delattr__(self, name):
        """
        Prohibits deletion of authorization attributes.  Authorization
        attributes are immutable.

        :param name: The name of the authorization attribute to set.
        """

        raise AttributeError("%r object does not allow deleting attribute %r" %
                             (self.__class__.__name__, name))

    def __nonzero__(self):
        """
        Returns the result of the authorization check.  If the
        ``result`` passed to the constructor evaluated as ``True``,
        returns ``True``; otherwise, returns ``False``.

        :returns: The result of the authorization check.
        """

        return self._result
    __bool__ = __nonzero__
