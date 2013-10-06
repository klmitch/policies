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

import abc
import operator


__all__ = ['Constant', 'Attribute', 'Ident', 'SetOperator', 'CallOperator',
           'inv_op', 'pos_op', 'neg_op', 'not_op',
           'pow_op', 'mul_op', 'true_div_op', 'floor_div_op', 'mod_op',
           'add_op', 'sub_op', 'left_shift_op', 'right_shift_op',
           'bit_and_op', 'bit_xor_op', 'bit_or_op', 'in_op', 'not_in_op',
           'is_op', 'is_not_op', 'lt_op', 'gt_op', 'le_op', 'ge_op', 'ne_op',
           'eq_op', 'and_op', 'or_op', 'item_op', 'trinary_op']


class Instruction(object):
    """
    An instruction is a callable that manipulates the evaluation
    context.  A sequence of instructions describes how to evaluate an
    expression using a value stack available in the evaluation
    context.
    """

    __metaclass__ = abc.ABCMeta

    def __ne__(self, other):
        """
        Compare two instructions for inequivalence.

        :param other: Another ``Instruction`` to compare to.

        :returns: A ``False`` value if the ``other`` instruction is
                  equivalent to this one, ``True`` otherwise.
        """

        return not self.__eq__(other)

    @abc.abstractmethod
    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Should update the evaluation
        context stack.

        :param ctxt: The evaluation context.
        """

        pass  # pragma: nocover

    @abc.abstractmethod
    def __hash__(self, *elems):
        """
        Return a hash value for this instruction.  Extra parameters
        can be passed in by subclasses to allow those elements to also
        factor into the hash value.

        :returns: The hash value.
        """

        return hash((self.__class__,) + elems)

    @abc.abstractmethod
    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``Instruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return self.__class__ is other.__class__


class Constant(Instruction):
    """
    An instruction that pushes a constant value onto the evaluation
    context stack.
    """

    def __init__(self, value):
        """
        Initialize a ``Constant``.

        :param value: The value of the constant.
        """

        self.value = value

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Pushes the value of the constant
        onto the evaluation context stack.

        :param ctxt: The evaluation context.
        """

        ctxt.stack.append(self.value)

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(Constant, self).__hash__(self.value)

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``Instruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Constant, self).__eq__(other) and
                self.value == other.value)


class Attribute(Instruction):
    """
    An instruction that replaces the top of the evaluation context
    stack with one of its attributes.
    """

    def __init__(self, attribute):
        """
        Initialize an ``Attribute``.

        :param attribute: The name of the attribute.
        """

        self.attribute = attribute

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Pops a value off the top of the
        evaluation context stack and pushes the value of its
        attribute.

        :param ctxt: The evaluation context.
        """

        ctxt.stack.append(getattr(ctxt.stack.pop(), self.attribute))

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(Attribute, self).__hash__(self.attribute)

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``Instruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Attribute, self).__eq__(other) and
                self.attribute == other.attribute)


class Ident(Instruction):
    """
    An instruction that resolves an identifier into a value and pushes
    that value onto the evaluation context stack.
    """

    def __init__(self, ident):
        """
        Initialize an ``Ident``.

        :param ident: The identifier.
        """

        self.ident = ident

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Resolves the identifier in the
        evaluation context and pushes its value onto the evaluation
        context stack.

        :param ctxt: The evaluation context.
        """

        ctxt.stack.append(ctxt.resolve(self.ident))

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(Ident, self).__hash__(self.ident)

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``Instruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Ident, self).__eq__(other) and
                self.ident == other.ident)


class Operator(Instruction):
    """
    An instruction that performs an operation on some elements of the
    evaluation context stack, replacing those elements with the return
    value of the operation.
    """

    def __init__(self, count):
        """
        Initialize an ``Operator``.

        :param count: The number of stack elements that will be
                      consumed by the operator.
        """

        self.count = count

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Replaces the ``count`` elements on
        the top of the evaluation context stack with the single
        element obtained by calling ``op()`` on those elements.

        :param ctxt: The evaluation context.
        """

        ctxt.stack[-self.count:] = [self.op(*ctxt.stack[-self.count:])]

    def __hash__(self, *elems):
        """
        Return a hash value for this instruction.  Extra parameters
        can be passed in by subclasses to allow those elements to also
        factor into the hash value.

        :returns: The hash value.
        """

        return super(Operator, self).__hash__(self.count, *elems)

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``Instruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Operator, self).__eq__(other) and
                self.count == other.count)

    def fold(self, elems):
        """
        Perform constant folding.  If all the elements are constant,
        then the operator is performed and the constant is folded.

        :param elems: A list (or list-like object) containing the
                      elements.

        :returns: If all elements are instances of ``Constant``,
                  returns a list of one element, which is the result
                  of calling the operation on ``elems``.  Otherwise,
                  returns a list composed of the elements of ``elems``
                  plus this operator.
        """

        # Are the elements constants?
        if all(isinstance(e, Constant) for e in elems):
            return [self.op(*elems)]

        return elems[:] + [self]

    @abc.abstractmethod
    def op(self, *args):
        """
        Perform the operation.  Will be passed the stack elements.

        :returns: The desired replacement value.
        """

        pass  # pragma: nocover


class GenericOperator(Operator):
    """
    A generic operator which evaluates a callable passed to the
    constructor.
    """

    def __init__(self, count, op):
        """
        Initialize a ``GenericOperator``.

        :param count: The number of stack elements that will be
                      consumed by the operator.
        :param op: The callable implementing the operation.
        """

        super(GenericOperator, self).__init__(count)
        self._op = op

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(GenericOperator, self).__hash__(self._op)

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``Instruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(GenericOperator, self).__eq__(other) and
                self._op == other._op)

    def op(self, *args):
        """
        Call the operation that was passed to the constructor with the
        given arguments.

        :returns: The result of calling the operator.
        """

        return self._op(*args)


class SetOperator(GenericOperator):
    """
    An instruction that constructs a frozen set from a given number of
    elements on the evaluation context stack, replacing those elements
    with the set.
    """

    def __init__(self, count):
        """
        Initialize a ``SetOperator``.

        :param count: The number of elements to construct the set
                      from.
        """

        super(SetOperator, self).__init__(count, frozenset)


class CallOperator(Operator):
    """
    An instruction that performs a function or method call.  The top
    ``count`` elements on the stack identify the function or method
    and its arguments.  The function or method reference and the
    arguments will be replaced by the return value of calling the
    function or method.
    """

    def op(self, func, *args):
        """
        Call the function with the given arguments.

        :returns: The result of calling the function.
        """

        return func(*args)

    def fold(self, elems):
        """
        Override constant folding for function or method calls.
        Constant folding needs to be overridden because function or
        method calls may have side effects, and so we cannot assume
        that a constant-folded function/method call is equivalent to
        one executed dynamically while evaluating an expression.

        :param elems: A list (or list-like object) containing the
                      elements.

        :returns: A list composed of the elements of ``elems`` plus
                  this operator.
        """

        return elems[:] + [self]


# Unary operators
inv_op = GenericOperator(1, operator.inv)
pos_op = GenericOperator(1, operator.pos)
neg_op = GenericOperator(1, operator.neg)
not_op = GenericOperator(1, operator.not_)

# Binary operators
pow_op = GenericOperator(2, operator.pow)
mul_op = GenericOperator(2, operator.mul)
true_div_op = GenericOperator(2, operator.truediv)
floor_div_op = GenericOperator(2, operator.floordiv)
mod_op = GenericOperator(2, operator.mod)
add_op = GenericOperator(2, operator.add)
sub_op = GenericOperator(2, operator.sub)
left_shift_op = GenericOperator(2, operator.lshift)
right_shift_op = GenericOperator(2, operator.rshift)
bit_and_op = GenericOperator(2, operator.and_)
bit_xor_op = GenericOperator(2, operator.xor)
bit_or_op = GenericOperator(2, operator.or_)
in_op = GenericOperator(2, lambda x, y: x in y)
not_in_op = GenericOperator(2, lambda x, y: x not in y)
is_op = GenericOperator(2, operator.is_)
is_not_op = GenericOperator(2, operator.is_not)
lt_op = GenericOperator(2, operator.lt)
gt_op = GenericOperator(2, operator.gt)
le_op = GenericOperator(2, operator.le)
ge_op = GenericOperator(2, operator.ge)
ne_op = GenericOperator(2, operator.ne)
eq_op = GenericOperator(2, operator.eq)
and_op = GenericOperator(2, lambda x, y: x and y)
or_op = GenericOperator(2, lambda x, y: x or y)
item_op = GenericOperator(2, lambda x, y: x[y])

# The trinary operator
trinary_op = GenericOperator(3, lambda x, y, z: y if x else z)
