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

import six

from policies import authorization


__all__ = ['Instructions', 'Jump', 'JumpIf', 'JumpIfNot',
           'Constant', 'Attribute', 'Ident', 'SetOperator', 'CallOperator',
           'AuthorizationAttr',
           'pop',
           'inv_op', 'pos_op', 'neg_op', 'not_op',
           'pow_op', 'mul_op', 'true_div_op', 'floor_div_op', 'mod_op',
           'add_op', 'sub_op', 'left_shift_op', 'right_shift_op',
           'bit_and_op', 'bit_xor_op', 'bit_or_op', 'in_op', 'not_in_op',
           'is_op', 'is_not_op', 'lt_op', 'gt_op', 'le_op', 'ge_op', 'ne_op',
           'eq_op', 'and_op', 'or_op',
           'item_op',
           'trinary_op',
           'set_authz']


@six.add_metaclass(abc.ABCMeta)
class AbstractInstruction(object):
    """
    An instruction is a callable that manipulates the evaluation
    context.  A sequence of instructions describes how to evaluate an
    expression using a value stack available in the evaluation
    context.
    """

    def __len__(self):
        """
        Compute the number of contained instructions.

        :returns: The number of instructions contained.
        """

        return 1

    def __ne__(self, other):
        """
        Compare two instructions for inequivalence.

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``False`` value if the ``other`` instruction is
                  equivalent to this one, ``True`` otherwise.
        """

        return not self.__eq__(other)

    @abc.abstractmethod
    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        pass  # pragma: nocover

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

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return self.__class__ is other.__class__


class Instructions(AbstractInstruction):
    """
    A special instruction that actually consists of a list of
    instructions.  This is needed for collapsing token lists in the
    parser, and also serves as the return value for the expression
    parser.
    """

    def __init__(self, instructions):
        """
        Initialize an ``Instructions`` object.

        :param instructions: A sequence of the instructions to be
                             contained by the ``Instructions`` object.
        """

        # Linearize the instructions into a flat tuple
        self.instructions = tuple(self._linearize(instructions))

    def __len__(self):
        """
        Compute the number of contained instructions.

        :returns: The number of instructions contained.
        """

        return len(self.instructions)

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return "Instructions(%r)" % (self.instructions,)

    def __call__(self, ctxt, no_authz=False):
        """
        Evaluate this instruction.  Executes the contained
        instructions in sequence.

        :param ctxt: The evaluation context.
        :param no_authz: If ``True``, evaluation will stop at the
                         set_authz instruction.  This can be used to
                         only evaluate the expression in a rule.
        """

        while ctxt.pc < len(self.instructions):
            # Allows for evaluating only the expression of a rule
            if no_authz and self.instructions[ctxt.pc] == set_authz:
                break

            # Default jump
            ctxt.step = 1

            # Execute the addressed instruction
            self.instructions[ctxt.pc](ctxt)

            # Advance to the next instruction
            ctxt.pc += ctxt.step

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(Instructions, self).__hash__(*self.instructions)

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Instructions, self).__eq__(other) and
                self.instructions == other.instructions)

    @classmethod
    def _linearize(cls, inst_list):
        """
        A generator function which performs linearization of the list
        of instructions; that is, each instruction which should be
        executed will be yielded in turn, recursing into
        ``Instructions`` instances that appear in the list.

        :param inst_list: A list (or other sequence) of instructions.

        :returns: An iterator which returns all instructions.
        """

        for inst in inst_list:
            # Check if we need to recurse
            if isinstance(inst, Instructions):
                for sub_inst in cls._linearize(inst.instructions):
                    yield sub_inst
            else:
                yield inst


class Jump(AbstractInstruction):
    """
    An instruction that causes an unconditional jump over a number of
    other instructions.
    """

    def __init__(self, count):
        """
        Initialize a ``Jump`` object.

        :param count: The number of instructions to jump over.
        """

        self.count = count

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return "%s(%r)" % (self.__class__.__name__, self.count)

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Increments the program counter
        step by the number of instructions to jump over.

        :param ctxt: The evaluation context.
        """

        ctxt.step += self.count

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(Jump, self).__hash__(self.count)

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Jump, self).__eq__(other) and
                self.count == other.count)


class JumpIf(Jump):
    """
    An instruction that causes a jump, conditional on the value on the
    top of the stack.  The value is left on the stack.
    """

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Increments the program counter
        step by the number of instructions to jump over, if the value
        at the top of the stack evaluates to ``True``.  The stack is
        not altered.

        :param ctxt: The evaluation context.
        """

        if ctxt.stack[-1]:
            super(JumpIf, self).__call__(ctxt)


class JumpIfNot(Jump):
    """
    An instruction that causes a jump, conditional on the value on the
    top of the stack.  The value is left on the stack.
    """

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Increments the program counter
        step by the number of instructions to jump over, if the value
        at the top of the stack evaluates to ``True``.  The stack is
        not altered.

        :param ctxt: The evaluation context.
        """

        if not ctxt.stack[-1]:
            super(JumpIfNot, self).__call__(ctxt)


class Pop(AbstractInstruction):
    """
    An instruction that simply discards a value from the top of the
    stack.
    """

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return 'Pop()'

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Discards the element at the top of
        the stack.

        :param ctxt: The evaluation context.
        """

        ctxt.stack.pop()

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(Pop, self).__hash__()

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return super(Pop, self).__eq__(other)


class Constant(AbstractInstruction):
    """
    An instruction that pushes a constant value onto the evaluation
    context stack.
    """

    def __init__(self, value):
        """
        Initialize a ``Constant`` object.

        :param value: The value of the constant.
        """

        self.value = value

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return "Constant(%r)" % (self.value,)

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

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Constant, self).__eq__(other) and
                self.value == other.value)


class Attribute(AbstractInstruction):
    """
    An instruction that replaces the top of the evaluation context
    stack with one of its attributes.
    """

    def __init__(self, attribute):
        """
        Initialize an ``Attribute`` object.

        :param attribute: The name of the attribute.
        """

        self.attribute = attribute

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return "Attribute(%r)" % (self.attribute,)

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

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Attribute, self).__eq__(other) and
                self.attribute == other.attribute)


class Ident(AbstractInstruction):
    """
    An instruction that resolves an identifier into a value and pushes
    that value onto the evaluation context stack.
    """

    def __init__(self, ident):
        """
        Initialize an ``Ident`` object.

        :param ident: The identifier.
        """

        self.ident = ident

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return "Ident(%r)" % (self.ident,)

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

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Ident, self).__eq__(other) and
                self.ident == other.ident)


@six.add_metaclass(abc.ABCMeta)
class AbstractOperator(object):
    """
    An operator is a class with a ``fold()`` method, which performs
    constant folding.  Most operators are also instructions.
    """

    @abc.abstractmethod
    def fold(self, elems):
        """
        Perform constant folding.  If the result of applying the
        operator to the elements would be a fixed constant value,
        returns the result of applying the operator to the operands.
        Otherwise, returns an instance of ``Instructions`` containing
        the instructions necessary to apply the operator.

        :param elems: A list (or list-like object) containing the
                      elements.

        :returns: A list of one element, containing the instructions
                  necessary to implement the operator.
        """

        pass  # pragma: nocover


class Operator(AbstractInstruction, AbstractOperator):
    """
    An instruction that performs an operation on some elements of the
    evaluation context stack, replacing those elements with the return
    value of the operation.
    """

    def __init__(self, count, opstr):
        """
        Initialize an ``Operator`` object.

        :param count: The number of stack elements that will be
                      consumed by the operator.
        :param opstr: A string representing the operation that will be
                      performed.  This is used when a representation
                      of this operator is requested.
        """

        self.count = count
        self.opstr = opstr

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return '%s(%d, %r)' % (self.__class__.__name__, self.count, self.opstr)

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

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(Operator, self).__eq__(other) and
                self.count == other.count)

    def fold(self, elems):
        """
        Perform constant folding.  If the result of applying the
        operator to the elements would be a fixed constant value,
        returns the result of applying the operator to the operands.
        Otherwise, returns an instance of ``Instructions`` containing
        the instructions necessary to apply the operator.

        :param elems: A list (or list-like object) containing the
                      elements.

        :returns: A list of one element, containing the instructions
                  necessary to implement the operator.
        """

        # Are the elements constants?
        if all(isinstance(e, Constant) for e in elems):
            return [Constant(self.op(*[e.value for e in elems]))]

        return [Instructions(elems[:] + [self])]

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

    def __init__(self, count, op, opstr):
        """
        Initialize a ``GenericOperator`` object.

        :param count: The number of stack elements that will be
                      consumed by the operator.
        :param op: The callable implementing the operation.
        :param opstr: A string representing the operation that will be
                      performed.  This is used when a representation
                      of this operator is requested.
        """

        super(GenericOperator, self).__init__(count, opstr)
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

        :param other: Another ``AbstractInstruction`` to compare to.

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


class SetOperator(Operator):
    """
    An instruction that constructs a frozen set from a given number of
    elements on the evaluation context stack, replacing those elements
    with the set.
    """

    def __init__(self, count):
        """
        Initialize a ``SetOperator`` object.

        :param count: The number of elements to construct the set
                      from.
        """

        super(SetOperator, self).__init__(count, 'set')

    def op(self, *args):
        """
        Construct a set with the given arguments.

        :returns: The constructed set.
        """

        return frozenset(args)


class CallOperator(AbstractInstruction):
    """
    An instruction that performs a function or method call.  The top
    ``count`` elements on the stack identify the function or method
    and its arguments.  The function or method reference and the
    arguments will be replaced by the return value of calling the
    function or method.
    """

    def __init__(self, count):
        """
        Initialize a ``CallOperator`` object.

        :param count: The number of elements to construct the call
                      from.  The first element is the callable, and
                      the remaining elements will be positional
                      arguments to the callable.
        """

        self.count = count

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return 'CallOperator(%d)' % self.count

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Replaces the ``count`` elements on
        the top of the evaluation context stack with the single
        element obtained by calling the function on its arguments.

        :param ctxt: The evaluation context.
        """

        # Get the function and its arguments
        args = ctxt.stack[-self.count:]
        func = args.pop(0)

        # If the function wants the context, add the context and call
        # it; it is assumed the function will do its own updates to
        # the context stack
        if getattr(func, '_policies_want_context', False):
            ctxt.stack = ctxt.stack[:-self.count]
            func(ctxt, *args)
        else:
            # Call the function and update the stack
            ctxt.stack[-self.count:] = [func(*args)]

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(CallOperator, self).__hash__(self.count)

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(CallOperator, self).__eq__(other) and
                self.count == other.count)


class SetAuthorization(AbstractInstruction):
    """
    An instruction that sets the result of the authorization check.
    This initializes the ``authz`` attribute of the evaluation context
    based on the boolean value of the top of the stack.
    """

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return 'SetAuthorization()'

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Creates the ``authz`` attribute of
        the evaluation context, with the boolean value of the top of
        the stack.  The attribute defaults are drawn from the
        ``attrs`` attribute of the evaluation context, which is
        expected to be a dictionary.

        :param ctxt: The evaluation context.
        """

        ctxt.authz = authorization.Authorization(ctxt.stack.pop(), ctxt.attrs)

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(SetAuthorization, self).__hash__()

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return super(SetAuthorization, self).__eq__(other)


class AuthorizationAttr(AbstractInstruction):
    """
    An instruction that sets attributes on the authorization result.
    The ``SetAuthorization`` instruction MUST be executed before this
    instruction can be called.  A value will be popped off the stack
    and its value set on a named attribute of the authorization
    result.
    """

    def __init__(self, attribute):
        """
        Initialize an ``AuthorizationAttr`` object.

        :param attribute: The name of the attribute to set.
        """

        self.attribute = attribute

    def __repr__(self):
        """
        Return a representation of this instruction.  Should provide
        enough information for a user to understand what operation
        will be performed.

        :returns: A string representation of this instruction.
        """

        return 'AuthorizationAttr(%r)' % self.attribute

    def __call__(self, ctxt):
        """
        Evaluate this instruction.  Pops a value off the top of the
        evaluation context stack and sets the corresponding attribute
        of the authorization result to that value.

        :param ctxt: The evaluation context.
        """

        ctxt.authz._attrs[self.attribute] = ctxt.stack.pop()

    def __hash__(self):
        """
        Return a hash value for this instruction.

        :returns: The hash value.
        """

        return super(AuthorizationAttr, self).__hash__(self.attribute)

    def __eq__(self, other):
        """
        Compare two instructions for equivalence.

        :param other: Another ``AbstractInstruction`` to compare to.

        :returns: A ``True`` value if the ``other`` instruction is
                  equivalent to this one, ``False`` otherwise.
        """

        return (super(AuthorizationAttr, self).__eq__(other) and
                self.attribute == other.attribute)


class TrinaryOperator(AbstractOperator):
    """
    A special operator which is not an instruction.  This class
    implements the trinary operator, which implements the
    ``if``/``else`` operator.
    """

    def fold(self, elems):
        """
        Perform constant folding.  If the result of applying the
        operator to the elements would be a fixed constant value,
        returns the result of applying the operator to the operands.
        Otherwise, returns an instance of ``Instructions`` containing
        the instructions necessary to apply the operator.

        :param elems: A list (or list-like object) containing the
                      elements.

        :returns: A list of one element, containing the instructions
                  necessary to implement the operator.
        """

        cond, if_true, if_false = elems

        if isinstance(cond, Constant):
            return [if_true if cond.value else if_false]

        return [Instructions([cond, JumpIfNot(len(if_true) + 2), pop, if_true,
                              Jump(len(if_false) + 1), pop, if_false])]


class AndOperator(AbstractOperator):
    """
    A special operator which is not an instruction.  This class
    implements the ``and`` operator.
    """

    def fold(self, elems):
        """
        Perform constant folding.  If the result of applying the
        operator to the elements would be a fixed constant value,
        returns the result of applying the operator to the operands.
        Otherwise, returns an instance of ``Instructions`` containing
        the instructions necessary to apply the operator.

        :param elems: A list (or list-like object) containing the
                      elements.

        :returns: A list of one element, containing the instructions
                  necessary to implement the operator.
        """

        lhs, rhs = elems

        if isinstance(lhs, Constant):
            return [rhs if lhs.value else lhs]

        return [Instructions([lhs, JumpIfNot(len(rhs) + 1), pop, rhs])]


class OrOperator(object):
    """
    A special operator which is not an instruction.  This class
    implements the ``or`` operator.
    """

    def fold(self, elems):
        """
        Perform constant folding.  If the result of applying the
        operator to the elements would be a fixed constant value,
        returns the result of applying the operator to the operands.
        Otherwise, returns an instance of ``Instructions`` containing
        the instructions necessary to apply the operator.

        :param elems: A list (or list-like object) containing the
                      elements.

        :returns: A list of one element, containing the instructions
                  necessary to implement the operator.
        """

        lhs, rhs = elems

        if isinstance(lhs, Constant):
            return [lhs if lhs.value else rhs]

        return [Instructions([lhs, JumpIf(len(rhs) + 1), pop, rhs])]


# The pop instruction
pop = Pop()

# Unary operators
inv_op = GenericOperator(1, operator.inv, '~')
pos_op = GenericOperator(1, operator.pos, '+')
neg_op = GenericOperator(1, operator.neg, '-')
not_op = GenericOperator(1, operator.not_, 'not')

# Binary operators
pow_op = GenericOperator(2, operator.pow, '**')
mul_op = GenericOperator(2, operator.mul, '*')
true_div_op = GenericOperator(2, operator.truediv, '/')
floor_div_op = GenericOperator(2, operator.floordiv, '//')
mod_op = GenericOperator(2, operator.mod, '%')
add_op = GenericOperator(2, operator.add, '+')
sub_op = GenericOperator(2, operator.sub, '-')
left_shift_op = GenericOperator(2, operator.lshift, '<<')
right_shift_op = GenericOperator(2, operator.rshift, '>>')
bit_and_op = GenericOperator(2, operator.and_, '&')
bit_xor_op = GenericOperator(2, operator.xor, '^')
bit_or_op = GenericOperator(2, operator.or_, '|')
in_op = GenericOperator(2, lambda x, y: x in y, 'in')
not_in_op = GenericOperator(2, lambda x, y: x not in y, 'not in')
is_op = GenericOperator(2, operator.is_, 'is')
is_not_op = GenericOperator(2, operator.is_not, 'is not')
lt_op = GenericOperator(2, operator.lt, '<')
gt_op = GenericOperator(2, operator.gt, '>')
le_op = GenericOperator(2, operator.le, '<=')
ge_op = GenericOperator(2, operator.ge, '>=')
ne_op = GenericOperator(2, operator.ne, '!=')
eq_op = GenericOperator(2, operator.eq, '==')
and_op = AndOperator()
or_op = OrOperator()
item_op = GenericOperator(2, lambda x, y: x[y], '[]')

# The trinary operator
trinary_op = TrinaryOperator()

# The set authorization instruction
set_authz = SetAuthorization()
