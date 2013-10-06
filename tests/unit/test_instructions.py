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

import operator

import mock

from policies import instructions

import tests


class InstructionForTest(instructions.Instruction):
    def __call__(self, ctxt):
        pass

    def __hash__(self, *elems):
        return super(InstructionForTest, self).__hash__(*elems)

    def __eq__(self, other):
        return super(InstructionForTest, self).__eq__(other)


class Instruction2ForTest(InstructionForTest):
    pass


class TestInstruction(tests.TestCase):
    def test_eq(self):
        one = InstructionForTest()
        two = InstructionForTest()
        three = Instruction2ForTest()

        self.assertTrue(one.__eq__(two))
        self.assertFalse(one.__eq__(three))

    def test_ne(self):
        one = InstructionForTest()
        two = InstructionForTest()
        three = Instruction2ForTest()

        self.assertFalse(one.__ne__(two))
        self.assertTrue(one.__ne__(three))

    def test_hash(self):
        one = InstructionForTest()

        self.assertEqual(hash(one), hash((InstructionForTest,)))
        self.assertEqual(one.__hash__(1, 2, 3),
                         hash((InstructionForTest, 1, 2, 3)))


class TestConstant(tests.TestCase):
    def test_init(self):
        constant = instructions.Constant('value')

        self.assertEqual(constant.value, 'value')

    def test_call(self):
        ctxt = mock.Mock(stack=[])
        constant = instructions.Constant('value')

        constant(ctxt)

        self.assertEqual(ctxt.stack, ['value'])

    def test_hash(self):
        constant = instructions.Constant('value')

        self.assertEqual(hash(constant),
                         hash((instructions.Constant, 'value')))

    def test_eq(self):
        class Constant2(instructions.Constant):
            pass

        constant1 = instructions.Constant('value')
        constant2 = instructions.Constant('value')
        constant3 = instructions.Constant('other')
        constant4 = Constant2('value')

        self.assertTrue(constant1.__eq__(constant2))
        self.assertFalse(constant1.__eq__(constant3))
        self.assertFalse(constant1.__eq__(constant4))


class TestAttribute(tests.TestCase):
    def test_init(self):
        attribute = instructions.Attribute('attr')

        self.assertEqual(attribute.attribute, 'attr')

    def test_call(self):
        ctxt = mock.Mock(stack=[mock.Mock(attr='value')])
        attribute = instructions.Attribute('attr')

        attribute(ctxt)

        self.assertEqual(ctxt.stack, ['value'])

    def test_hash(self):
        attribute = instructions.Attribute('attr')

        self.assertEqual(hash(attribute),
                         hash((instructions.Attribute, 'attr')))

    def test_eq(self):
        class Attribute2(instructions.Attribute):
            pass

        attribute1 = instructions.Attribute('attr')
        attribute2 = instructions.Attribute('attr')
        attribute3 = instructions.Attribute('other')
        attribute4 = Attribute2('attr')

        self.assertTrue(attribute1.__eq__(attribute2))
        self.assertFalse(attribute1.__eq__(attribute3))
        self.assertFalse(attribute1.__eq__(attribute4))


class TestIdent(tests.TestCase):
    def test_init(self):
        ident = instructions.Ident('ident')

        self.assertEqual(ident.ident, 'ident')

    def test_call(self):
        ctxt = mock.Mock(**{
            'stack': [],
            'resolve.return_value': 'value',
        })
        ident = instructions.Ident('ident')

        ident(ctxt)

        self.assertEqual(ctxt.stack, ['value'])

    def test_hash(self):
        ident = instructions.Ident('ident')

        self.assertEqual(hash(ident),
                         hash((instructions.Ident, 'ident')))

    def test_eq(self):
        class Ident2(instructions.Ident):
            pass

        ident1 = instructions.Ident('ident')
        ident2 = instructions.Ident('ident')
        ident3 = instructions.Ident('other')
        ident4 = Ident2('ident')

        self.assertTrue(ident1.__eq__(ident2))
        self.assertFalse(ident1.__eq__(ident3))
        self.assertFalse(ident1.__eq__(ident4))


class OperatorForTest(instructions.Operator):
    def op(self, *args):
        return args


class Operator2ForTest(OperatorForTest):
    pass


class TestOperator(tests.TestCase):
    def test_init(self):
        op = OperatorForTest(5)

        self.assertEqual(op.count, 5)

    def test_call(self):
        ctxt = mock.Mock(stack=[1, 2, 3, 4, 5])
        op = OperatorForTest(3)

        op(ctxt)

        self.assertEqual(ctxt.stack, [1, 2, (3, 4, 5)])

    def test_hash(self):
        op_func = lambda x: x
        op = OperatorForTest(5)

        self.assertEqual(hash(op),
                         hash((OperatorForTest, 5)))
        self.assertEqual(op.__hash__(op_func),
                         hash((OperatorForTest, 5, op_func)))

    def test_eq(self):
        op1 = OperatorForTest(5)
        op2 = OperatorForTest(5)
        op3 = OperatorForTest(3)
        op4 = Operator2ForTest(5)

        self.assertTrue(op1.__eq__(op2))
        self.assertFalse(op1.__eq__(op3))
        self.assertFalse(op1.__eq__(op4))

    def test_fold_constant(self):
        elems = [instructions.Constant(i) for i in range(3)]
        op = OperatorForTest(3)

        result = op.fold(elems)

        self.assertEqual(result, [tuple(elems)])

    def test_fold_nonconstant(self):
        elems = [instructions.Constant(i) for i in range(2)]
        elems += [instructions.Ident('spam')]
        op = OperatorForTest(3)

        result = op.fold(elems)

        self.assertEqual(result, elems + [op])


class TestGenericOperator(tests.TestCase):
    def test_init(self):
        gen_op = instructions.GenericOperator(3, 'op')

        self.assertEqual(gen_op.count, 3)
        self.assertEqual(gen_op._op, 'op')

    def test_hash(self):
        gen_op = instructions.GenericOperator(3, 'op')

        self.assertEqual(hash(gen_op),
                         hash((instructions.GenericOperator, 3, 'op')))

    def test_eq(self):
        class GenericOperator2(instructions.GenericOperator):
            pass

        gen_op1 = instructions.GenericOperator(3, 'op')
        gen_op2 = instructions.GenericOperator(3, 'op')
        gen_op3 = instructions.GenericOperator(2, 'op')
        gen_op4 = instructions.GenericOperator(3, 'other')
        gen_op5 = GenericOperator2(3, 'op')

        self.assertTrue(gen_op1.__eq__(gen_op2))
        self.assertFalse(gen_op1.__eq__(gen_op3))
        self.assertFalse(gen_op1.__eq__(gen_op4))
        self.assertFalse(gen_op1.__eq__(gen_op5))

    def test_op(self):
        op = mock.Mock(return_value='value')
        gen_op = instructions.GenericOperator(3, op)

        result = gen_op.op(1, 2, 3)

        self.assertEqual(result, 'value')
        op.assert_called_once_with(1, 2, 3)


class TestSetOperator(tests.TestCase):
    def test_init(self):
        set_op = instructions.SetOperator(5)

        self.assertEqual(set_op.count, 5)
        self.assertEqual(set_op._op, frozenset)


class TestCallOperator(tests.TestCase):
    def test_op(self):
        func = mock.Mock(return_value='value')
        call_op = instructions.CallOperator(5)

        result = call_op.op(func, 1, 2, 3, 4)

        self.assertEqual(result, 'value')
        func.assert_called_once_with(1, 2, 3, 4)

    def test_fold(self):
        elems = [instructions.Constant(i) for i in range(3)]
        call_op = instructions.CallOperator(3)

        result = call_op.fold(elems)

        self.assertEqual(result, elems + [call_op])


class TestInOperator(tests.TestCase):
    def test_op(self):
        exemplar = frozenset([1, 3, 5])

        self.assertTrue(instructions.in_op.op(1, exemplar))
        self.assertFalse(instructions.in_op.op(2, exemplar))
        self.assertTrue(instructions.in_op.op(3, exemplar))
        self.assertFalse(instructions.in_op.op(4, exemplar))
        self.assertTrue(instructions.in_op.op(5, exemplar))


class TestNotInOperator(tests.TestCase):
    def test_op(self):
        exemplar = frozenset([1, 3, 5])

        self.assertFalse(instructions.not_in_op.op(1, exemplar))
        self.assertTrue(instructions.not_in_op.op(2, exemplar))
        self.assertFalse(instructions.not_in_op.op(3, exemplar))
        self.assertTrue(instructions.not_in_op.op(4, exemplar))
        self.assertFalse(instructions.not_in_op.op(5, exemplar))


class TestAndOperator(tests.TestCase):
    def test_op(self):
        self.assertEqual(instructions.and_op.op(False, False), False)
        self.assertEqual(instructions.and_op.op(True, False), False)
        self.assertEqual(instructions.and_op.op(False, True), False)
        self.assertEqual(instructions.and_op.op(True, 'foo'), 'foo')


class TestOrOperator(tests.TestCase):
    def test_op(self):
        self.assertEqual(instructions.or_op.op(False, False), False)
        self.assertEqual(instructions.or_op.op('foo', False), 'foo')
        self.assertEqual(instructions.or_op.op(False, 'foo'), 'foo')
        self.assertEqual(instructions.or_op.op('foo', 'bar'), 'foo')


class TestItemOperator(tests.TestCase):
    def test_op(self):
        exemplar = {'a': 1, 'b': 2}

        self.assertEqual(instructions.item_op.op(exemplar, 'a'), 1)
        self.assertEqual(instructions.item_op.op(exemplar, 'b'), 2)
        self.assertRaises(KeyError, instructions.item_op.op,
                          exemplar, 'c')


class TestTrinaryOperator(tests.TestCase):
    def test_op(self):
        self.assertEqual(instructions.trinary_op.op(True, 1, 2), 1)
        self.assertEqual(instructions.trinary_op.op(False, 1, 2), 2)
