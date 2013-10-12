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


class InstructionForTest(instructions.AbstractInstruction):
    def __call__(self, ctxt):
        pass

    def __repr__(self):
        return ''

    def __hash__(self, *elems):
        return super(InstructionForTest, self).__hash__(*elems)

    def __eq__(self, other):
        return super(InstructionForTest, self).__eq__(other)


class Instruction2ForTest(InstructionForTest):
    pass


class TestAbstractInstruction(tests.TestCase):
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


class TestInstructions(tests.TestCase):
    @mock.patch.object(instructions.Instructions, '_linearize',
                       return_value=[1, 2, 3])
    def test_init(self, mock_linearize):
        insts = instructions.Instructions([3, 2, 1])

        self.assertEqual(insts.instructions, (1, 2, 3))
        mock_linearize.assert_called_once_with([3, 2, 1])

    @mock.patch.object(instructions.Instructions, '_linearize',
                       side_effect=lambda x: x)
    def test_repr(self, mock_linearize):
        insts = instructions.Instructions([1, 2, 3])

        self.assertEqual(repr(insts), 'Instructions((1, 2, 3))')

    @mock.patch.object(instructions.Instructions, '_linearize',
                       side_effect=lambda x: x)
    def test_call(self, mock_linearize):
        calls_obj = mock.Mock()
        insts = instructions.Instructions([calls_obj.one, calls_obj.two,
                                           calls_obj.three, calls_obj.four])

        insts('ctxt')

        calls_obj.assert_has_calls([
            mock.call.one('ctxt'),
            mock.call.two('ctxt'),
            mock.call.three('ctxt'),
            mock.call.four('ctxt'),
        ])

    @mock.patch.object(instructions.Instructions, '_linearize',
                       side_effect=lambda x: x)
    def test_call_no_authz(self, mock_linearize):
        calls_obj = mock.Mock()
        insts = instructions.Instructions([calls_obj.one, calls_obj.two,
                                           instructions.set_authz,
                                           calls_obj.three, calls_obj.four])

        insts('ctxt', True)

        calls_obj.assert_has_calls([
            mock.call.one('ctxt'),
            mock.call.two('ctxt'),
        ])
        self.assertEqual(len(calls_obj.method_calls), 2)

    @mock.patch.object(instructions.Instructions, '_linearize',
                       side_effect=lambda x: x)
    def test_hash(self, mock_linearize):
        insts = instructions.Instructions([1, 2, 3])

        self.assertEqual(hash(insts),
                         hash((instructions.Instructions, 1, 2, 3)))

    @mock.patch.object(instructions.Instructions, '_linearize',
                       side_effect=lambda x: x)
    def test_eq(self, mock_linearize):
        class Instructions2(instructions.Instructions):
            pass

        insts1 = instructions.Instructions([1, 2, 3])
        insts2 = instructions.Instructions([1, 2, 3])
        insts3 = instructions.Instructions([3, 2, 1])
        insts4 = Instructions2([1, 2, 3])

        self.assertTrue(insts1.__eq__(insts2))
        self.assertFalse(insts1.__eq__(insts3))
        self.assertFalse(insts1.__eq__(insts4))

    def test_linearize(self):
        with mock.patch.object(instructions.Instructions, '_linearize',
                               side_effect=lambda x: x):
            insts1 = instructions.Instructions([1, 2, 3])
            insts2 = instructions.Instructions(['a', 'b', 'c'])
            insts3 = instructions.Instructions([insts2, 'd', 'e'])
        feed = [9, 8, insts1, 7, 6, insts3, 5, 4]

        result = list(instructions.Instructions._linearize(feed))

        self.assertEqual(result, [
            9, 8, 1, 2, 3, 7, 6, 'a', 'b', 'c', 'd', 'e', 5, 4
        ])


class TestConstant(tests.TestCase):
    def test_init(self):
        constant = instructions.Constant('value')

        self.assertEqual(constant.value, 'value')

    def test_repr(self):
        constant = instructions.Constant('value')

        self.assertEqual(repr(constant), "Constant('value')")

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

    def test_repr(self):
        attribute = instructions.Attribute('attr')

        self.assertEqual(repr(attribute), "Attribute('attr')")

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

    def test_repr(self):
        ident = instructions.Ident('ident')

        self.assertEqual(repr(ident), "Ident('ident')")

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
        op = OperatorForTest(5, 'opstr')

        self.assertEqual(op.count, 5)
        self.assertEqual(op.opstr, 'opstr')

    def test_repr(self):
        op = OperatorForTest(5, 'opstr')

        self.assertEqual(repr(op), "OperatorForTest(5, 'opstr')")

    def test_call(self):
        ctxt = mock.Mock(stack=[1, 2, 3, 4, 5])
        op = OperatorForTest(3, 'opstr')

        op(ctxt)

        self.assertEqual(ctxt.stack, [1, 2, (3, 4, 5)])

    def test_hash(self):
        op_func = lambda x: x
        op = OperatorForTest(5, 'opstr')

        self.assertEqual(hash(op),
                         hash((OperatorForTest, 5)))
        self.assertEqual(op.__hash__(op_func),
                         hash((OperatorForTest, 5, op_func)))

    def test_eq(self):
        op1 = OperatorForTest(5, 'op1')
        op2 = OperatorForTest(5, 'op2')
        op3 = OperatorForTest(3, 'op3')
        op4 = Operator2ForTest(5, 'op4')

        self.assertTrue(op1.__eq__(op2))
        self.assertFalse(op1.__eq__(op3))
        self.assertFalse(op1.__eq__(op4))

    def test_fold_constant(self):
        elems = [instructions.Constant(i) for i in range(3)]
        op = OperatorForTest(3, 'opstr')

        result = op.fold(elems)

        self.assertEqual(len(result), 1)
        self.assertTrue(isinstance(result[0], instructions.Constant))
        self.assertEqual(result[0].value, tuple(i.value for i in elems))

    def test_fold_nonconstant(self):
        elems = [instructions.Constant(i) for i in range(2)]
        elems += [instructions.Ident('spam')]
        op = OperatorForTest(3, 'opstr')

        result = op.fold(elems)

        self.assertEqual(len(result), 1)
        self.assertTrue(isinstance(result[0], instructions.Instructions))
        self.assertEqual(result[0].instructions, tuple(elems + [op]))


class TestGenericOperator(tests.TestCase):
    def test_init(self):
        gen_op = instructions.GenericOperator(3, 'op', 'opstr')

        self.assertEqual(gen_op.count, 3)
        self.assertEqual(gen_op.opstr, 'opstr')
        self.assertEqual(gen_op._op, 'op')

    def test_hash(self):
        gen_op = instructions.GenericOperator(3, 'op', 'opstr')

        self.assertEqual(hash(gen_op),
                         hash((instructions.GenericOperator, 3, 'op')))

    def test_eq(self):
        class GenericOperator2(instructions.GenericOperator):
            pass

        gen_op1 = instructions.GenericOperator(3, 'op', 'op1')
        gen_op2 = instructions.GenericOperator(3, 'op', 'op2')
        gen_op3 = instructions.GenericOperator(2, 'op', 'op3')
        gen_op4 = instructions.GenericOperator(3, 'other', 'op4')
        gen_op5 = GenericOperator2(3, 'op', 'op5')

        self.assertTrue(gen_op1.__eq__(gen_op2))
        self.assertFalse(gen_op1.__eq__(gen_op3))
        self.assertFalse(gen_op1.__eq__(gen_op4))
        self.assertFalse(gen_op1.__eq__(gen_op5))

    def test_op(self):
        op = mock.Mock(return_value='value')
        gen_op = instructions.GenericOperator(3, op, 'opstr')

        result = gen_op.op(1, 2, 3)

        self.assertEqual(result, 'value')
        op.assert_called_once_with(1, 2, 3)


class TestTrinaryOperator(tests.TestCase):
    def test_init(self):
        trinary = instructions.TrinaryOperator()

        self.assertEqual(trinary.count, 3)
        self.assertEqual(trinary.opstr, 'if/else')

    def test_op(self):
        trinary = instructions.TrinaryOperator()

        self.assertEqual(trinary.op(1, 'true', 'false'), 'true')
        self.assertEqual(trinary.op(0, 'true', 'false'), 'false')

    def test_fold_constant_true(self):
        elems = [instructions.Constant(True), instructions.Ident('a'),
                 instructions.Ident('b')]
        trinary = instructions.TrinaryOperator()

        result = trinary.fold(elems)

        self.assertEqual(len(result), 1)
        self.assertEqual(result, [elems[1]])

    def test_fold_constant_false(self):
        elems = [instructions.Constant(False), instructions.Ident('a'),
                 instructions.Ident('b')]
        trinary = instructions.TrinaryOperator()

        result = trinary.fold(elems)

        self.assertEqual(len(result), 1)
        self.assertEqual(result, [elems[2]])

    def test_fold_nonconstant(self):
        elems = [instructions.Ident('a'), instructions.Constant('true'),
                 instructions.Constant('false')]
        trinary = instructions.TrinaryOperator()

        result = trinary.fold(elems)

        self.assertEqual(len(result), 1)
        self.assertTrue(isinstance(result[0], instructions.Instructions))
        self.assertEqual(result[0].instructions, tuple(elems + [trinary]))


class TestSetOperator(tests.TestCase):
    def test_init(self):
        set_op = instructions.SetOperator(5)

        self.assertEqual(set_op.count, 5)
        self.assertEqual(set_op.opstr, 'set')

    def test_op(self):
        set_op = instructions.SetOperator(5)

        result = set_op.op(3, 5, 7)

        self.assertEqual(result, frozenset([3, 5, 7]))


class TestCallOperator(tests.TestCase):
    def test_init(self):
        call_op = instructions.CallOperator(5)

        self.assertEqual(call_op.count, 5)

    def test_repr(self):
        call_op = instructions.CallOperator(5)

        self.assertEqual(repr(call_op), "CallOperator(5)")

    def test_call_basic(self):
        func = mock.Mock(return_value='value', spec=[])
        ctxt = mock.Mock(stack=[func, 1, 2, 3, 4])
        call_op = instructions.CallOperator(5)

        call_op(ctxt)

        self.assertEqual(ctxt.stack, ['value'])
        func.assert_called_once_with(1, 2, 3, 4)

    def test_call_want_context_false(self):
        func = mock.Mock(return_value='value', _policies_want_context=False)
        ctxt = mock.Mock(stack=[func, 1, 2, 3, 4])
        call_op = instructions.CallOperator(5)

        call_op(ctxt)

        self.assertEqual(ctxt.stack, ['value'])
        func.assert_called_once_with(1, 2, 3, 4)

    def test_call_want_context_true(self):
        func = mock.Mock(return_value='value', _policies_want_context=True)
        ctxt = mock.Mock(stack=[func, 1, 2, 3, 4])
        call_op = instructions.CallOperator(5)

        call_op(ctxt)

        self.assertEqual(ctxt.stack, [])
        func.assert_called_once_with(ctxt, 1, 2, 3, 4)

    def test_hash(self):
        call_op = instructions.CallOperator(5)

        self.assertEqual(hash(call_op),
                         hash((instructions.CallOperator, 5)))

    def test_eq(self):
        class CallOperator2(instructions.CallOperator):
            pass

        call_op1 = instructions.CallOperator(5)
        call_op2 = instructions.CallOperator(5)
        call_op3 = instructions.CallOperator(3)
        call_op4 = CallOperator2(5)

        self.assertTrue(call_op1.__eq__(call_op2))
        self.assertFalse(call_op1.__eq__(call_op3))
        self.assertFalse(call_op1.__eq__(call_op4))

    # def test_op(self):
    #     func = mock.Mock(return_value='value')
    #     call_op = instructions.CallOperator(5)

    #     result = call_op.op(func, 1, 2, 3, 4)

    #     self.assertEqual(result, 'value')
    #     func.assert_called_once_with(1, 2, 3, 4)


class TestSetAuthorization(tests.TestCase):
    def test_repr(self):
        authz = instructions.SetAuthorization()

        self.assertEqual(repr(authz), "SetAuthorization()")

    @mock.patch('policies.authorization.Authorization', return_value='authz')
    def test_call(self, mock_Authorization):
        ctxt = mock.Mock(stack=['zhtua'], attrs='defaults')
        authz = instructions.SetAuthorization()

        authz(ctxt)

        self.assertEqual(ctxt.stack, [])
        self.assertEqual(ctxt.authz, 'authz')
        mock_Authorization.assert_called_once_with('zhtua', 'defaults')

    def test_hash(self):
        authz = instructions.SetAuthorization()

        self.assertEqual(hash(authz),
                         hash((instructions.SetAuthorization,)))

    def test_eq(self):
        class SetAuthorization2(instructions.SetAuthorization):
            pass

        authz1 = instructions.SetAuthorization()
        authz2 = instructions.SetAuthorization()
        authz3 = SetAuthorization2()

        self.assertTrue(authz1.__eq__(authz2))
        self.assertFalse(authz1.__eq__(authz3))


class TestAuthorizationAttr(tests.TestCase):
    def test_init(self):
        attr = instructions.AuthorizationAttr('attr')

        self.assertEqual(attr.attribute, 'attr')

    def test_repr(self):
        attr = instructions.AuthorizationAttr('attr')

        self.assertEqual(repr(attr), "AuthorizationAttr('attr')")

    def test_call(self):
        ctxt = mock.Mock(stack=['value'], authz=mock.Mock(_attrs={}))
        attr = instructions.AuthorizationAttr('attr')

        attr(ctxt)

        self.assertEqual(ctxt.stack, [])
        self.assertEqual(ctxt.authz._attrs, {'attr': 'value'})

    def test_hash(self):
        attr = instructions.AuthorizationAttr('attr')

        self.assertEqual(hash(attr),
                         hash((instructions.AuthorizationAttr, 'attr')))

    def test_eq(self):
        class AuthorizationAttr2(instructions.AuthorizationAttr):
            pass

        attr1 = instructions.AuthorizationAttr('attr')
        attr2 = instructions.AuthorizationAttr('attr')
        attr3 = instructions.AuthorizationAttr('other')
        attr4 = AuthorizationAttr2('attr')

        self.assertTrue(attr1.__eq__(attr2))
        self.assertFalse(attr1.__eq__(attr3))
        self.assertFalse(attr1.__eq__(attr4))


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
