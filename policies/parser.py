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

import logging

import pyparsing

from policies.instructions import *


pyparsing.ParserElement.enablePackrat()


def unary_construct(tokens):
    """
    Construct proper instructions for unary expressions.  For
    instance, if the tokens represent "~ 1", this will return the
    instruction array "1 inv_op".

    :param tokens: The sequence of tokens.

    :returns: An instance of ``Instructions`` containing the list of
              instructions.
    """

    op, operand = tokens

    return op.fold([operand])


def binary_construct(tokens):
    """
    Construct proper instructions for binary expressions from a
    sequence of tokens at the same precedence level.  For instance, if
    the tokens represent "1 + 2 + 3", this will return the instruction
    array "1 2 add_op 3 add_op".

    :param tokens: The sequence of tokens.

    :returns: An instance of ``Instructions`` containing the list of
              instructions.
    """

    # Initialize the list of instructions we will return with the
    # left-most element
    instructions = [tokens[0]]

    # Now process all the remaining tokens, building up the array we
    # will return
    for i in range(1, len(tokens), 2):
        op, rhs = tokens[i:i + 2]

        # Add the right-hand side
        instructions.append(rhs)

        # Now apply constant folding
        instructions[-2:] = op.fold(instructions[-2:])

    return instructions


# Primitive values
TRUE = pyparsing.Keyword('True').setParseAction(lambda: [Constant(True)])
FALSE = pyparsing.Keyword('False').setParseAction(lambda: [Constant(False)])
NONE = pyparsing.Keyword('None').setParseAction(lambda: [Constant(None)])
INT = (
    pyparsing.Regex(r'[+-]?\d+') +
    ~pyparsing.FollowedBy(pyparsing.Regex(r'[.eE]'))
).setParseAction(lambda t: [Constant(int(t[0]))])
FLOAT = (
    pyparsing.Regex(r'[+-]?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?')
).setParseAction(lambda t: [Constant(float(t[0]))])
STR = (
    pyparsing.OneOrMore(pyparsing.quotedString)
).setParseAction(lambda t: [Constant(''.join(
    v[1:-1].decode('unicode-escape') for v in t))])
IDENT = (
    pyparsing.Regex(r'[a-zA-Z_][a-zA-Z0-9_]*')
).setParseAction(lambda t: [Ident(t[0])])
ATTR = (
    pyparsing.Regex(r'[a-zA-Z_][a-zA-Z0-9_]*')
).setParseAction(lambda t: [Attribute(t[0])])
AUTHATTR = (
    pyparsing.Regex(r'[a-zA-Z][a-zA-Z0-9_]*')
).setParseAction(lambda t: [AuthorizationAttr(t[0])])

# Unary operators
INV_OP = pyparsing.Literal('~').setParseAction(lambda: [inv_op])
POS_OP = pyparsing.Literal('+').setParseAction(lambda: [pos_op])
NEG_OP = pyparsing.Literal('-').setParseAction(lambda: [neg_op])
NOT_OP = pyparsing.Keyword('not').setParseAction(lambda: [not_op])

# Binary operators
POW_OP = pyparsing.Literal('**').setParseAction(lambda: [pow_op])
MUL_OP = pyparsing.Literal('*').setParseAction(lambda: [mul_op])
TRUE_DIV_OP = pyparsing.Literal('/').setParseAction(lambda: [true_div_op])
FLOOR_DIV_OP = pyparsing.Literal('//').setParseAction(lambda: [floor_div_op])
MOD_OP = pyparsing.Literal('%').setParseAction(lambda: [mod_op])
ADD_OP = pyparsing.Literal('+').setParseAction(lambda: [add_op])
SUB_OP = pyparsing.Literal('-').setParseAction(lambda: [sub_op])
LEFT_SHIFT_OP = pyparsing.Literal('<<').setParseAction(lambda: [left_shift_op])
RIGHT_SHIFT_OP = (
    pyparsing.Literal('>>')
).setParseAction(lambda: [right_shift_op])
BIT_AND_OP = pyparsing.Literal('&').setParseAction(lambda: [bit_and_op])
BIT_XOR_OP = pyparsing.Literal('^').setParseAction(lambda: [bit_xor_op])
BIT_OR_OP = pyparsing.Literal('|').setParseAction(lambda: [bit_or_op])
IN_OP = pyparsing.Keyword('in').setParseAction(lambda: [in_op])
NOT_IN_OP = (
    pyparsing.Keyword('not') + pyparsing.Keyword('in')
).setParseAction(lambda: [not_in_op])
IS_OP = pyparsing.Keyword('is').setParseAction(lambda: [is_op])
IS_NOT_OP = (
    pyparsing.Keyword('is') + pyparsing.Keyword('not')
).setParseAction(lambda: [is_not_op])
LT_OP = pyparsing.Literal('<').setParseAction(lambda: [lt_op])
GT_OP = pyparsing.Literal('>').setParseAction(lambda: [gt_op])
LE_OP = pyparsing.Literal('<=').setParseAction(lambda: [le_op])
GE_OP = pyparsing.Literal('>=').setParseAction(lambda: [ge_op])
NE_OP = pyparsing.Literal('!=').setParseAction(lambda: [ne_op])
EQ_OP = pyparsing.Literal('==').setParseAction(lambda: [eq_op])
AND_OP = pyparsing.Keyword('and').setParseAction(lambda: [and_op])
OR_OP = pyparsing.Keyword('or').setParseAction(lambda: [or_op])

# Trinary operators
IF_OP = pyparsing.Keyword('if').suppress()
ELSE_OP = pyparsing.Keyword('else').suppress()

# Useful tokens
LPAREN = pyparsing.Suppress('(')
RPAREN = pyparsing.Suppress(')')
LBRACKET = pyparsing.Suppress('[')
RBRACKET = pyparsing.Suppress(']')
LBRACE = pyparsing.Suppress('{')
RBRACE = pyparsing.Suppress('}')
LLBRACE = pyparsing.Suppress('{{')
RRBRACE = pyparsing.Suppress('}}')
COMMA = pyparsing.Suppress(',')
DOT = pyparsing.Suppress('.')
ASSIGN = pyparsing.Suppress('=')


# Hand-construct the expression.  We have to do this instead of using
# pyparsing.infixNotation(), because we need some special expressions
# at the top precedence level: attribute access, item access, and
# function call.  This internal expression does not have the parse
# action set that consolidates the result as an instance of
# Instructions, because this can mess up constant
# folding--particularly for set literals.
int_expr = pyparsing.Forward()

# Describe set literals
set_literal = (
    LBRACE +
    pyparsing.Optional(int_expr + pyparsing.ZeroOrMore(COMMA + int_expr)) +
    pyparsing.Optional(COMMA) +
    RBRACE
).setParseAction(lambda t: SetOperator(len(t)).fold(t))

# Build the value non-terminal
value = (TRUE | FALSE | NONE | INT | FLOAT | STR | IDENT | set_literal)

# Build the primary non-terminal
primary = value | (LPAREN + int_expr + RPAREN)

# Build the sub-elements of the expr0 precedence level: attribute
# access, item access, and function call
expr0 = pyparsing.Forward()
attr_pattern = DOT + ATTR
item_pattern = (
    LBRACKET + int_expr + RBRACKET
).setParseAction(lambda t: list(t) + [item_op])
call_pattern = (
    LPAREN +
    pyparsing.Optional(int_expr + pyparsing.ZeroOrMore(COMMA + int_expr)) +
    pyparsing.Optional(COMMA) +
    RPAREN
).setParseAction(lambda t: list(t) + [CallOperator(len(t) + 1)])
expr0_pattern = attr_pattern | item_pattern | call_pattern
expr0_match = (
    pyparsing.FollowedBy(primary + expr0_pattern) +
    primary + pyparsing.OneOrMore(expr0_pattern)
).setParseAction(lambda t: [Instructions(t)])
expr0 <<= (expr0_match | primary)

# Build the expr1 precedence level: **
expr1 = pyparsing.Forward()
expr1_ops = POW_OP
expr1_match = (
    pyparsing.FollowedBy(expr0 + expr1_ops + expr1) +
    expr0 + pyparsing.OneOrMore(expr1_ops + expr1)
).setParseAction(binary_construct)
expr1 <<= (expr1_match | expr0)

# Build the expr2 precedence level: unary +, -, and ~
expr2 = pyparsing.Forward()
expr2_ops = INV_OP | POS_OP | NEG_OP
expr2_match = (
    pyparsing.FollowedBy(expr2_ops + expr2) +
    pyparsing.Optional(expr2_ops) + expr2
).setParseAction(unary_construct)
expr2 <<= (expr2_match | expr1)

# Build the expr3 precedence level: arithmetic *, /, //, and %
expr3 = pyparsing.Forward()
# Note: Order here is important; // tried first, then /
expr3_ops = FLOOR_DIV_OP | TRUE_DIV_OP | MUL_OP | MOD_OP
expr3_match = (
    pyparsing.FollowedBy(expr2 + expr3_ops + expr2) +
    expr2 + pyparsing.OneOrMore(expr3_ops + expr2)
).setParseAction(binary_construct)
expr3 <<= (expr3_match | expr2)

# Build the expr4 precedence level: arithmetic + and -
expr4 = pyparsing.Forward()
expr4_ops = ADD_OP | SUB_OP
expr4_match = (
    pyparsing.FollowedBy(expr3 + expr4_ops + expr3) +
    expr3 + pyparsing.OneOrMore(expr4_ops + expr3)
).setParseAction(binary_construct)
expr4 <<= (expr4_match | expr3)

# Build the expr5 precedence level: >> and <<
expr5 = pyparsing.Forward()
expr5_ops = LEFT_SHIFT_OP | RIGHT_SHIFT_OP
expr5_match = (
    pyparsing.FollowedBy(expr4 + expr5_ops + expr4) +
    expr4 + pyparsing.OneOrMore(expr5_ops + expr4)
).setParseAction(binary_construct)
expr5 <<= (expr5_match | expr4)

# Build the expr6 precedence level: &
expr6 = pyparsing.Forward()
expr6_ops = BIT_AND_OP
expr6_match = (
    pyparsing.FollowedBy(expr5 + expr6_ops + expr5) +
    expr5 + pyparsing.OneOrMore(expr6_ops + expr5)
).setParseAction(binary_construct)
expr6 <<= (expr6_match | expr5)

# Build the expr7 precedence level: ^
expr7 = pyparsing.Forward()
expr7_ops = BIT_XOR_OP
expr7_match = (
    pyparsing.FollowedBy(expr6 + expr7_ops + expr6) +
    expr6 + pyparsing.OneOrMore(expr7_ops + expr6)
).setParseAction(binary_construct)
expr7 <<= (expr7_match | expr6)

# Build the expr8 precedence level: |
expr8 = pyparsing.Forward()
expr8_ops = BIT_OR_OP
expr8_match = (
    pyparsing.FollowedBy(expr7 + expr8_ops + expr7) +
    expr7 + pyparsing.OneOrMore(expr8_ops + expr7)
).setParseAction(binary_construct)
expr8 <<= (expr8_match | expr7)

# Build the expr9 precedence level: in, not in, is, is not, <, <=, >,
# >=, !=, and ==
expr9 = pyparsing.Forward()
# Note: Order here is important; e.g., <= tried first, then <
expr9_ops = (IN_OP | NOT_IN_OP | IS_NOT_OP | IS_OP |
             LE_OP | GE_OP | LT_OP | GT_OP | NE_OP | EQ_OP)
expr9_match = (
    pyparsing.FollowedBy(expr8 + expr9_ops + expr8) +
    expr8 + pyparsing.OneOrMore(expr9_ops + expr8)
).setParseAction(binary_construct)
expr9 <<= (expr9_match | expr8)

# Build the expr10 precedence level: unary not
expr10 = pyparsing.Forward()
expr10_ops = NOT_OP
expr10_match = (
    pyparsing.FollowedBy(expr10_ops + expr10) +
    pyparsing.Optional(expr10_ops) + expr10
).setParseAction(unary_construct)
expr10 <<= (expr10_match | expr9)

# Build the expr11 precedence level: logical and
expr11 = pyparsing.Forward()
expr11_ops = AND_OP
expr11_match = (
    pyparsing.FollowedBy(expr10 + expr11_ops + expr10) +
    expr10 + pyparsing.OneOrMore(expr11_ops + expr10)
).setParseAction(binary_construct)
expr11 <<= (expr11_match | expr10)

# Build the expr12 precedence level: logical or
expr12 = pyparsing.Forward()
expr12_ops = OR_OP
expr12_match = (
    pyparsing.FollowedBy(expr11 + expr12_ops + expr11) +
    expr11 + pyparsing.OneOrMore(expr12_ops + expr11)
).setParseAction(binary_construct)
expr12 <<= (expr12_match | expr11)

# Build the expr13 precedence level: trinary if/else
expr13 = pyparsing.Forward()
expr13_ops1 = IF_OP
expr13_ops2 = ELSE_OP
expr13_match = (
    pyparsing.FollowedBy(expr12 + expr13_ops1 + expr12 +
                         expr13_ops2 + expr12) +
    expr12 + expr13_ops1 + expr12 + expr13_ops2 + expr12
).setParseAction(lambda t: trinary_op.fold([t[1], t[0], t[2]]))
expr13 <<= (expr13_match | expr12)

# Finish building internal expressions
int_expr <<= expr13

# Build expressions as used by rules; this adds a parse action that
# wraps up all the instructions into a single instance of Instructions
expr = int_expr('expr')
expr.setParseAction(lambda t: [Instructions(t)])

# Set up authorization attribute assignment; this allows us to set
# arbitrary values on the authorization object, for the benefit of
# client code.  This could be used to restrict access to certain
# fields of a user object, for instance.
assignment = (
    AUTHATTR('attr') + ASSIGN +
    pyparsing.Optional(expr, default=Constant(None))
).setParseAction(lambda t: [Instructions([t['expr'], t['attr']])])

# Finally, we can build a rule
rule = (
    pyparsing.Optional(expr, default=Constant(False)) +
    pyparsing.Optional(
        LLBRACE +
        pyparsing.Optional(
            assignment +
            pyparsing.ZeroOrMore(COMMA + assignment)
        ) +
        pyparsing.Optional(COMMA) +
        RRBRACE
    )
).setParseAction(lambda t: [Instructions([t[0], set_authz] + t[1:])])


def parse_rule(name, rule_text, do_raise=False):
    """
    Parses the given rule text.

    :param name: The name of the rule.  Used when emitting log
                 messages regarding a failure to parse the rule.
    :param rule_text: The text of the rule to parse.
    :param do_raise: If ``False`` and the rule fails to parse, a log
                     message is emitted to the "policies" logger at
                     level WARN, and a rule that always evaluates to
                     ``False`` will be returned.  If ``True``, a
                     ``pyparsing.ParseException`` will be raised.

    :returns: An instance of ``policies.instructions.Instructions``,
              containing the instructions necessary to evaluate the
              authorization rule.
    """

    try:
        return rule.parseString(rule_text, parseAll=True)[0]
    except pyparsing.ParseException as exc:
        # Allow for debugging
        if do_raise:
            raise

        # Get the logger and emit our log messages
        log = logging.getLogger('policies')
        log.warn("Failed to parse rule %r: %s" % (name, exc))
        log.warn("Rule line: %s" % exc.line)
        log.warn("Location : %s^" % (" " * (exc.col - 1)))

        # Construct and return a fail-closed instruction
        return Instructions([Constant(False), set_authz])
