========
Policies
========

A package for interpretation and enforcement of access control
policies.

Introduction
============

It is often necessary to separate code that performs an action from
the code that performs the access check.  One reason for this is to
accommodate different users with different access control
requirements.  For instance, one user may be operating a system
internally, where all authenticated users should be able to perform
all actions, whereas another user may need to lock down specific
operations so they can only be executed by administrators.

The ``policies`` package is designed to accommodate these needs.
Access control policies can be expressed as strings, using a subset of
Python; then, these policies can be loaded into a ``policies.Policy``
object.  When an access determination needs to be made, a call to the
``policies.Policy.evaluate()`` method will evaluate a named policy
rule and return an ``Authorization`` object, which evaluates as either
``True`` or ``False``.

The policy strings may be loaded from any source.  They are simply
strings, written in a subset of the Python language, and allow much of
the expressive power of Python.  The policy language has syntax for
making function calls, including functions defined as entrypoints_;
this allows any desired access control policy to be implemented for
any application using ``policies``.

``policies`` for Developers
===========================

The ``policies`` package is easy for developers to use; simply
instantiate a ``policies.Policy`` object with an optional entrypoint
group and dictionary of built-in functions (defaults to select Python
builtins, available as ``policies.Policy.builtins``), then add rules
to the object.  This can be done by assigning the rule text using the
dictionary item setting syntax, like so::

    policy['rule_name'] = "user.is_admin()"

Alternatively, the rule text can be passed to ``policies.Rule`` and
set using the ``policies.Policy.set_rule()`` method, like so::

    rule = policies.Rule("rule_name", "user.is_admin()")
    policy.set_rule(rule)

These two different methods allow for the rules to be loaded from any
desired source, such as a file or a database.

Evaluation of a policy rule is as simple as calling the
``policies.Policy.evaluate()`` function::

    authz = policy.evaluate("rule_name", {'user': user})

The ``authz`` value can then be used to determine if the operation is
allowed by the policy::

    if authz:
        # Perform the operation here
	pass
    else:
        # Tell the user he's unprivileged
	pass

Note the dictionary passed as the second argument to
``policy.evaluate()`` above; this allows variables to be passed in to
policy rules.

Authorization Attributes
------------------------

The return value from ``policy.evaluate()`` is not a simple ``True``
or ``False`` value; it is an instance of ``policies.Authorization``.
The reason for this is that the policy language allows for setting
*authorization attributes*.  To explain what this is about, let's
assume that the operation we're writing a policy for is a user update
operation.  Obviously, we want the user to be able to update certain
parts of their own record, but others--say, payment status--should
only be available to administrators.  We can write this all in one
rule in the policy language::

    user.is_admin() or user == target {{ payment=user.is_admin() }}

When we evaluate this rule, the ``policies.Authorization`` object
returned will test ``True`` or ``False`` depending on the result of
evaluating the first part of the rule, ``user.is_admin() or user ==
target``.  However, the ``authz`` object will now also have an
attribute named ``payment``; this attribute will have the value
obtained by computing ``user.is_admin()``.

Authorization attributes default to ``None`` if the policy language
doesn't set them.  This default can be overridden by passing a
dictionary of attribute defaults to the ``policies.Rule`` instance
when it is created, or by declaring the rule using
``policies.Policy.declare()``.

Note that authorization attribute names CANNOT begin with an
underscore ("_").

Declaring Policy Rules
----------------------

Setting policy rules has been described above, but what about setting
up defaults for the policy rules?  This can be done using the
``policies.Policy.declare()`` method::

    policy.declare("rule_name", text="user.is_admin()")

This can also be used to set defaults for authorization attributes, by
passing a dictionary of those defaults as the ``attrs`` keyword
argument.

The ``policy.declare()`` method also allows associating documentation
text with the rule and the authorization attributes, using the ``doc``
and ``attr_docs`` keyword arguments; calling ``policy.declare()`` will
result in the creation of ``policies.RuleDoc`` objects to contain the
passed-in documentation.  These objects can be retrieved using the
``policies.Policy.get_doc()`` and ``policies.Policy.get_docs()``
methods, and could be used to generate sample policy configuration
files.

Variable Resolution in Policy Rules
-----------------------------------

When a variable is encountered in a policy rule, it must be resolved
to an actual value.  The first place searched when resolving variables
is the dictionary of variables that was passed to
``policies.Policy.evaluate()``; values passed here override any other
source.

If the variable cannot be found in the dictionary passed to
``policies.Policy.evaluate()``, then a dictionary of builtins is
searched; by default, these builtins are the ones in
``policies.Policy.builtins``, and represent a subset of the Python
builtins.  These builtins can be overridden by passing a dictionary as
the ``builtins`` parameter of the ``policies.Policy`` constructor.
Note that one special builtin exists which is not listed in
``policies.Policy.builtins``, and which will be added to the builtins
passed to the ``policies.Policy`` constructor: the ``rule()`` builtin
allows for one rule to call another.  It can be overridden, if
desired, by passing an alternate value for the "rule" key in the
``builtins`` dictionary.

If the variable cannot be resolved from either of the sources above,
it is next searched for using entrypoints_.  The entrypoint group to
search can be specified as the ``group`` argument to the
``policies.Policy`` constructor.  There is no default for the
entrypoint group, so if left unset, no entrypoints will be resolved.
Any entrypoints found will be cached for the lifetime of the
``policies.Policy`` object.  It is recommended that you set ``group``
to be the name of your application, followed by a period, followed by
the name "policies"; e.g., if your application was called "spam", you
would use "spam.policies".  Using an entrypoint group allows your
users to set up arbitrary functions for use in evaluating access
control policies, and thus allows them ultimate control over access.

If a variable cannot be resolved using any of the above sources, its
value will be ``None``.  This is as opposed to the standard Python
behavior of raising a ``NameError``.  The ``policies`` package is
designed to be as tolerant of user errors as possible.

``policies`` for Users
======================

Policy rules are written in a subset of the Python expression
language.  The singleton values ``True``, ``False``, and ``None`` are
recognized, as are single- and double-quoted strings, integers, and
floats.  The set literal syntax is also recognized, i.e., ``{1, 2,
3}`` represents the value ``frozenset([1, 2, 3])``.  Tuple literals,
list literals, dictionary literals, and comprehensions are not
supported, although the ``tuple()``, ``list()``, and ``dict()``
builtins are available, as are ``set()`` and ``frozenset()``.

In addition to the literal values mentioned above, the policy language
also supports attribute reference, subscription (``x[index]``), and
function calls.  Note that "slicing" (``x[index:index]``) is not
supported, however.  Finally, all arithmetic, logical, and comparison
operators are supported, as is the Python "trinary" syntax (``a if b
else c``).

As an example, let's suppose that a particular rule is controlling
update access to a user record.  The ``user`` variable will be the
user requesting the operation, and ``target`` will be the user record
the operation is to act upon.  The policy we want to implement is to
allow a given user to update only their own record, but we want
administrators to be able to update any user record.  We'll assume
that ``user`` has a boolean attribute named ``admin`` that is ``True``
if the user is an administrator.  Under these assumptions, the policy
rule could be written as::

    user == target or user.admin

It is also possible to call methods on an object.  Lets say that,
instead of a boolean attribute named ``admin`` that specifies whether
a user is an admin, we instead base administrator status on the
members of a group.  We assume that the ``user`` object has an
``in_group()`` method.  We could then write the rule as::

    user == target or user.in_group("administrators")

Finally, it is also possible to call functions.  If the
``policies.Policy()`` class was instantiated with an entrypoint group,
you can install a package with a function defined in that entrypoint
group (see entrypoints_), which will then be available to policy
rules.  This allows ultimate control over access control.  Note that
only positional arguments can be passed to functions; keyword
arguments are not available.

Note that operator short-circuiting is implemented; that is, in an
expression like ``user == target or user.admin``, if the ``user ==
target`` clause evaluates to ``True``, then ``user.admin`` will not be
evaluated.  This applies for the logical operators (``and`` and
``or``), as well as in the "trinary" syntax.  Constant folding is also
implemented, so rule text like ``5 + 23 > user.spam`` will only
compute the operation ``5 + 23`` once, during rule parsing.

Authorization Attributes
------------------------

Let us take the example from above and add one more requirement.
Let's say that one of the things the user update operation can update
is the current payment status on a user.  Obviously, that is something
that we don't want a user to be able to update; only administrators
should be able to update the payment status.  A developer can allow
this particular subset of functionality to be controlled separately
using an *authorization attribute*.  For the example above, let's
assume that the ``payment`` authorization attribute can control access
to the update of the payment status.  Now we can rewrite the policy
rule as::

    user == target or user.admin {{ payment=user.admin }}

More than one authorization attribute can be computed by separating
them with commas.  Let's assume that we have an authorization
attribute ``name`` that allows updating the user's name, and we want
to allow only the user to alter the name; we could write the rule as::

    user == target or user.admin {{ payment=user.admin,
                                    name=user==target }}

Evaluating Other Rules
----------------------

Each rule has an associated name.  It is possible to define an
arbitrary rule, and then evaluate it from another rule.  Taking our
example from above, let's assume that an admin must not only be in the
"administrators" group, but must also have ``admin`` set to ``True``
on their user record.  (This could be the case if your policy requires
administrators to explicitly turn on their administrative privileges.)
We could create an "is_admin" rule that looks like this::

    user.in_group("administrators") and user.admin

We could then write the rule controlling access to the user update
operation as::

    user == target or rule("is_admin")

Note that any authorization attributes on the "is_admin" rule will be
ignored; to set an authorization attribute on the user update
operation, they have to be explicitly declared::

    user == target or rule("is_admin") {{ payment=rule("is_admin"),
                                          name=user==target }}

Available Builtins
------------------

The following Python builtins are available:

* ``abs()``
* ``basestring()``
* ``bin()``
* ``bool()``
* ``bytes()``
* ``callable()``
* ``chr()``
* ``complex()``
* ``dict()``
* ``divmod()``
* ``enumerate()``
* ``float()``
* ``format()``
* ``frozenset()``
* ``getattr()``
* ``hasattr()``
* ``hash()``
* ``hex()``
* ``id()``
* ``int()``
* ``isinstance()``
* ``issubclass()``
* ``iter()``
* ``len()``
* ``list()``
* ``long()``
* ``max()``
* ``min()``
* ``next()``
* ``object()``
* ``oct()``
* ``ord()``
* ``pow()``
* ``range()``
* ``repr()``
* ``reversed()``
* ``round()``
* ``set()``
* ``sorted()``
* ``str()``
* ``sum()``
* ``tuple()``
* ``type()``
* ``unichr()``
* ``unicode()``
* ``xrange()``
* ``zip()``

Advanced Function Calls
=======================

Under normal circumstances, functions are called with only the
arguments passed in the rule text, and their return values are then
pushed onto the stack in place of those function arguments.  However,
certain functions--such as the ``rule()`` function--need access to the
context object (``policies.PolicyContext``).  In the case of
``rule()``, this allows it to keep a cache of rules that have been
evaluated for the duration of the ``policies.Policy.evaluate()`` call,
as well as looking up the rule to be evaluated.

To facilitate functions like ``rule()``, use the
``@policies.want_context`` decorator.  The ``policies.PolicyContext``
object will be passed as the first argument of the function, with
remaining arguments passed after that.  Note that all the arguments
will be popped off the stack, but the function's return value will
*not* be pushed on the stack; a function decorated with
``@policies.want_context`` must perform its own manipulation of the
stack.  For a function like this to push a return value on the stack,
and assuming that the context argument is ``ctxt``, the relevant code
would be::

    ctxt.stack.append("value")

In instances where you're using functions decorated with
``@policies.want_context``, it may be necessary to perform some
application-specific initialization on the ``policies.PolicyContext``
class, such as initializing a context attribute.  This may be done by
changing the ``policies.Policy.context_class`` setting.  Ideally, this
would be on an instance of ``policies.Policy``, rather than altering
the class itself, i.e.::

    policy = policies.Policy(...)
    policy.context_class = MyPolicyContext

Be very careful using ``@policies.want_context``.  Failing to push a
function return value onto the evaluation context stack could corrupt
the stack and cause a crash during rule evaluation.

``policies`` Internals
======================

This section intended for developers interested in developing the
``policies`` package itself.

Rule Parsing
------------

The policy rules work by parsing the rule text, using a parser built
with ``pyparsing``, into a sequence of *instructions*.  The
instructions are stored in postfix order; that is, an expression like
"1+2" would become a sequence of instructions that would first push
the value "1" onto a stack; then push the value "2" onto the stack;
then pop the top two values from the stack, add them, and push the
result onto the stack.  The instructions are all defined in
``instructions.py``, and the parser is defined in ``parser.py``.  The
``policies.Policy.evaluate()`` method simply constructs an evaluation
context (a ``policies.policy.PolicyContext`` object), then executes
the instructions.  Included in the instructions are instructions that
create a ``policy.Authorization`` object and set up the authorization
attributes (if any were defined); this authorization object is then
returned.

Caching
-------

Caching is used wherever possible to achieve the highest possible
efficiency.  Policy rules are compiled the first time they are
evaluated, and the instructions are then cached.  The results of an
entrypoint look-up are also cached, as are the results of calling
rules--in the example above::

    user == target or rule("is_admin") {{ payment=rule("is_admin"),
                                          name=user==target }}

The "is_admin" rule will only be evaluated one time.  This cache is
stored in the ``policies.PolicyContext`` object, in the ``rule_cache``
attribute.

.. _entrypoints: http://pythonhosted.org/distribute/pkg_resources.html#entry-points
