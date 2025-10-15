Operators
=========

The Zeek scripting language supports the following operators.  Note that
each data type only supports a subset of these operators.  For more
details, see the documentation about the :doc:`data types <types>`.

.. _relational-operators:

Relational operators
--------------------

The relational operators evaluate to type :zeek:type:`bool`.

In addition to numeric operands, the relational operators also work with
operands of type :zeek:type:`interval`, :zeek:type:`time`, :zeek:type:`string`,
:zeek:type:`port`, :zeek:type:`addr`, and :zeek:type:`set`.

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax

  * - Equality
    - ``a == b``

  * - Inquality
    - ``a != b``

  * - Less than
    - ``a < b``

  * - Less than or equal
    - ``a <= b``

  * - Greater than
    - ``a > b``

  * - Greater than or equal
    - ``a >= b``

.. _logical-operators:

Logical operators
-----------------

The logical operators require operands of type :zeek:type:`bool`, and
evaluate to type :zeek:type:`bool`.

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax

  * - Logical AND
    - ``a && b``

  * - Logical OR
    - ``a || b``

  * - Logical NOT
    - ``! a``

.. _arithmetic-operators:

Arithmetic operators
--------------------

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax
    - Notes

  * - Addition
    - ``a + b``
    - For :zeek:type:`string` operands, this performs string concatenation.

  * - Subtraction
    - ``a - b``
    -

  * - Multiplication
    - ``a * b``
    -

  * - Division
    - ``a / b``
    - For :zeek:type:`int` or :zeek:type:`count` operands, the fractional part
      of the result is dropped.

  * - Modulo
    - ``a % b``
    - Operand types cannot be :zeek:type:`double`.

  * - Unary plus
    - ``+a``
    -

  * - Unary minus
    - ``-a``
    -

  * - Pre-increment
    - ``++a``
    - Operand type cannot be :zeek:type:`double`.

  * - Pre-decrement
    - ``--a``
    - Operand type cannot be :zeek:type:`double`.

  * - Absolute value
    - ``|a|``
    - If operand is  :zeek:type:`string`, :zeek:type:`set`, :zeek:type:`table`,
      or  :zeek:type:`vector`, this evaluates to number of elements.

.. _bitwise-operators:

Bitwise operators
-----------------

The bitwise operators work with operands of type :zeek:type:`count` or ``vector
of count``. The bitwise shift operators can also work with :zeek:type:`int`.
The bitwise complement operator works with :zeek:type:`count` only.

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax

  * - Bitwise AND
    - ``a & b``

  * - Bitwise OR
    - ``a | b``

  * - Bitwise XOR
    - ``a ^ b``

  * - Bitwise left shift
    - ``a << b``

  * - Bitwise right shift
    - ``a >> b``

  * - Bitwise complement
    - ``~a``

.. _set-operators:

Set operators
-------------

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax

  * - Set intersection
    - ``s1 & s2``

  * - Set union
    - ``s1 | s2``

  * - Set difference
    - ``s1 - s2``

.. _assignment-operators:

Assignment operators
--------------------

The assignment operators evaluate to the result of the assignment.

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax

  * - Assignment
    - ``a = b``

  * - Addition assignment (more generally, "add to")
    - ``a += b``

  * - Subtraction assignment (more generally, "remove from")
    - ``a -= b``

Along with simple arithmetic, the ``+=`` operator supports adding elements to
:zeek:type:`table`,
:zeek:type:`set`,
:zeek:type:`vector`, and
:zeek:type:`pattern`
values, providing the righthand operand (RHS) has the same type.
For :zeek:type:`table` and :zeek:type:`set` values,
each of the RHS elements are added to the
table or set.  For :zeek:type:`vector`, the RHS elements are appended to
the end of the vector.  For :zeek:type:`pattern` values, the pattern is
modified to include the RHS pattern as an alterantive (regular expression ``|``
operator).

The ``-=`` operator provides analogous functionality for :zeek:type:`table`
and :zeek:type:`set` types, removing from the lefthand operand any elements
it has in common with the RHS value.  (Note that for tables, only the
indices are used; if the RHS value has an index in common with the lefthand
operand's value, it's removed even if the "yield" values differ.)

For all assignment operators, you can specify a comma-separated list of
values within braces (``{`` ... ``}``).  These are treated as *constructor*
arguments to create a corresponding :zeek:type:`table`, :zeek:type:`set`,
or :zeek:type:`vector` value, with the type of constructor taken from
the lefthand operand.  For example:

.. code-block:: zeek

    local t: table[count, string] of double;
    ...
    t += { [3, "three"] = 3.0, [9, "nine"] = 9.0 };

will add those two elements to the table ``t``.  For :zeek:type:`table`
and :zeek:type:`set` constructors, you can embed lists in the constructor
arguments to produce a cross-product expansion.  For example:

.. code-block:: zeek

    local t: table[count, string] of double;
    ...
    t += { [[3, 4], ["three", "four"]] = 3.0, [9, "nine"] = 9.0 };

results in ``t`` having five elements:

.. code-block:: zeek

    [3, three] = 3.0
    [3, four] = 3.0
    [4, three] = 3.0
    [4, four] = 3.0
    [9, nine] = 9.0

Finally, you can also use the ``+=`` operator to
append an element to the end of a
vector.  For example, ``v += e`` is equivalent to ``v[|v|] = e``,
providing that ``e``'s type corresponds to that of one of ``v``'s elements.

.. _record-field-operators:

Record field operators
----------------------

The record field operators take a :zeek:type:`record` as the first operand,
and a field name as the second operand.  For both operators, the specified
field name must be in the declaration of the record type.

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax
    - Notes

  * - Field access
    - ``a$b``
    -

  * - Field value existence test
    - ``a?$b``
    - Evaluates to type :zeek:type:`bool`.  True if the specified field has
      been assigned a value, or if not.

.. _pattern-operators:

Pattern operators
-----------------

In the table below, ``p`` is a pattern, and ``s`` is a string.

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax
    - Notes

  * - Exact matching
    - ``p == s``
    - Evaluates to a boolean, indicating if the entire string exactly matches
      the pattern.

  * - Embedded matching
    - ``p in s``
    - Evaluates to a boolean, indicating if pattern is found somewhere in the
      string.

  * - Conjunction
    - ``p1 & p2``
    - Evaluates to a pattern that represents matching ``p1`` followed by
      ``p2``.

  * - Disjunction
    - ``p1 | p2``
    - Evaluates to a pattern that represents matching ``p1`` or ``p2``.

Type casting
------------

The ``as`` operator performs type casting and the ``is`` operator checks if a
type cast is supported or not.  For both operators, the first operand is a
value and the second operand is the name of a Zeek script type (either built-in
or user-defined).

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax
    - Notes

  * - Type cast
    - ``v as t``
    - Cast value ``v`` into type ``t``. Evaluates to the value as cast to the
      specified type.  If this is not a  supported cast, then a runtime error
      is triggered.

  * - Check if a cast is supported
    - ``v is t``
    - Evaluates to :zeek:type:`bool`. If true,  then ``v as t`` would succeed.

Only the following kinds of type casts are supported currently:

- Broker values (i.e., :zeek:see:`Broker::Data` values returned from
  functions such as :zeek:id:`Broker::data`) can be cast to their
  corresponding Zeek script types.
- A value of declared type :zeek:type:`any` can be cast to its actual
  underlying type.
- All values can be cast to their declared types (i.e., this is a no-op).
- :zeek:type:`set` and :zeek:type:`vector` values can be converted into each
  other, with the following limitations: (1) A :zeek:type:`set` being converted
  into a :zeek:type:`vector` can only have a single index type.  Converting a
  set with multiple index types will return an error. (2) The :zeek:type:`set`
  and :zeek:type:`vector` types must have the same internal type.

The function in this example tries to cast a value to a string:

.. code-block:: zeek

    function example(a: any)
        {
        local s: string;

        if ( a is string )
            s = (a as string);
        }

The function in this example converts a set to a vector:

.. code-block:: zeek

    function example()
        {
	local s: set[count] = { 1, 2, 3 };
	local v = s as vector of count;
        }

Other operators
---------------

.. list-table::
  :header-rows: 1

  * - Name
    - Syntax
    - Notes

  * - Membership test
    - ``a in b``
    - Evaluates to type :zeek:type:`bool`.  Works with :zeek:type:`string`,
      :zeek:type:`pattern`, :zeek:type:`subnet`, :zeek:type:`set`,
      :zeek:type:`table`, or :zeek:type:`vector` operands.  Do not confuse this
      use of ``in`` with that used in a :zeek:keyword:`for`
      statement.

  * - Non-membership test
    - ``a !in b``
    - This is the logical NOT of the ``in`` operator.  For example:
      ``a !in b`` is equivalent to ``!(a in b)``.

  * - Table or vector element access
    - ``a[b]``
    - This operator can also be used with a :zeek:type:`set`, but only with the
      :zeek:keyword:`add` or :zeek:keyword:`delete` statement.

  * - Substring extraction
    - ``a[b:c]``
    - See the :zeek:type:`string` type for more details.

  * - Create a deep copy
    - ``copy(a)``
    - This is relevant only for data types that are assigned by reference, such
      as :zeek:type:`vector`, :zeek:type:`set`, :zeek:type:`table`, and
      :zeek:type:`record`.

  * - Module namespace access
    - ``a::b``
    - The first operand is the module name, and the second operand is an
      identifier that refers to a global variable, enumeration constant, or
      user-defined type that was exported from the module.

  * - Conditional
    - ``a ? b : c``
    - The first operand must evaluate to type :zeek:type:`bool`.  If true, then
      the second expression is evaluated and is the result of the entire
      expression.  Otherwise, the third expression is evaluated and is the
      result of the entire expression. The types of the second and third
      operands must be compatible.  Known as the ternary operator.
