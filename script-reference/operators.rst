Operators
=========

The Bro scripting language supports the following operators.  Note that
each data type only supports a subset of these operators.  For more
details, see the documentation about the `data types <types.html>`_.

Relational operators
--------------------

The relational operators evaluate to type :bro:type:`bool`.

In addition to numeric operands, the relational operators also work with
operands of type :bro:type:`interval`, :bro:type:`time`, :bro:type:`string`,
:bro:type:`port`, :bro:type:`addr`, and :bro:type:`set`.


+------------------------------+--------------+
| Name                         | Syntax       |
+==============================+==============+
| Equality                     | *a* == *b*   |
+------------------------------+--------------+
| Inequality                   | *a* != *b*   |
+------------------------------+--------------+
| Less than                    | *a* < *b*    |
+------------------------------+--------------+
| Less than or equal           | *a* <= *b*   |
+------------------------------+--------------+
| Greater than                 | *a* > *b*    |
+------------------------------+--------------+
| Greater than or equal        | *a* >= *b*   |
+------------------------------+--------------+


Logical operators
-----------------

The logical operators require operands of type :bro:type:`bool`, and
evaluate to type :bro:type:`bool`.

+------------------------------+--------------+
| Name                         | Syntax       |
+==============================+==============+
| Logical AND                  | *a* && *b*   |
+------------------------------+--------------+
| Logical OR                   | *a* \|\| *b* |
+------------------------------+--------------+
| Logical NOT                  | ! *a*        |
+------------------------------+--------------+


Arithmetic operators
--------------------

+------------------------------+-------------+-------------------------------+
| Name                         | Syntax      | Notes                         |
+==============================+=============+===============================+
| Addition                     | *a* + *b*   | For :bro:type:`string`        |
|                              |             | operands, this performs       |
|                              |             | string concatenation.         |
+------------------------------+-------------+-------------------------------+
| Subtraction                  | *a* - *b*   |                               |
+------------------------------+-------------+-------------------------------+
| Multiplication               | *a* \* *b*  |                               |
+------------------------------+-------------+-------------------------------+
| Division                     | *a* / *b*   | For :bro:type:`int` or        |
|                              |             | :bro:type:`count` operands,   |
|                              |             | the fractional part of the    |
|                              |             | result is dropped.            |
+------------------------------+-------------+-------------------------------+
| Modulo                       | *a* % *b*   | Operand types cannot be       |
|                              |             | "double".                     |
+------------------------------+-------------+-------------------------------+
| Unary plus                   | \+ *a*      |                               |
+------------------------------+-------------+-------------------------------+
| Unary minus                  | \- *a*      |                               |
+------------------------------+-------------+-------------------------------+
| Pre-increment                | ++ *a*      | Operand type cannot be        |
|                              |             | "double".                     |
+------------------------------+-------------+-------------------------------+
| Pre-decrement                | ``--`` *a*  | Operand type cannot be        |
|                              |             | "double".                     |
+------------------------------+-------------+-------------------------------+
| Absolute value               | \| *a* \|   | If operand is                 |
|                              |             | :bro:type:`string`,           |
|                              |             | :bro:type:`set`,              |
|                              |             | :bro:type:`table`, or         |
|                              |             | :bro:type:`vector`, this      |
|                              |             | evaluates to number           |
|                              |             | of elements.                  |
+------------------------------+-------------+-------------------------------+

Bitwise operators
-----------------

The bitwise operators work with operands of type :bro:type:`count` or
``vector of count``, but the bitwise complement operator works with ``count``
only.

+------------------------------+-------------+
| Name                         | Syntax      |
+==============================+=============+
| Bitwise AND                  | *a* & *b*   |
+------------------------------+-------------+
| Bitwise OR                   | *a* | *b*   |
+------------------------------+-------------+
| Bitwise XOR                  | *a* ^ *b*   |
+------------------------------+-------------+
| Bitwise complement           | ~ *a*       |
+------------------------------+-------------+

Set operators
-------------

+------------------------------+-------------+
| Name                         | Syntax      |
+==============================+=============+
| Set intersection             | *s1* & *s2* |
+------------------------------+-------------+
| Set union                    | *s1* | *s2* |
+------------------------------+-------------+
| Set difference               | *s1* - *s2* |
+------------------------------+-------------+

Assignment operators
--------------------

The assignment operators evaluate to the result of the assignment.

The "+=" operator can also be used to append an element to the end of a
vector.  For example, ``v += e`` is equivalent to ``v[|v|] = e``.

+------------------------------+-------------+
| Name                         | Syntax      |
+==============================+=============+
| Assignment                   | *a* = *b*   |
+------------------------------+-------------+
| Addition assignment          | *a* += *b*  |
+------------------------------+-------------+
| Subtraction assignment       | *a* -= *b*  |
+------------------------------+-------------+


Record field operators
----------------------

The record field operators take a :bro:type:`record` as the first operand,
and a field name as the second operand.  For both operators, the specified
field name must be in the declaration of the record type.

+------------------------------+-------------+-------------------------------+
| Name                         | Syntax      | Notes                         |
+==============================+=============+===============================+
| Field access                 | *a* $ *b*   |                               |
+------------------------------+-------------+-------------------------------+
| Field value existence test   | *a* ?$ *b*  | Evaluates to type             |
|                              |             | :bro:type:`bool`.             |
|                              |             | True if the specified field   |
|                              |             | has been assigned a value, or |
|                              |             | false if not.                 |
+------------------------------+-------------+-------------------------------+


Pattern operators
-----------------

In the table below, *p* is a pattern, and *s* is a string.

+------------------------------+-------------+-------------------------------+
| Name                         | Syntax      | Notes                         |
+==============================+=============+===============================+
| Exact matching               | *p* == *s*  | Evaluates to a boolean,       |
|                              |             | indicating if the entire      |
|                              |             | string exactly matches the    |
|                              |             | pattern.                      |
+------------------------------+-------------+-------------------------------+
| Embedded matching            | *p* in *s*  | Evaluates to a boolean,       |
|                              |             | indicating if pattern is      |
|                              |             | found somewhere in the string.|
+------------------------------+-------------+-------------------------------+
| Conjunction                  | *p1* & *p2* | Evaluates to a pattern that   |
|                              |             | represents matching p1        |
|                              |             | followed by p2.               |
+------------------------------+-------------+-------------------------------+
| Disjunction                  | *p1* | *p2* | Evaluates to a pattern that   |
|                              |             | represents matching p1 or p2. |
+------------------------------+-------------+-------------------------------+


Type casting
------------

The "as" operator performs type casting and the "is" operator checks if a
type cast is supported or not.  For both operators, the first operand is a
value and the second operand is the name of a Bro script type (either built-in
or user-defined).

+------------------------------+-------------+-------------------------------+
| Name                         | Syntax      | Notes                         |
+==============================+=============+===============================+
| Type cast                    | *v* as *t*  | Cast value "v" into type "t". |
|                              |             | Evaluates to the value casted |
|                              |             | to the specified type.        |
|                              |             | If this is not a supported    |
|                              |             | cast, then a runtime error is |
|                              |             | triggered.                    |
+------------------------------+-------------+-------------------------------+
| Check if a cast is supported | *v* is *t*  | Evaluates to boolean. If true,|
|                              |             | then "v as t" would succeed.  |
+------------------------------+-------------+-------------------------------+

Only the following kinds of type casts are supported currently:

- Broker values (i.e., :bro:see:`Broker::Data` values returned from
  functions such as :bro:id:`Broker::data`) can be casted to their
  corresponding Bro script types.
- A value of declared type "any" can be casted to its actual underlying type.
- All values can be casted to their declared types (i.e., this is a no-op).

The function in this example tries to cast a value to a string::

    function example(a: any)
        {
        local s: string;

        if ( a is string )
            s = (a as string);
        }


Other operators
---------------

+--------------------------------+-------------------+------------------------+
| Name                           | Syntax            | Notes                  |
+================================+===================+========================+
| Membership test                | *a* in *b*        |Evaluates to type       |
|                                |                   |:bro:type:`bool`. Works |
|                                |                   |with :bro:type:`string`,|
|                                |                   |:bro:type:`pattern`,    |
|                                |                   |:bro:type:`subnet`,     |
|                                |                   |:bro:type:`set`,        |
|                                |                   |:bro:type:`table`, or   |
|                                |                   |:bro:type:`vector`      |
|                                |                   |operands.  Do not       |
|                                |                   |confuse this use of "in"|
|                                |                   |with that used in a     |
|                                |                   |:bro:keyword:`for`      |
|                                |                   |statement.              |
+--------------------------------+-------------------+------------------------+
| Non-membership test            | *a* !in *b*       |This is the logical NOT |
|                                |                   |of the "in" operator.   |
|                                |                   |For example: "a !in b"  |
|                                |                   |is equivalent to        |
|                                |                   |"!(a in b)".            |
+--------------------------------+-------------------+------------------------+
| Table or vector element access | *a* [ *b* ]       |This operator can also  |
|                                |                   |be used with a          |
|                                |                   |:bro:type:`set`, but    |
|                                |                   |only with the           |
|                                |                   |:bro:keyword:`add` or   |
|                                |                   |:bro:keyword:`delete`   |
|                                |                   |statement.              |
+--------------------------------+-------------------+------------------------+
| Substring extraction           | *a* [ *b* : *c* ] |See the                 |
|                                |                   |:bro:type:`string` type |
|                                |                   |for more details.       |
+--------------------------------+-------------------+------------------------+
| Create a deep copy             | copy ( *a* )      |This is relevant only   |
|                                |                   |for data types that are |
|                                |                   |assigned by reference,  |
|                                |                   |such as                 |
|                                |                   |:bro:type:`vector`,     |
|                                |                   |:bro:type:`set`,        |
|                                |                   |:bro:type:`table`,      |
|                                |                   |and :bro:type:`record`. |
+--------------------------------+-------------------+------------------------+
| Module namespace access        | *a* \:\: *b*      |The first operand is the|
|                                |                   |module name, and the    |
|                                |                   |second operand is an    |
|                                |                   |identifier that refers  |
|                                |                   |to a global variable,   |
|                                |                   |enumeration constant, or|
|                                |                   |user-defined type that  |
|                                |                   |was exported from the   |
|                                |                   |module.                 |
+--------------------------------+-------------------+------------------------+
| Conditional                    | *a* ? *b* : *c*   |The first operand must  |
|                                |                   |evaluate to type        |
|                                |                   |:bro:type:`bool`.       |
|                                |                   |If true, then the       |
|                                |                   |second expression is    |
|                                |                   |evaluated and is the    |
|                                |                   |result of the entire    |
|                                |                   |expression.  Otherwise, |
|                                |                   |the third expression is |
|                                |                   |evaluated and is the    |
|                                |                   |result of the entire    |
|                                |                   |expression. The types of|
|                                |                   |the second and third    |
|                                |                   |operands must be        |
|                                |                   |compatible.             |
+--------------------------------+-------------------+------------------------+

