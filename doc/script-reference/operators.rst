Operators
=========

The Bro scripting language supports the following operators.  Note that
each data type only supports a subset of these operators.  For more
details, see the documentation about the `data types <types.html>`_.

Relational operators
--------------------

The relational operators evaluate to type :bro:type:`bool`.

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


Assignment operators
--------------------

The assignment operators evaluate to the result of the assignment.

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


Other operators
---------------

+--------------------------------+-------------------+------------------------+
| Name                           | Syntax            | Notes                  |
+================================+===================+========================+
| Membership test                | *a* in *b*        |Evaluates to type       |
|                                |                   |:bro:type:`bool`. Do not|
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

