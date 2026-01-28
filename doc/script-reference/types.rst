Types
=====

The Zeek scripting language supports the following built-in types:

.. list-table::
  :header-rows: 1


  * - Name(s)
    - Description

  * - :zeek:type:`bool`
    - Boolean

  * - :zeek:type:`count`, :zeek:type:`int`, :zeek:type:`double`
    - Numeric types

  * - :zeek:type:`time`, :zeek:type:`interval`
    - Time types

  * - :zeek:type:`string`
    - String

  * - :zeek:type:`pattern`
    - Regular expression

  * - :zeek:type:`port`, :zeek:type:`addr`, :zeek:type:`subnet`
    - Network types

  * - :zeek:type:`enum`
    - Enumeration (user-defined type)

  * - :zeek:type:`table`, :zeek:type:`set`, :zeek:type:`vector`,
      :zeek:type:`record`
    - Container types

  * - :zeek:type:`function`, :zeek:type:`event`, :zeek:type:`hook`
    - Executable types

  * - :zeek:type:`file`
    - File type (only for writing)

  * - :zeek:type:`opaque`
    - Opaque type (for some built-in functions)

  * - :zeek:type:`any`
    - Any type (for functions or containers)

Here is a more detailed description of each type:


.. zeek:native-type:: addr

addr
----

A type representing an IP address.

IPv4 address constants are written in "dotted quad" format,
``A1.A2.A3.A4``, where ``A1``-``A4`` all lie between 0 and 255.

IPv6 address constants are written as colon-separated hexadecimal form
as described by :rfc:`2373` (including the mixed notation with embedded
IPv4 addresses as dotted-quads in the lower 32 bits), but additionally
encased in square brackets.  Some examples: ``[2001:db8::1]``,
``[::ffff:192.168.1.100]``, or
``[aaaa:bbbb:cccc:dddd:eeee:ffff:1111:2222]``.

Note that IPv4-mapped IPv6 addresses (i.e., addresses with the first 80
bits zero, the next 16 bits one, and the remaining 32 bits are the IPv4
address) are treated internally as IPv4 addresses (for example,
``[::ffff:192.168.1.100]`` is equal to ``192.168.1.100``).

Addresses can be compared for equality (``==``, ``!=``),
and also for ordering (``<``, ``<=``, ``>``, ``>=``).  The absolute value
of an address gives the size in bits (32 for IPv4, and 128 for IPv6).
Addresses can also be masked with ``/`` to produce a :zeek:type:`subnet`:

.. code-block:: zeek

    local a: addr = 192.168.1.100;
    local s: subnet = 192.168.0.0/16;

    if ( a/16 == s )
        print "true";

And checked for inclusion within a :zeek:type:`subnet` using ``in``
or ``!in``:

.. code-block:: zeek

    local a: addr = 192.168.1.100;
    local s: subnet = 192.168.0.0/16;

    if ( a in s )
        print "true";

You can check if a given ``addr`` is IPv4 or IPv6 using
the :zeek:id:`is_v4_addr` and :zeek:id:`is_v6_addr` built-in functions.

Hostname constants can also be used, but since a hostname can
correspond to multiple IP addresses, the type of such a variable is
``set[addr]``. For example:

.. code-block:: zeek

    local a = www.google.com;

.. note::

   This syntax is deprecated and slated for removal in Zeek 8.1.
   Consider the :zeek:see:`lookup_hostname` and
   :zeek:see:`blocking_lookup_hostname` functions instead.

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(foo)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%s", foo)``

   * - :zeek:see:`subnet`
     - :zeek:see:`addr_to_subnet` BIF
     - ``addr_to_subnet([::1])``


.. zeek:native-type:: any

any
---

Used to bypass strong typing.  For example, a function can take an
argument of type ``any`` when it may be of different types.
The only operation allowed on a variable of type ``any`` is assignment.

Note that users aren't expected to use this type.  It's provided mainly
for use by some built-in functions and scripts included with Zeek. For
example, passing a vector into a ``.bif`` function is best accomplished by
taking :zeek:type:`any` as an argument and casting it to a vector.


.. zeek:native-type:: bool

bool
----

Reflects a value with one of two meanings: true or false.  The two
``bool`` constants are ``T`` and ``F``.

The ``bool`` type supports the following operators: equality/inequality
(``==``, ``!=``), logical and/or (``&&``, ``||``), logical
negation (``!``), and absolute value (where ``|T|`` is ``1``, and ``|F|`` is
``0``, and in both cases the result type is :zeek:type:`count`).

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`count`
     - Absolute value operator
     - ``|foo|``

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(T)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%s", F)``


.. zeek:native-type:: count

count
-----

A numeric type representing a 64-bit unsigned integer.  A ``count``
constant is a string of digits, e.g. ``1234`` or ``0``.  A ``count``
can also be written in hexadecimal notation (in which case ``0x`` must
precede the hex digits), e.g. ``0xff`` or ``0xABC123``.

The ``count`` type supports the same operators as the :zeek:type:`int`
type, but a unary plus or minus applied to a ``count`` results in an
:zeek:type:`int`.

In addition, ``count`` types support more bitwise operations.  You can use
``&``, ``|``, ``^``, ``<<``, and ``>>`` for bitwise ``and``, ``or``,
``xor``, ``left shift``, and ``right shift``.  You can also use ``~``
for bitwise (one's) complement.

For unsigned arithmetic involving ``count`` types that cause overflows
(results that exceed the numeric limits of representable value in either
direction), Zeek's behavior is to wrap the result modulo 2^64 back into
the range of representable values (the same behavior as defined by C++).

.. note::

   Integer literals in Zeek that are not preceded by a unary ``+`` or ``-``
   are treated as the unsigned ``count`` type.  This can cause unintentional
   surprises is some situations, like for an absolute-value operation of
   ``|5 - 9|`` that results in an unsigned-integer overflow to the large number
   of ``18446744073709551612`` where ``|+5 - +9|`` results in signed-integer
   arithmetic and (likely) more expected result of ``4``.

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`addr`
     - :zeek:see:`count_to_v4_addr` BIF
     - ``count_to_v4_addr(2130706433)``

   * - :zeek:see:`bool`
     - Relational operator
     - ``foo > 0``

   * - :zeek:see:`double`
     - :zeek:see:`count_to_double` BIF
     - ``count_to_double(42)``

   * - :zeek:see:`double`
     - Addition operator
     - ``foo + 0.0``

   * - :zeek:see:`double`
     - Division operator
     - ``foo / 1.0``

   * - :zeek:see:`double`
     - Multiplication operator
     - ``foo * 1.0``

   * - :zeek:see:`double`
     - Subtraction operator
     - ``foo - 0.0``

   * - :zeek:see:`port`
     - :zeek:see:`count_to_port` BIF
     - ``count_to_port(80, tcp)``

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(foo)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%x", 3735928559)``


.. zeek:native-type:: double

double
------

A numeric type representing a double-precision floating-point
number.  Floating-point constants are written as a string of digits
with an optional decimal point, optional scale-factor in scientific
notation, and optional ``+`` or ``-`` sign.  Examples are ``-1234``,
``-1234e0``, ``3.14159``, and ``.003E-23``.

The ``double`` type supports the following operators:  arithmetic
operators (``+``, ``-``, ``*``, ``/``), comparison operators
(``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``), assignment operators
(``=``, ``+=``, ``-=``), unary plus and minus (``+``, ``-``), and
absolute value (e.g., ``|-3.14|`` is 3.14).

When using type inferencing use care so that the
intended type is inferred, e.g. ``local size_difference = 5`` will
infer :zeek:type:`count`, while ``local size_difference = 5.0``
will infer ``double``.

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`count`
     - :zeek:see:`double_to_count` BIF
     - ``double_to_count(1234.0)``

   * - :zeek:see:`interval`
     - :zeek:see:`double_to_interval` BIF
     - ``double_to_interval(86400.0)``

   * - :zeek:see:`time`
     - :zeek:see:`double_to_time` BIF
     - ``double_to_time(1626723410.4)``

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(foo)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%.2f", 3.14159265)``


.. zeek:native-type:: enum

enum
----

A type allowing the specification of a set of related values that
have no further structure.  An example declaration:

.. code-block:: zeek

    type color: enum { Red, White, Blue, };

The last comma after ``Blue`` is optional.  Both the type name ``color``
and the individual values (``Red``, etc. -- not ``color::Red``) have
global scope.

Enumerations may assign :zeek:type:`count` values explicitly:

.. code-block:: zeek

    type color: enum { Red = 10, White = 20, Blue = 30 };

Without explicit assignment, Zeek numbers enumerations sequentially starting
from 0. You may not mix explicit and implicit assignments.

The only operations allowed on enumerations are equality comparisons (``==``,
``!=``) and assignment (``=``). Enumerations do not automatically yield their
values or provide ordering (neither ``Red == 10`` nor ``Red < White`` works),
but the :zeek:see:`enum_to_int` BIF lets you retrieve an enumeration's numeric
value if you require such logic.

.. note::

   We recommend using explicit value assignment when relying on numeric values,
   since it avoids sensitivity to :zeek:keyword:`@load` sequencing when
   enumerations are :zeek:keyword:`redef`'d in multiple scripts.

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`int`
     - :zeek:see:`enum_to_int` BIF
     - ``enum_to_int(Intel::ADDR)``

   * - :zeek:see:`int`
     - Absolute value operator
     - ``|Intel::ADDR|``

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(foo)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%s", foo)``


.. zeek:native-type:: event

event
-----

Event handlers are nearly identical in both syntax and semantics to
a :zeek:type:`function`, with the two differences being that event
handlers have no return type since they never return a value, and
you cannot call an event handler.

Example:

.. code-block:: zeek

    event my_event(r: bool, s: string)
        {
        print "my_event", r, s;
        }

Instead of directly calling an event handler from a script, event
handler bodies are executed when they are invoked by one of three
different methods:

- From the event engine

    When the event engine detects an event for which you have
    defined a corresponding event handler, it queues an event for
    that handler.  The handler is invoked as soon as the event
    engine finishes processing the current packet and flushing the
    invocation of other event handlers that were queued first.

- With the ``event`` statement from a script

    Immediately queuing invocation of an event handler occurs like:

    .. code-block:: zeek

        event password_exposed(user, password);

    This assumes that ``password_exposed`` was previously declared
    as an event handler type with compatible arguments.

- Via the :zeek:keyword:`schedule` expression in a script

    This delays the invocation of event handlers until some time in
    the future.  For example:

    .. code-block:: zeek

        schedule 5 secs { password_exposed(user, password) };

Multiple event handler bodies can be defined for the same event handler
identifier and the body of each will be executed in turn.  Ordering
of their execution can be influenced with :zeek:attr:`&priority`.

Multiple alternate event prototype declarations are allowed, but the
alternates must be some subset of the first, canonical prototype and
arguments must match by name and type.  This allows users to define
handlers for any such prototype they may find convenient or for the core
set of handlers to be extended, changed, or deprecated without breaking
existing handlers a user may have written.  Example:

.. code-block:: zeek

    # Event Prototype Declarations
    global my_event: event(s: string, c: count);
    global my_event: event(c: count);
    global my_event: event();

    # Event Handler Definitions
    event my_event(s: string, c: count)
        {
        print "my event", s, c;
        }

    event my_event(c: count)
        {
        print "my event", c;
        }

    event my_event()
        {
        print "my event";
        }

By using alternate event prototypes, handlers are allowed to consume a
subset of the full argument list as given by the first prototype
declaration.  It also even allows arguments to be ordered differently
from the canonical prototype.

To use :zeek:attr:`&default` on event arguments, it must appear on the
first, canonical prototype.

Employing its static analysis capabilities, Zeek will warn if it cannot
determine that an event will ever be triggered. In case the warning is not
appropriate (e.g., the event might be triggered remotely via broker),
:zeek:attr:`&is_used` can be applied to suppress the warning.


.. zeek:native-type:: file

file
----

Zeek supports writing to files, but not reading from them (to read from
files see the :doc:`/frameworks/input`).  Files
can be opened using either the :zeek:id:`open` or :zeek:id:`open_for_append`
built-in functions, and closed using the :zeek:id:`close` built-in
function.  For example, declare, open, and write to a file and finally
close it like:

.. code-block:: zeek

    local f = open("myfile");
    print f, "hello, world";
    close(f);

Writing to files like this for logging usually isn't recommended, for better
logging support see :doc:`/frameworks/logging`.


.. zeek:native-type:: function

function
--------

Function types in Zeek are declared using::

    function( argument*  ): type

where ``argument*`` is a (possibly empty) comma-separated list of
arguments, and ``type`` is an optional return type.  For example:

.. code-block:: zeek

    global greeting: function(name: string): string;

Here ``greeting`` is an identifier with a certain function type.
The function body is not defined yet and ``greeting`` could even
have different function body values at different times.  To define
a function including a body value, the syntax is like:

.. code-block:: zeek

    function greeting(name: string): string
        {
        return "Hello, " + name;
        }

Note that in the definition above, it's not necessary for us to have
done the first (forward) declaration of ``greeting`` as a function
type, but when it is, the return type and argument list (including the
name of each argument) must match exactly.

Here is an example function that takes no parameters and does not
return a value:

.. code-block:: zeek

    function my_func()
        {
        print "my_func";
        }

Function types don't need to have a name and can be assigned anonymously:

.. code-block:: zeek

    greeting = function(name: string): string { return "Hi, " + name; };

And finally, the function can be called like:

.. code-block:: zeek

    print greeting("Dave");

.. _anonymous-function:

Anonymous functions and their closures
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Anonymously defined functions (lambdas) capture their closures. This means
that they can use variables from their enclosing scope at the time of their
creation.  In older-style deprecated functionality (capture by "reference"),
closure-capture happens automatically.  The current style
(capture by "copy") requires explicitly listing the captured variables.

Here is an example of a simple anonymous function that automatically
captures its closure in Zeek (deprecated functionality):

.. code-block:: zeek

    local make_adder = function(n: count): function(m: count): count
        {
        return function (m: count): count
            {
            return n + m;
            };
        };

    print make_adder(3)(5); # prints 8

    local three = make_adder(3);
    print three(5); # prints 8

Here ``make_adder`` is generating a function that captures ``n`` in its
closure.  The same, but in current (non-deprecated, closure-by-copy) form:

.. code-block:: zeek

    local make_adder = function(n: count): function(m: count): count
        {
        return function [n] (m: count): count
            {
            return n + m;
            };
        };

    print make_adder(3)(5); # prints 8

    local three = make_adder(3);
    print three(5); # prints 8

The only difference is that the inner anonymous function explicitly declares
that ``n`` is captured, by listing all of the captured variables in ``[...]``
after the :zeek:type:`function` keyword.  It is a compile-time error to fail to
list a captured variable (or to list the same variable more than once, or to
list a global variable).

Old-style capture-by-reference closure semantics means that those
anonymous functions can modify the variables in their closures. For example:

.. code-block:: zeek

    local n = 3;
    local f = function() { n += 1; print n; };
    f();     # prints 4
    print n; # prints 4
    n = 0;
    f();     # prints 1, since n is shared between outer and inner functions
    print n; # prints 1

The same in capture-by-copy, however, yields different results:

.. code-block:: zeek

    local n = 3;
    local f = function [n] () { n += 1; print n; };
    f();     # prints 4
    print n; # prints 3, since n is not shared
    n = 0;
    f();     # prints 5, since n persists for f
    print n; # prints 0

With capture-by-copy, by default variables are captured using the equivalent
of ``=`` assignments.  In Zeek, variable assignments use "shallow" copy,
meaning that assignments of aggregates share the same aggregate rather
than fully duplicating all of its members.  These semantics allow you to
get the equivalent of the original "reference" semantics by using record
fields rather than variables for the sharing.  For example:

.. code-block:: zeek

    type r: record { n: count; };
    ...
    local var = r($n=3);
    local f = function [var] () { var$n += 1; print var$n; };
    f();         # prints 4
    print var$n; # prints 4
    var$n = 0;
    f();         # prints 1, since n is shared between outer and inner functions
    print var$n; # prints 1

You can specify that a given variable should instead be captured using
a *deep* copy by preceding it with the ``copy`` keyword:

.. code-block:: zeek

    type r: record { n: count; };
    ...
    local var = r($n=3);
    local f = function [copy var] () { var$n += 1; print var$n; };
    f();         # prints 4
    print var$n; # prints 3, since the var aggregate is not shared
    var$n = 0;
    f();         # prints 5, since the function has its own deep copy of var
    print var$n; # prints 0

Finally, you can intermingle both shallow and deep copying, as shown in
this fragment:

.. code-block:: zeek

    type r: record { n: count; };
    ...
    local var1 = r($n=3);
    local var2 = r($n=7);
    local f = function [copy var1, var2] () { ...

where ``var1`` will be captured via deep-copy and ``var2`` via the normal
shallow-copy.

When anonymous functions are serialized over Broker they keep their closures,
but they will not continue to mutate the values from the sending script (either
directly, for reference semantics, or for shallow-copy aggregates, for copy
semantics).  At the time of serialization they create a copy of their closure.
Also, anonymous functions do not capture global variables in their closures and
thus will use the receiver's global variables.

In order to serialize an anonymous function, that function must have been
already declared on the receiver's end, because Zeek does not serialize the
function's source code. See :file:`testing/btest/language/closure-sending.zeek`
for an example of how to serialize anonymous functions over Broker.

.. _default-values:

Default values
^^^^^^^^^^^^^^

Function parameters may specify default values as long as they appear
last in the parameter list:

.. code-block:: zeek

    global foo: function(s: string, t: string &default="abc", u: count &default=0);

If a function was previously declared with default parameters, the
default expressions can be omitted when implementing the function
body and they will still be used for function calls that lack those
arguments.

.. code-block:: zeek

    function foo(s: string, t: string, u: count)
        {
        print s, t, u;
        }

And calls to the function may omit the defaults from the argument list:

.. code-block:: zeek

    foo("test");

Asynchronous functions
^^^^^^^^^^^^^^^^^^^^^^

Use of the ``return when`` construct renders a function *asynchronous*: it
will return its result at a later time, when an underlying condition becomes
fulfilled. See :zeek:keyword:`when` and the description of :ref:`asynchronous
returns <asynchronous-return>` for details.


.. zeek:native-type:: hook

hook
----

A hook is another flavor of function that shares characteristics of
both a :zeek:type:`function` and an :zeek:type:`event`.  They are like
events in that many handler bodies can be defined for the same hook
identifier and the order of execution can be enforced with
:zeek:attr:`&priority`.  They are more like functions in the way they
are invoked/called, because, unlike events, their execution is
immediate and they do not get scheduled through an event queue.
Also, a unique feature of a hook is that a given hook handler body
can short-circuit the execution of remaining hook handlers simply by
exiting from the body as a result of a :zeek:keyword:`break` statement (as
opposed to a :zeek:keyword:`return` or just reaching the end of the body).

A hook type is declared like::

    hook( argument* )

where ``argument*`` is a (possibly empty) comma-separated list of
arguments.  For example:

.. code-block:: zeek

    global myhook: hook(s: string, vs: vector of string);

Here ``myhook`` is the hook type identifier and no hook handler
bodies have been defined for it yet.  To define some hook handler
bodies the syntax looks like:

.. code-block:: zeek

    hook myhook(s: string, vs: vector of string) &priority=10
        {
        print "priority 10 myhook handler", s, vs;
        s = "bye";
        vs += "modified";
        }

    hook myhook(s: string, vs: vector of string)
        {
        print "break out of myhook handling", s, vs;
        break;
        }

    hook myhook(s: string, vs: vector of string) &priority=-5
        {
        print "not going to happen", s, vs;
        }

Note that the first (forward) declaration of ``myhook`` as a hook
type isn't strictly required.  Argument types must match for all
hook handlers and any forward declaration of a given hook.

To invoke immediate execution of all hook handler bodies, they
are called similarly to a function, except preceded by the ``hook``
keyword:

.. code-block:: zeek

    hook myhook("hi", vector("foo"));

or

.. code-block:: zeek

    if ( hook myhook("hi", vector("foo")) )
        print "all handlers ran";

And the output would look like::

    priority 10 myhook handler, hi, [foo]
    break out of myhook handling, hi, [foo, modified]

Note how the re-assigning of a ``hook`` argument (``s = "bye"`` in the example)
will not be visible to remaining ``hook`` handlers, but it's still possible
to modify values of composite/aggregate types like :zeek:type:`vector`,
:zeek:type:`record`, :zeek:type:`set`, or :zeek:type:`table`.

Hooks cannot return values, but the return value of a hook call is an
implicit :zeek:type:`bool` value. True (``T``) means that all handlers
for the hook were executed and none executed a ``break`` statement.
False (``F``) means that one handler halted further execution as a
result of a ``break`` statement.

Hooks are also allowed to have multiple/alternate prototype declarations,
just like an :zeek:see:`event`.


.. zeek:native-type:: int

int
---

A numeric type representing a 64-bit signed integer.  An ``int`` constant
is a string of digits preceded by a ``+`` or ``-`` sign, e.g.
``-42`` or ``+5`` (the ``+`` sign is optional but see note about type
inferencing below).  An ``int`` constant can also be written in
hexadecimal notation (in which case ``0x`` must be between the sign and
the hex digits), e.g. ``-0xFF`` or ``+0xabc123``.

The ``int`` type supports the following operators:  arithmetic
operators (``+``, ``-``, ``*``, ``/``, ``%``), comparison operators
(``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``), assignment operators
(``=``, ``+=``, ``-=``), pre-increment (``++``), pre-decrement
(``--``), unary plus and minus (``+``, ``-``), absolute value
(e.g., ``|-3|`` is 3, but the result type is :zeek:type:`count`), and
bitwise shift operations (``<<``, ``>>``).

.. note::

   Zeek's ``%`` operator is remainder, the same as C++. This is different
   than the modulo operator for negative numbers. If modulo is necessary,
   use :zeek:see:`modulo`.

When using type inferencing, use care so that the
intended type is inferred, e.g. ``local size_difference = 0`` will
infer :zeek:type:`count`, while ``local size_difference = +0``
will infer ``int``.

For signed-integer arithmetic involving ``int`` types that cause overflows
(results that exceed the numeric limits of representable values in either
direction), Zeek's behavior is generally undefined and one should not rely on
any observed behavior being consistent across compilers, platforms, time, etc.
The reason for this is that the C++ standard also deems this as undefined
behavior and Zeek does not currently attempt to detect such overflows within
its underlying C++ implementation (some limited cases may try to statically
determine at parse-time that an overflow will definitely occur and reject them
an error, but don't rely on that).

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`bool`
     - Relational operator
     - ``foo != 0``

   * - :zeek:see:`count`
     - Absolute value operator
     - ``|foo|``

   * - :zeek:see:`count`
     - :zeek:see:`int_to_count` BIF
     - ``int_to_count(42)``

   * - :zeek:see:`double`
     - :zeek:see:`int_to_double` BIF
     - ``int_to_double(foo)``

   * - :zeek:see:`double`
     - Addition operator
     - ``foo + 0.0``

   * - :zeek:see:`double`
     - Division operator
     - ``foo / 1.0``

   * - :zeek:see:`double`
     - Multiplication operator
     - ``foo * 1.0``

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(-10)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%s", 0)``


.. zeek:native-type:: interval

interval
--------

A temporal type representing a relative time.  An ``interval``
constant can be written as a numeric constant followed by a time
unit where the time unit is one of ``usec``, ``msec``, ``sec``, ``min``,
``hr``, or ``day`` which respectively represent microseconds, milliseconds,
seconds, minutes, hours, and days.  Whitespace between the numeric
constant and time unit is optional.  Appending the letter ``s`` to the
time unit in order to pluralize it is also optional (to no semantic
effect).  Examples of ``interval`` constants are ``3.5 min`` and
``3.5mins``.  An ``interval`` can also be negated, for example
``-12 hr`` represents "twelve hours in the past".

Intervals support addition and subtraction, the comparison operators
(``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``), the assignment
operators (``=``, ``+=``, ``-=``), and unary plus and minus (``+``, ``-``).

Intervals also support division (in which case the result is a
:zeek:type:`double` value).  An ``interval`` can be multiplied or divided
by an arithmetic type (``count``, ``int``, or ``double``) to produce
an ``interval`` value.  The absolute value of an ``interval`` is a
``double`` value equal to the number of seconds in the ``interval``
(e.g., ``|-1 min|`` is 60.0).

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`double`
     - :zeek:see:`interval_to_double` BIF
     - ``interval_to_double(5mins)``

   * - :zeek:see:`double`
     - Absolute value operator
     - ``|foo|``

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(foo)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%s", foo)``

   * - :zeek:see:`time`
     - Addition operator
     - ``5 mins + start_time``

   * - :zeek:see:`time`
     - Subtraction operator
     - ``start_time - 60 secs``


.. zeek:native-type:: opaque

opaque
------

A data type whose actual representation/implementation is
intentionally hidden, but whose values may be passed to certain
built-in functions that can actually access the internal/hidden resources.
Opaque types are differentiated from each other by qualifying them
like ``opaque of md5`` or ``opaque of sha1``.

An example use of this type is the set of built-in functions which
perform hashing:

.. code-block:: zeek

    local handle = md5_hash_init();
    # Explicitly -> local handle : opaque of md5 = ...
    md5_hash_update(handle, "test");
    md5_hash_update(handle, "testing");
    print md5_hash_finish(handle);

Here the opaque type is used to provide a handle to a particular
resource which is calculating an MD5 hash incrementally over
time, but the details of that resource aren't relevant, it's only
necessary to have a handle as a way of identifying it and
distinguishing it from other such resources.

The scripting layer implementations of these types are found primarily in
:doc:`/scripts/base/bif/zeek.bif.zeek` and a more granular look at them
can be found in ``src/OpaqueVal.h/cc`` inside the Zeek repo. Opaque types
are a good way to integrate functionality into Zeek without needing to
add an entire new type to the scripting language.

.. zeek:type:: paraglob

  An opaque type for creating and using paraglob data structures inside of
  Zeek. A paraglob is a data structure for fast string matching against a
  large set of glob style patterns. It can be loaded with a vector of
  patterns, and then queried with input strings. Note that these patterns are
  just strings, and not the pattern type built in to Zeek. For a query it
  returns all of the patterns that it contains matching that input string.

  Paraglobs offer significant performance advantages over making a pass over
  a vector of patterns and checking each one. Note though that initializing a
  paraglob can take some time for very large pattern sets (1,000,000+
  patterns) and care should be taken to only initialize one with a large
  pattern set when there is time for the paraglob to compile. Subsequent get
  operations run very quickly though, even for very large pattern sets.

  .. code-block:: zeek

    local v = vector("*", "d?g", "*og", "d?", "d[!wl]g");
    local p : opaque of paraglob = paraglob_init(v);
    print paraglob_match(p, "dog");
    # out: [*, *og, d?g, d[!wl]g]

  For more documentation on paraglob see :doc:`/components/index`.

.. zeek:see:: md5_hash_init sha1_hash_init sha256_hash_init
              hll_cardinality_add bloomfilter_basic_init


.. zeek:native-type:: pattern

pattern
-------

A type representing regular-expression patterns that can be used for fast
text-searching operations.  Pattern constants are created by enclosing text
within forward slashes (``/``) and support a large subset of the `flex lexical
analyzer <https://westes.github.io/flex/manual/Patterns.html>`_ syntax.  As in
other implementations, patterns consist of ordinary and special characters.
Patterns such as ``/a/`` or ``/A0123/`` match that specific character byte or
character sequence, case-sensitively. Special characters and modifiers customize
matching, as follows:

.. list-table::
  :header-rows: 1

  * - Syntax
    - Meaning

  * - ``^``
    - Matches the beginning of the input.

  * - ``$``
    - Matches the end of the input.

  * - ``.``
    - Matches any character except newline (but see the ``(?s:`` and ``/s`` modifiers).

  * - ``<expr>*``
    - Matches zero or more instances of ``expr``.

  * - ``<expr>+``
    - Matches one or more instances of ``expr``.

  * - ``<expr>?``
    - Matches zero or one instance of ``expr``.

  * - ``<expr>{n}``
    - Matches ``expr`` ``n`` times, where ``n`` is a non-negative integer.

  * - ``<expr>{n,}``
    - Matches ``expr`` ``n`` or more times, where ``n`` is a non-negative integer.

  * - ``<expr>{n,m}``
    - Matches ``expr`` between ``n`` and ``m`` times, inclusively, where ``n``
      and ``m`` are non-negative integers and ``m >= n``.

  * - ``<expr1>|<expr2>``
    - Matches either ``expr1`` or ``expr2``.

  * - ``(<expr>)``
    - Groups the contained expression to form a building-block of a more complex
      one.

  * - ``"<chars>"``
    - Matches literal strings, without the quotation marks. These always match
      as given, even if case-insensitivity is active.

  * - ``[<chars>]``
    - Defines a character class, matching any of the contained characters.

  * - ``[^<chars>]``
    - Defines a negated character class, matching any but the contained
      characters.

  * - ``<char1>-<char2>``
    - Inside a character class this specifies a range, matching any character
      between ``<char1>`` and ``<char2>``, inclusively. Outside a character
      class it matches the literal string.

  * - ``(?i:<expr>)``
    - Matches the expression case-insensitively.

  * - ``(?s:<expr>)``
    - Treats the input as a single line: the ``.`` character also matches
      newlines.

Zeek supports the following pre-defined character classes:

.. list-table::
  :header-rows: 1
  :widths: 20 20 60

  * - Shorthand
    - Equivalent to
    - Meaning

  * - ``[:alnum:]``
    - ``[A-Za-z0-9]``
    - Upper- and lowercase letters plus digits.

  * - ``[:alpha:]``
    - ``[A-Za-z]``
    - Upper- and lowercase letters.

  * - ``[:blank:]``
    - ``[ \t]``
    - The space or tab character.

  * - ``[:cntrl:]``
    -
    - Non-printable characters, a.k.a. control characters. See
      `iscntrl() <https://cplusplus.com/reference/cctype/iscntrl/>`_ for details.

  * - ``[:digit:]``
    - ``[0-9]``
    - Digits.

  * - ``[:graph:]``
    - ``[^ [:cntrl:]]``
    - Characters with graphic representation: everything other than space
      and control characters.

  * - ``[:print:]``
    - ``[^[:cntrl:]]``
    - Printable characters: those with graphic representation, plus the space character.

  * - ``[:punct:]``
    -
    - Punctuation: any characters with graphic representation that are not alphanumeric.

  * - ``[:space:]``
    - ``[ \t\n\r\f\v]``
    - Whitespace characters.

  * - ``[:xdigit:]``
    - ``[A-Fa-f0-9]``
    - Hexadecimal characters.

  * - ``[:lower:]``
    - ``[a-z]``
    - Lowercase letters.

  * - ``[:upper:]``
    - ``[A-Z]``
    - Uppercase letters.

To match special characters, escape them with a backslash (``\``).

Zeek also supports the following pattern-level operators and modifiers:

.. list-table::
  :header-rows: 1

  * - Example
    - Meaning

  * - ``/<expr1>/ | /<expr2>/``
    - Succeeds when either pattern matches the input.

  * - ``/<expr1>/ & /<expr2>/``
    - Succeeds when the concatenation of both patterns matches the input. Note
      that this differs from a logical "AND"; ordering matters.

  * - ``/<expr>/i``
    - Matches the expression case-insensitively, like ``(?i:<expr>)``. Use the
      latter when you need it to apply to only a part of a larger expression.

  * - ``/<expr>/s``
    - Treats the input as a single line, like ``(?s:<expr>)``. Use the
      latter when you need it to apply to only a part of a larger expression.

The speed of regular expression matching does not depend on the complexity or
size of the patterns.

Patterns support two types of matching, exact and embedded.
In exact matching the ``==`` equality relational operator is used
with one ``pattern`` operand and one :zeek:type:`string`
operand (order of operands does not matter) to check whether the full
string exactly matches the pattern.  In exact matching, the ``^``
beginning-of-line and ``$`` end-of-line anchors are redundant since
the pattern is implicitly anchored to the beginning and end of the
line to facilitate an exact match.  For example:

.. code-block:: zeek

    /foo|bar/ == "foo"

yields true, while:

.. code-block:: zeek

    /foo|bar/ == "foobar"

yields false.  The ``!=`` operator would yield the negation of ``==``.

In embedded matching the ``in`` operator is used with one
``pattern`` operand (which must be on the left-hand side) and
one :zeek:type:`string` operand, but tests whether the pattern
appears anywhere within the given string.  For example:

.. code-block:: zeek

    /foo|bar/ in "foobar"

yields true, while:

.. code-block:: zeek

    /^oob/ in "foobar"

is false since ``"oob"`` does not appear at the start of ``"foobar"``.  The
``!in`` operator would yield the negation of ``in``.

Additional examples:

- ``/foo+bar/`` matches ``"foobar"`` and ``"fooooobar"``, but not ``"fobar"``.
- ``/foo*bar/`` matches ``"fobar"``, ``"foobar"``, and ``"fooooobar"``.
- ``/foo?bar/`` matches ``"fobar"`` and ``"foobar"``, but not ``"fooooobar"``.
- ``/foo[b-d]ar/`` matches ``"foobar"``, ``"foocar"``, and ``"foodar"``.
- ``/foo/ | /bar/ in "foobar"`` yields true.
- ``/foo/ & /bar/ in "foobar"`` yields true, since ``/(foo)(bar)/`` appears in ``"foobar"``.
- ``/foo|bar/`` matches ``"foo"`` and ``"bar"``.
- ``/fo(o|b)ar/`` matches ``"fooar"`` and ``"fobar"``, but not ``"foo"`` or ``"bar"``.
- ``/foo|bar/i`` matches ``"foo"``, ``"Foo"``, ``"BaR"``, etc.
- ``/foo|(?i:bar)/`` matches ``"foo"`` and ``"BaR"``, but *not* ``"Foo"``.
- ``/"foo"/i`` matches ``"foo"``, but *not* ``"Foo"``.
- ``/foo.bar/`` doesn't match ``"foo\nbar"``, while ``/foo.bar/s`` does.

The ``i`` and ``s`` modifiers can also be combined in a single pattern
such as ``/foo/is`` or ``/bar/si``. In this case, both case-insensitivity
and single-line mode will apply to the pattern.

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(foo)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%s", foo)``


.. zeek:native-type:: port

port
----

A type representing transport-level port numbers (besides TCP and
UDP ports, there is a concept of an ICMP ``port`` where the source
port is the ICMP message type and the destination port the ICMP
message code).  A ``port`` constant is written as an unsigned integer
followed by one of ``/tcp``, ``/udp``, ``/icmp``, or ``/unknown``.

Ports support the comparison operators (``==``, ``!=``, ``<``, ``<=``,
``>``, ``>=``).  When comparing order across transport-level protocols,
``unknown`` < ``tcp`` < ``udp`` < ``icmp``, for example ``65535/tcp``
is smaller than ``0/udp``.

Note that you can obtain the transport-level protocol type of a ``port``
with the :zeek:id:`get_port_transport_proto` built-in function, and
the numeric value of a ``port`` with the :zeek:id:`port_to_count`
built-in function.

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`count`
     - :zeek:see:`port_to_count` BIF
     - ``port_to_count(53/udp)``

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(foo)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%s", foo)``


.. zeek:native-type:: record

record
------

A ``record`` is a collection of values.  Each value has a field name
and a type.  Values do not need to have the same type and the types
have no restrictions.  Field names must follow the same syntax as
regular variable names (except that field names are allowed to be the
same as local or global variables).  An example record type
definition:

.. code-block:: zeek

    type MyRecordType: record {
        c: count;
        s: string &optional;
    };

Records can be initialized or assigned as a whole in three different ways.
When assigning a whole record value, all fields that are not
:zeek:attr:`&optional` or have a :zeek:attr:`&default` attribute must
be specified.  First, the constructor can be explicitly named by type,
which is arguably most readable:

.. code-block:: zeek

    local r = MyRecordType($c = 42);

There's also a plain constructor syntax:

.. code-block:: zeek

    local r: MyRecordType = record($c = 7);

And lastly, a shorthand best reserved for situations such as large, repetitive
initializer blocks where typing is fairly obvious:

.. code-block:: zeek

    local r: MyRecordType = [$c = 13, $s = "thirteen"];

Access to a record field uses the dollar sign (``$``) operator, and
record fields can be assigned with this:

.. code-block:: zeek

    local r: MyRecordType;
    r$c = 13;

To test if a field that is :zeek:attr:`&optional` has been assigned a
value, use the ``?$`` operator (it returns a :zeek:type:`bool` value of
``T`` if the field has been assigned a value, or ``F`` if not):

.. code-block:: zeek

    if ( r ?$ s )
        ...


.. zeek:native-type:: set

set
---

A set is like a :zeek:type:`table`, but it is a collection of indices
that do not map to any yield value.

Declaration and initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets are declared with the syntax::

    set [ type^+ ]

where ``type^+`` is one or more types separated by commas.  The index type
cannot be any of the following types: :zeek:type:`file`, :zeek:type:`opaque`,
:zeek:type:`any`.

Sets can be initialized by listing elements enclosed by curly braces:

.. code-block:: zeek

    global s: set[port] = { 21/tcp, 23/tcp, 80/tcp, 443/tcp };
    global s2: set[port, string] = { [21/tcp, "ftp"], [23/tcp, "telnet"] };

A set constructor (equivalent to above example) can also be used to
create a set:

.. code-block:: zeek

    global s3 = set(21/tcp, 23/tcp, 80/tcp, 443/tcp);

Set constructors can also be explicitly named by a type, which is
useful when a more complex index type could otherwise be
ambiguous:

.. code-block:: zeek

    type MyRec: record {
        a: count &optional;
        b: count;
    };

    type MySet: set[MyRec];

    global s4 = MySet([$b=1], [$b=2]);

Insertion and removal
^^^^^^^^^^^^^^^^^^^^^

Elements are added with :zeek:keyword:`add`:

.. code-block:: zeek

    add s[22/tcp];

Nothing happens if the element with value ``22/tcp`` was already present in
the set.

Elements are removed with :zeek:keyword:`delete`:

.. code-block:: zeek

    delete s[21/tcp];

.. versionadded:: 7.0

Removing all set elements can be done with the :zeek:keyword:`delete`, too:

.. code-block:: zeek

    delete s;


Nothing happens if the element with value ``21/tcp`` isn't present in
the set.

Sets behave like tables when it comes to complex member types: indexing happens
via hashing at access time. See :zeek:type:`table` for details.

Lookup and iteration
^^^^^^^^^^^^^^^^^^^^

Set membership is tested with ``in`` or ``!in``:

.. code-block:: zeek

    if ( 21/tcp in s )
        ...

    if ( [21/tcp, "ftp"] !in s2 )
        ...

See the :zeek:keyword:`for` statement for info on how to iterate over
the elements in a set.

Set operations
^^^^^^^^^^^^^^

You can compute the union, intersection, or difference of two sets
using the ``|``, ``&``, and ``-`` operators.

.. note::

   Use ``+=`` instead of ``|`` to grow an existing set. That is,
   say ``s += new_s`` instead of ``s = s | new_s``. The latter requires
   copying both input sets and thus quickly deteriorates runtime. See
   :ref:`assignment-operators` for details.

You can compare sets for equality (they have exactly the same elements)
using ``==``.  The ``<`` operator returns ``T`` if the lefthand operand
is a proper subset of the righthand operand.  Similarly, ``<=``
returns ``T`` if the lefthand operator is a subset (not necessarily proper,
i.e., it may be equal to the righthand operand).  The operators ``!=``,
``>`` and ``>=`` provide the expected complementary operations.

Additional operations
^^^^^^^^^^^^^^^^^^^^^

The number of elements in a set can be obtained by placing the set
identifier between vertical pipe characters:

.. code-block:: zeek

    |s|


The :ref:`table's special lookups <table-special-lookups>` extend to the
set ``in`` operator: Using ``in`` with ``addr`` and ``set[subnet]``
or ``string`` and ``set[pattern]`` yields ``T`` if any of the subnets
or patterns the set holds contain or match the given value.


.. zeek:native-type:: string

string
------

A type used to hold bytes which represent text and also can hold
arbitrary binary data.

String constants are created by enclosing text within a pair of double
quotes (``"``).  A string constant cannot span multiple lines in a Zeek script.
The backslash character (\\) introduces escape sequences. Zeek recognizes
the following escape sequences: ``\\``, ``\n``, ``\t``, ``\v``, ``\b``,
``\r``, ``\f``, ``\a``, ``\ooo`` (where each 'o' is an octal digit),
``\xhh`` (where each 'h' is a hexadecimal digit).  If Zeek does not
recognize an escape sequence, Zeek will ignore the backslash
(``\\g`` becomes ``g``).

Strings support concatenation (``+``), and assignment (``=``, ``+=``).
Strings also support the comparison operators (``==``, ``!=``, ``<``,
``<=``, ``>``, ``>=``).  The number of characters in a string can be
found by enclosing the string within pipe characters (e.g., ``|"abc"|``
is 3).  Substring searching can be performed using the ``in`` or ``!in``
operators (e.g., ``"bar" in "foobar"`` yields true).

The subscript operator can extract a substring of a string.  To do this,
specify the starting index to extract (if the starting index is omitted,
then zero is assumed), followed by a colon and index
one past the last character to extract (if the last index is omitted,
then the extracted substring will go to the end of the original string).
However, if both the colon and last index are omitted, then a string of
length one is extracted.  String indexing is zero-based, but an index
of -1 refers to the last character in the string, and -2 refers to the
second-to-last character, etc.  Here are a few examples:

.. code-block:: zeek

    local orig = "0123456789";
    local second_char = orig[1];         # "1"
    local last_char = orig[-1];          # "9"
    local first_two_chars = orig[:2];    # "01"
    local last_two_chars = orig[8:];     # "89"
    local no_first_and_last = orig[1:9]; # "12345678"
    local no_first = orig[1:];           # "123456789"
    local no_last = orig[:-1];           # "012345678"
    local copy_orig = orig[:];           # "0123456789"

Note that the subscript operator cannot be used to modify a string (i.e.,
it cannot be on the left side of an assignment operator).

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`addr`
     - :zeek:see:`to_addr` BIF
     - ``to_addr("127.0.0.1")``

   * - :zeek:see:`addr`
     - :zeek:see:`raw_bytes_to_v4_addr` BIF
     - ``raw_bytes_to_v4_addr("\x7f\x0\x0\x1")``

   * - :zeek:see:`addr`
     - :zeek:see:`raw_bytes_to_v6_addr` BIF
     - ``raw_bytes_to_v6_addr("\xda\xda\xbe\xef\x00\x00AAAAAAAAAA")``

   * - :zeek:see:`bool`
     - Relational operator
     - ``foo != ""``

   * - :zeek:see:`count`
     - :zeek:see:`to_count` BIF
     - ``to_count("42")``

   * - :zeek:see:`count`
     - :zeek:see:`bytestring_to_count` BIF
     - ``bytestring_to_count("\xde\xad\xbe\xef")``

   * - :zeek:see:`double`
     - :zeek:see:`to_double` BIF
     - ``to_double("0.001")``

   * - :zeek:see:`double`
     - :zeek:see:`bytestring_to_double` BIF
     - ``bytestring_to_double("\x43\x26\x4f\xa0\x71\x30\x80\x00")``

   * - :zeek:see:`int`
     - :zeek:see:`to_int` BIF
     - ``to_int("-42")``

   * - :zeek:see:`pattern`
     - :zeek:see:`string_to_pattern` BIF
     - ``string_to_pattern("rsh .*", F)``

   * - :zeek:see:`port`
     - :zeek:see:`to_port` BIF
     - ``to_port("53/udp")``

   * - :zeek:see:`subnet`
     - :zeek:see:`to_subnet` BIF
     - ``to_subnet("::1/128")``


.. zeek:native-type:: subnet

subnet
------

A type representing a block of IP addresses in CIDR notation.  A
``subnet`` constant is written as an :zeek:type:`addr` followed by a
slash (``/``) and then the network prefix size specified as a decimal
number.  For example, ``192.168.0.0/16`` or ``[fe80::]/64``.

Subnets can be compared for equality (``==``, ``!=``).  An
:zeek:type:`addr` can be checked for inclusion in a subnet using
the ``in`` or ``!in`` operators.

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`addr`
     - :zeek:see:`subnet_to_addr` BIF
     - ``subnet_to_addr([::1]/120)``

   * - :zeek:see:`double`
     - Absolute value operator
     - ``|1.2.3.0/24|``

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(foo)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%s", foo)``


.. zeek:native-type:: table

table
-----

An associate array that maps from one set of values to another.  The
values being mapped are termed the *index* or *indices* and the
result of the mapping is called the *yield*.  Indexing into tables
is very efficient, and internally it is just a single hash table
lookup.

Declaration and initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The table declaration syntax is::

    table [ type^+ ] of type

where ``type^+`` is one or more types, separated by commas.  The
index type cannot be any of the following types:  :zeek:type:`file`,
:zeek:type:`opaque`, :zeek:type:`any`.

Here is an example of declaring a table indexed by :zeek:type:`count` values
and yielding :zeek:type:`string` values:

.. code-block:: zeek

    global a: table[count] of string;

The yield type can also be more complex:

.. code-block:: zeek

    global a: table[count] of table[addr, port] of string;

which declares a table indexed by :zeek:type:`count` and yielding
another ``table`` which is indexed by an :zeek:type:`addr`
and :zeek:type:`port` to yield a :zeek:type:`string`.

One way to initialize a table is by enclosing a set of initializers within
braces, for example:

.. code-block:: zeek

    global t: table[count] of string = {
        [11] = "eleven",
        [5] = "five",
    };

A table constructor can also be used to create a table:

.. code-block:: zeek

    global t2 = table(
        [192.168.0.2, 22/tcp] = "ssh",
        [192.168.0.3, 80/tcp] = "http"
    );

Table constructors can also be explicitly named by a type, which is
useful when a more complex index type could otherwise be
ambiguous:

.. code-block:: zeek

    type MyRec: record {
        a: count &optional;
        b: count;
    };

    type MyTable: table[MyRec] of string;

    global t3 = MyTable([[$b=5]] = "b5", [[$b=7]] = "b7");

Insertion and removal
^^^^^^^^^^^^^^^^^^^^^

Add or overwrite individual table elements by assignment:

.. code-block:: zeek

    t[13] = "thirteen";

Remove individual table elements with :zeek:keyword:`delete`:

.. code-block:: zeek

    delete t[13];

Nothing happens if the element with index value ``13`` isn't present in
the table.

.. versionadded:: 7.0

Removing all table elements can be done with the :zeek:keyword:`delete`, too:

.. code-block:: zeek

    delete t;

.. note::

   Indexing with complex types (such as records or sets) happens via hashing of
   the provided index value at the time of table access. Subsequent
   modifications to the index value do not affect the table. For example:

   .. code-block:: zeek

       local t: table[set[port]] of string = table();
       local s: set[port] = { 80/tcp, 8000/tcp };

       t[s] = "http";

       add s[8080/tcp];

       print t[set(80/tcp, 8000/tcp)]; # prints "http"
       print t[s]; # error: no such index

Lookup and iteration
^^^^^^^^^^^^^^^^^^^^

Accessing table elements is provided by enclosing index values within
square brackets (``[]``), for example:

.. code-block:: zeek

    print t[11];

Membership can be tested with ``in`` or ``!in``:

.. code-block:: zeek

    if ( 13 in t )
        ...
    if ( [192.168.0.2, 22/tcp] in t2 )
        ...

See the :zeek:keyword:`for` statement for information on how to iterate over
the elements in a table.

.. _table-special-lookups:

Special lookups
^^^^^^^^^^^^^^^

Zeek supports two forms of special table lookups. The first is for tables
with an index type of :zeek:type:`subnet`. When indexed with an
:zeek:type:`addr` value, these tables produce the yield associated with
the closest (narrowest) subnet. For example:

.. code-block:: zeek

    global st: table[subnet] of count;
    st[1.2.3.4/24] = 5;
    st[1.2.3.4/29] = 9;
    print st[1.2.3.4], st[1.2.3.251];

will print ``9, 5``. Attempting to look up an address that doesn't match
any of the subnet indices results in a run-time error.

.. versionadded:: 6.2

In addition, :zeek:type:`string` lookups for tables that have an index type of
:zeek:type:`pattern` return a (possibly empty)
:zeek:type:`vector` containing the values corresponding to each of the
patterns matching the given string. The order of entries in the resulting
vector is non-deterministic. For example:

.. code-block:: zeek

    global pt: table[pattern] of count;
    pt[/foo/] = 1;
    pt[/bar/] = 2;
    pt[/(foo|bletch)/] = 3;
    print pt["foo"];

will print either ``[1, 3]`` or ``[3, 1]``.
Indexing with a string that matches only one pattern returns a
one-element :zeek:type:`vector`, and indexing with a string that no
pattern matches returns an empty :zeek:type:`vector`.

Note that these pattern matches are all *exact*: the pattern must match
the entire string. If you want the pattern to match if it's *anywhere*
in the string, you can use the usual regular expression operators such
as ``/.*foo.*/``.

.. note::

   The :zeek:attr:`&default` attribute is ignored for this type of lookup.
   If none of the patterns matches a given string, the result will be an empty
   :zeek:type:`vector`, regardless of :zeek:attr:`&default`. Neither is the
   :zeek:attr:`&default_insert` attribute used. It's not an error to have
   either of these attributes, however. They'll still be in effect when
   indexing with :zeek:type:`pattern` values.

.. note::

   Internally, Zeek matches a table's patterns in parallel using a lazily
   constructed deterministic finite automaton (DFA). This means that the nature
   of patterns in the table *and* the strings looked up in it can lead to
   varying degrees of runtime memory growth.

   Users are advised to test scripts using this feature with a wide range of
   input data. Script developers can reset the DFA's state by removal or
   addition of a single pattern. For observability, the
   :zeek:see:`table_pattern_matcher_stats` function returns a
   :zeek:see:`MatcherStats` record with details about a table's DFA state.


Additional operations
^^^^^^^^^^^^^^^^^^^^^

The number of elements in a table can be obtained by placing the table
identifier between vertical pipe characters:

.. code-block:: zeek

    |t|

It's common to extend the behavior of table lookup and membership lifetimes
via :doc:`attributes <attributes>` but note that it's also a :ref:`confusing
pitfall <attribute-propagation-pitfalls>` that attributes bind to initial
*values* instead of *type* or *variable* and do not currently propagate to
any new *value* subsequently re-assigned to the table *variable*.


.. zeek:native-type:: time

time
----

A temporal type representing an absolute time.  There is currently
no way to specify a ``time`` constant, but one can use the
:zeek:id:`double_to_time`, :zeek:id:`current_time`, or :zeek:id:`network_time`
built-in functions to assign a value to a ``time``-typed variable.

Time values support the comparison operators (``==``, ``!=``, ``<``,
``<=``, ``>``, ``>=``).  A ``time`` value can be subtracted from
another ``time`` value to produce an :zeek:type:`interval` value.  An
``interval`` value can be added to, or subtracted from, a ``time`` value
to produce a ``time`` value.  The absolute value of a ``time`` value is
a :zeek:type:`double` with the same numeric value.

Type Conversions
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - To
     - Description
     - Example

   * - :zeek:see:`double`
     - :zeek:see:`time_to_double` BIF
     - ``time_to_double(foo)``

   * - :zeek:see:`double`
     - Absolute value operator
     - ``|foo|``

   * - :zeek:see:`interval`
     - Subtraction operator
     - ``end_time - start_time``

   * - :zeek:see:`string`
     - :zeek:see:`cat` BIF
     - ``cat(foo)``

   * - :zeek:see:`string`
     - :zeek:see:`fmt` BIF for additional control over the formatting
     - ``fmt("%s", foo)``


.. zeek:native-type:: vector

vector
------

A vector is like a :zeek:type:`table`, except its indices are non-negative
integers, starting from zero.

Declaration and initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A vector is declared as follows:

.. code-block:: zeek

    global v: vector of string;

Vectors can be initialized with the vector constructor:

.. code-block:: zeek

    local v = vector("one", "two", "three");

Vector constructors can also be explicitly named by a type, which
is useful for when a more complex yield type could otherwise be
ambiguous.

.. code-block:: zeek

    type MyRec: record {
        a: count &optional;
        b: count;
    };

    type MyVec: vector of MyRec;

    global v2 = MyVec([$b=1], [$b=2], [$b=3]);

Insertion
^^^^^^^^^

An element can be added to a vector by assigning the value (a value
that already exists at that index will be overwritten):

.. code-block:: zeek

    v[3] = "four";

A range of elements can be *replaced* by assigning to a vector slice:

.. code-block:: zeek

    # Note that the number of elements in the slice being replaced
    # may differ from the number of elements being inserted.  This
    # causes the vector to grow or shrink accordingly.
    v[0:2] = vector("five", "six", "seven");

A particularly common operation on a vector is to append an element
to its end.  You can do so using:

.. code-block:: zeek

    v += e;

where if *e*'s type is ``X``, *v*'s type is ``vector of X``.  Note that
this expression is equivalent to:

.. code-block:: zeek

    v[|v|] = e;

In addition, if *e*'s type is ``vector of X`` and so is *v*'s type, then

.. code-block:: zeek

    v += e;

instead appends each element of *e* to *v*.  (In this case the expression
is *not* equivalent to ``v[|v|] = e``, which will generate an error because
*e*'s type is not compatible with ``X``.)

Lookup and iteration
^^^^^^^^^^^^^^^^^^^^

Access individual vector elements by enclosing index values within
square brackets (``[]``), for example:

.. code-block:: zeek

    print v[2];

Access a slice of vector elements by enclosing a range of indices,
delimited by a colon, within square brackets (``[x:y]``).  For example,
this will print a vector containing the first and second elements:

.. code-block:: zeek

    print v[0:2];

The slicing notation is the same as what is permitted by the
:zeek:see:`string` substring extraction operations.

The ``in`` operator can be used to check if a value has been assigned at a
specified index value in the vector.  For example, if a vector has size 4,
then the expression ``3 in v`` would yield true and ``4 in v`` would yield
false.

See the :zeek:keyword:`for` statement for info on how to iterate over
the elements in a vector.

.. versionadded:: 7.0

The :zeek:keyword:`delete` statement can be used to delete all elements
from a vector.

Vectorized operations
^^^^^^^^^^^^^^^^^^^^^

Vectors of integral types (:zeek:type:`int` or :zeek:type:`count`) support the pre-increment
(``++``) and pre-decrement operators (``--``), which will increment or
decrement each element in the vector.

Vectors of arithmetic types (:zeek:type:`int` or :zeek:type:`count`, or :zeek:type:`double`) can be
operands of the arithmetic operators (``+``, ``-``, ``*``, ``/``, ``%``),
but both operands must have the same number of elements (and the remainder
operator ``%`` cannot be used if either operand is a ``vector of double``).
The resulting vector contains the result of the operation applied to each
of the elements in the operand vectors.

Vectors of :zeek:type:`bool` can be operands of the logical "and" (``&&``) and logical
"or" (``||``) operators (both operands must have the same number of elements).
The resulting ``vector of bool`` is the logical "and" (or logical "or") of
each element of the operand vectors.

Vectors of :zeek:type:`count` can also be operands for the bitwise and/or/xor
operators, ``&``, ``|`` and ``^``.

Vectors of :zeek:type:`string` can be concatenated element-wise through
the ``+`` operator, yielding a new ``vector of string`` containing the
resulting values. Both operand vectors must be of the same length. A
vector of type :zeek:type:`string` can also be paired with a scalar operand
using any operator that supports string/scalar operations (i.e.,
concatenation and comparisons). The resulting vector will contain the
result of the operator applied to each of the elements.

.. note::

   As a quirk of the language, for a string vector ``v`` there is a
   difference between ``v = v + "foo"`` and ``v += "foo"``: the former
   extends each element, while the latter appends a new element to the
   vector.)

Additional operations
^^^^^^^^^^^^^^^^^^^^^

The size of a vector (this is one greater than the highest index value, and
is normally equal to the number of elements in the vector) can be obtained
by placing the vector identifier between vertical pipe characters:

.. code-block:: zeek

    |v|


.. zeek:native-type:: void

void
----

An internal Zeek type (i.e., ``void`` is not a reserved keyword in the Zeek
scripting language) representing the absence of a return type for a
function.
