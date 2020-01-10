Types
=====

The Zeek scripting language supports the following built-in types:

+-----------------------+--------------------+
| Name                  | Description        |
+=======================+====================+
| :zeek:type:`bool`     | Boolean            |
+-----------------------+--------------------+
| :zeek:type:`count`,   | Numeric types      |
| :zeek:type:`int`,     |                    |
| :zeek:type:`double`   |                    |
+-----------------------+--------------------+
| :zeek:type:`time`,    | Time types         |
| :zeek:type:`interval` |                    |
+-----------------------+--------------------+
| :zeek:type:`string`   | String             |
+-----------------------+--------------------+
| :zeek:type:`pattern`  | Regular expression |
+-----------------------+--------------------+
| :zeek:type:`port`,    | Network types      |
| :zeek:type:`addr`,    |                    |
| :zeek:type:`subnet`   |                    |
+-----------------------+--------------------+
| :zeek:type:`enum`     | Enumeration        |
|                       | (user-defined type)|
+-----------------------+--------------------+
| :zeek:type:`table`,   | Container types    |
| :zeek:type:`set`,     |                    |
| :zeek:type:`vector`,  |                    |
| :zeek:type:`record`   |                    |
+-----------------------+--------------------+
| :zeek:type:`function`,| Executable types   |
| :zeek:type:`event`,   |                    |
| :zeek:type:`hook`     |                    |
+-----------------------+--------------------+
| :zeek:type:`file`     | File type (only    |
|                       | for writing)       |
+-----------------------+--------------------+
| :zeek:type:`opaque`   | Opaque type (for   |
|                       | some built-in      |
|                       | functions)         |
+-----------------------+--------------------+
| :zeek:type:`any`      | Any type (for      |
|                       | functions or       |
|                       | containers)        |
+-----------------------+--------------------+

Here is a more detailed description of each type:

.. zeek:type:: bool

    Reflects a value with one of two meanings: true or false.  The two
    "bool" constants are ``T`` and ``F``.

    The "bool" type supports the following operators: equality/inequality
    (``==``, ``!=``), logical and/or (``&&``, ``||``), logical
    negation (``!``), and absolute value (where ``|T|`` is 1, and ``|F|`` is 0,
    and in both cases the result type is :zeek:type:`count`).

.. zeek:type:: int

    A numeric type representing a 64-bit signed integer.  An "int" constant
    is a string of digits preceded by a "+" or "-" sign, e.g.
    ``-42`` or ``+5`` (the "+" sign is optional but see note about type
    inferencing below).  An "int" constant can also be written in
    hexadecimal notation (in which case "0x" must be between the sign and
    the hex digits), e.g. ``-0xFF`` or ``+0xabc123``.

    The "int" type supports the following operators:  arithmetic
    operators (``+``, ``-``, ``*``, ``/``, ``%``), comparison operators
    (``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``), assignment operators
    (``=``, ``+=``, ``-=``), pre-increment (``++``), pre-decrement
    (``--``), unary plus and minus (``+``, ``-``), and absolute value
    (e.g., ``|-3|`` is 3, but the result type is :zeek:type:`count`).

    When using type inferencing use care so that the
    intended type is inferred, e.g. "local size_difference = 0" will
    infer ":zeek:type:`count`", while "local size_difference = +0"
    will infer "int".

.. zeek:type:: count

    A numeric type representing a 64-bit unsigned integer.  A "count"
    constant is a string of digits, e.g. ``1234`` or ``0``.  A "count"
    can also be written in hexadecimal notation (in which case "0x" must
    precede the hex digits), e.g. ``0xff`` or ``0xABC123``.

    The "count" type supports the same operators as the ":zeek:type:`int`"
    type, but a unary plus or minus applied to a "count" results in an
    "int".

    In addition, "count" types support bitwise operations.  You can use
    ``&``, ``|``, and ``^`` for bitwise ``and``, ``or``, and ``xor``.  You
    can also use ``~`` for bitwise (one's) complement.

.. zeek:type:: double

    A numeric type representing a double-precision floating-point
    number.  Floating-point constants are written as a string of digits
    with an optional decimal point, optional scale-factor in scientific
    notation, and optional "+" or "-" sign.  Examples are ``-1234``,
    ``-1234e0``, ``3.14159``, and ``.003E-23``.

    The "double" type supports the following operators:  arithmetic
    operators (``+``, ``-``, ``*``, ``/``), comparison operators
    (``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``), assignment operators
    (``=``, ``+=``, ``-=``), unary plus and minus (``+``, ``-``), and
    absolute value (e.g., ``|-3.14|`` is 3.14).

    When using type inferencing use care so that the
    intended type is inferred, e.g. "local size_difference = 5" will
    infer ":zeek:type:`count`", while "local size_difference = 5.0"
    will infer "double".

.. zeek:type:: time

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

.. zeek:type:: interval

    A temporal type representing a relative time.  An ``interval``
    constant can be written as a numeric constant followed by a time
    unit where the time unit is one of ``usec``, ``msec``, ``sec``, ``min``,
    ``hr``, or ``day`` which respectively represent microseconds, milliseconds,
    seconds, minutes, hours, and days.  Whitespace between the numeric
    constant and time unit is optional.  Appending the letter "s" to the
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

.. zeek:type:: string

    A type used to hold bytes which represent text and also can hold
    arbitrary binary data.

    String constants are created by enclosing text within a pair of double
    quotes (").  A string constant cannot span multiple lines in a Zeek script.
    The backslash character (\\) introduces escape sequences. Zeek recognizes
    the following escape sequences: ``\\``, ``\n``, ``\t``, ``\v``, ``\b``,
    ``\r``, ``\f``, ``\a``, ``\ooo`` (where each 'o' is an octal digit),
    ``\xhh`` (where each 'h' is a hexadecimal digit).  If Zeek does not
    recognize an escape sequence, Zeek will ignore the backslash
    ("\\g" becomes "g").

    Strings support concatenation (``+``), and assignment (``=``, ``+=``).
    Strings also support the comparison operators (``==``, ``!=``, ``<``,
    ``<=``, ``>``, ``>=``).  The number of characters in a string can be
    found by enclosing the string within pipe characters (e.g., ``|"abc"|``
    is 3).  Substring searching can be performed using the "in" or "!in"
    operators (e.g., "bar" in "foobar" yields true).

    The subscript operator can extract a substring of a string.  To do this,
    specify the starting index to extract (if the starting index is omitted,
    then zero is assumed), followed by a colon and index
    one past the last character to extract (if the last index is omitted,
    then the extracted substring will go to the end of the original string).
    However, if both the colon and last index are omitted, then a string of
    length one is extracted.  String indexing is zero-based, but an index
    of -1 refers to the last character in the string, and -2 refers to the
    second-to-last character, etc.  Here are a few examples::

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

.. zeek:type:: pattern

    A type representing regular-expression patterns that can be used
    for fast text-searching operations.  Pattern constants are created
    by enclosing text within forward slashes (``/``) and use the same syntax
    as the patterns supported by the `flex lexical analyzer
    <http://westes.github.io/flex/manual/Patterns.html>`_.  The speed of
    regular expression matching does not depend on the complexity or
    size of the patterns.  Patterns support two types of matching, exact
    and embedded.

    In exact matching the ``==`` equality relational operator is used
    with one "pattern" operand and one ":zeek:type:`string`"
    operand (order of operands does not matter) to check whether the full
    string exactly matches the pattern.  In exact matching, the ``^``
    beginning-of-line and ``$`` end-of-line anchors are redundant since
    the pattern is implicitly anchored to the beginning and end of the
    line to facilitate an exact match.  For example::

        /foo|bar/ == "foo"

    yields true, while::

        /foo|bar/ == "foobar"

    yields false.  The ``!=`` operator would yield the negation of ``==``.

    In embedded matching the ``in`` operator is used with one
    "pattern" operand (which must be on the left-hand side) and
    one ":zeek:type:`string`" operand, but tests whether the pattern
    appears anywhere within the given string.  For example::

        /foo|bar/ in "foobar"

    yields true, while::

        /^oob/ in "foobar"

    is false since "oob" does not appear at the start of "foobar".  The
    ``!in`` operator would yield the negation of ``in``.

    You can create a disjunction (either-or) of two patterns
    using the ``|`` operator.  For example::

	/foo/ | /bar/ in "foobar"

    yields true, like in the similar example above.  You can also
    create the conjunction (concatenation) of patterns using the ``&``
    operator.  For example::

	/foo/ & /bar/ in "foobar"

    will yield true because the pattern /(foo)(bar)/ appears in
    the string "foobar".

    When specifying a pattern, you can add a final ``i`` specifier to
    mark it as case-insensitive.  For example, ``/foo|bar/i`` will match
    "foo", "Foo", "BaR", etc.

    You can also introduce a case-insensitive sub-pattern by enclosing it
    in ``(?i:<pattern>)``.  So, for example, ``/foo|(?i:bar)/`` will
    match "foo" and "BaR", but *not* "Foo".

    For both ways of specifying case-insensitivity, characters enclosed
    in double quotes maintain their case-sensitivity.  So for example
    /"foo"/i will not match "Foo", but it will match "foo".

.. zeek:type:: port

    A type representing transport-level port numbers (besides TCP and
    UDP ports, there is a concept of an ICMP "port" where the source
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

.. zeek:type:: addr

    A type representing an IP address.

    IPv4 address constants are written in "dotted quad" format,
    ``A1.A2.A3.A4``, where Ai all lie between 0 and 255.

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

    .. sourcecode:: zeek

        local a: addr = 192.168.1.100;
        local s: subnet = 192.168.0.0/16;
        if ( a/16 == s )
            print "true";

    And checked for inclusion within a :zeek:type:`subnet` using ``in``
    or ``!in``:

    .. sourcecode:: zeek

        local a: addr = 192.168.1.100;
        local s: subnet = 192.168.0.0/16;
        if ( a in s )
            print "true";

    You can check if a given ``addr`` is IPv4 or IPv6 using
    the :zeek:id:`is_v4_addr` and :zeek:id:`is_v6_addr` built-in functions.

    Note that hostname constants can also be used, but since a hostname can
    correspond to multiple IP addresses, the type of such a variable is
    "set[addr]". For example:

    .. sourcecode:: zeek

        local a = www.google.com;

.. zeek:type:: subnet

    A type representing a block of IP addresses in CIDR notation.  A
    ``subnet`` constant is written as an :zeek:type:`addr` followed by a
    slash (/) and then the network prefix size specified as a decimal
    number.  For example, ``192.168.0.0/16`` or ``[fe80::]/64``.

    Subnets can be compared for equality (``==``, ``!=``).  An
    "addr" can be checked for inclusion in a subnet using
    the ``in`` or ``!in`` operators.

.. zeek:type:: enum

    A type allowing the specification of a set of related values that
    have no further structure.  An example declaration:

    .. sourcecode:: zeek

        type color: enum { Red, White, Blue, };

    The last comma after ``Blue`` is optional.  Both the type name ``color``
    and the individual values (``Red``, etc.) have global scope.

    Enumerations do not have associated values or ordering.
    The only operations allowed on enumerations are equality comparisons
    (``==``, ``!=``) and assignment (``=``).

.. zeek:type:: table

    An associate array that maps from one set of values to another.  The
    values being mapped are termed the *index* or *indices* and the
    result of the mapping is called the *yield*.  Indexing into tables
    is very efficient, and internally it is just a single hash table
    lookup.

    The table declaration syntax is::

        table [ type^+ ] of type

    where *type^+* is one or more types, separated by commas.  The
    index type cannot be any of the following types:  pattern, table, set,
    vector, file, opaque, any.

    Here is an example of declaring a table indexed by "count" values
    and yielding "string" values:

    .. sourcecode:: zeek

        global a: table[count] of string;

    The yield type can also be more complex:

    .. sourcecode:: zeek

        global a: table[count] of table[addr, port] of string;

    which declares a table indexed by "count" and yielding
    another "table" which is indexed by an "addr"
    and "port" to yield a "string".

    One way to initialize a table is by enclosing a set of initializers within
    braces, for example:

    .. sourcecode:: zeek

        global t: table[count] of string = {
            [11] = "eleven",
            [5] = "five",
        };

    A table constructor can also be used to create a table:

    .. sourcecode:: zeek

        global t2 = table(
            [192.168.0.2, 22/tcp] = "ssh",
            [192.168.0.3, 80/tcp] = "http"
        );

    Table constructors can also be explicitly named by a type, which is
    useful when a more complex index type could otherwise be
    ambiguous:

    .. sourcecode:: zeek

        type MyRec: record {
            a: count &optional;
            b: count;
        };

        type MyTable: table[MyRec] of string;

        global t3 = MyTable([[$b=5]] = "b5", [[$b=7]] = "b7");

    Accessing table elements is provided by enclosing index values within
    square brackets (``[]``), for example:

    .. sourcecode:: zeek

        print t[11];

    And membership can be tested with ``in`` or ``!in``:

    .. sourcecode:: zeek

        if ( 13 in t )
            ...
        if ( [192.168.0.2, 22/tcp] in t2 )
            ...

    Add or overwrite individual table elements by assignment:

    .. sourcecode:: zeek

        t[13] = "thirteen";

    Remove individual table elements with :zeek:keyword:`delete`:

    .. sourcecode:: zeek

        delete t[13];

    Nothing happens if the element with index value ``13`` isn't present in
    the table.

    The number of elements in a table can be obtained by placing the table
    identifier between vertical pipe characters:

    .. sourcecode:: zeek

        |t|

    See the :zeek:keyword:`for` statement for info on how to iterate over
    the elements in a table.

    It's common to extend the behavior of table lookup and membership lifetimes
    via :doc:`attributes <attributes>` but note that it's also a :ref:`confusing
    pitfall <attribute-propagation-pitfalls>` that attributes bind to initial
    *values* instead of *type* or *variable* and do not currently propagate to
    any new *value* subsequently re-assigned to the table *variable*.

.. zeek:type:: set

    A set is like a :zeek:type:`table`, but it is a collection of indices
    that do not map to any yield value.  They are declared with the
    syntax::

        set [ type^+ ]

    where *type^+* is one or more types separated by commas.  The
    index type cannot be any of the following types:  pattern, table, set,
    vector, file, opaque, any.

    Sets can be initialized by listing elements enclosed by curly braces:

    .. sourcecode:: zeek

        global s: set[port] = { 21/tcp, 23/tcp, 80/tcp, 443/tcp };
        global s2: set[port, string] = { [21/tcp, "ftp"], [23/tcp, "telnet"] };

    A set constructor (equivalent to above example) can also be used to
    create a set:

    .. sourcecode:: zeek

        global s3 = set(21/tcp, 23/tcp, 80/tcp, 443/tcp);

    Set constructors can also be explicitly named by a type, which is
    useful when a more complex index type could otherwise be
    ambiguous:

    .. sourcecode:: zeek

        type MyRec: record {
            a: count &optional;
            b: count;
        };

        type MySet: set[MyRec];

        global s4 = MySet([$b=1], [$b=2]);

    Set membership is tested with ``in`` or ``!in``:

    .. sourcecode:: zeek

        if ( 21/tcp in s )
            ...

        if ( [21/tcp, "ftp"] !in s2 )
            ...

    Elements are added with :zeek:keyword:`add`:

    .. sourcecode:: zeek

        add s[22/tcp];

    Nothing happens if the element with value ``22/tcp`` was already present in
    the set.

    And removed with :zeek:keyword:`delete`:

    .. sourcecode:: zeek

        delete s[21/tcp];

    Nothing happens if the element with value ``21/tcp`` isn't present in
    the set.

    The number of elements in a set can be obtained by placing the set
    identifier between vertical pipe characters:

    .. sourcecode:: zeek

        |s|

    You can compute the union, intersection, or difference of two sets
    using the ``|``, ``&``, and ``-`` operators.

    You can compare sets for equality (they have exactly the same elements)
    using ``==``.  The ``<`` operator returns ``T`` if the lefthand operand
    is a proper subset of the righthand operand.  Similarly, ``<=``
    returns ``T`` if the lefthand operator is a subset (not necessarily proper,
    i.e., it may be equal to the righthand operand).  The operators ``!=``,
    ``>`` and ``>=`` provide the expected complementary operations.

    See the :zeek:keyword:`for` statement for info on how to iterate over
    the elements in a set.

.. zeek:type:: vector

    A vector is like a :zeek:type:`table`, except its indices are non-negative
    integers, starting from zero.  A vector is declared like:

    .. sourcecode:: zeek

        global v: vector of string;

    And can be initialized with the vector constructor:

    .. sourcecode:: zeek

        local v = vector("one", "two", "three");

    Vector constructors can also be explicitly named by a type, which
    is useful for when a more complex yield type could otherwise be
    ambiguous.

    .. sourcecode:: zeek

        type MyRec: record {
            a: count &optional;
            b: count;
        };

        type MyVec: vector of MyRec;

        global v2 = MyVec([$b=1], [$b=2], [$b=3]);

    Access individual vector elements by enclosing index values within
    square brackets (``[]``), for example:

    .. sourcecode:: zeek

        print v[2];

    Access a slice of vector elements by enclosing a range of indices,
    delimited by a colon, within square brackets (``[x:y]``).  For example,
    this will print a vector containing the first and second elements:

    .. sourcecode:: zeek

        print v[0:2];

    The slicing notation is the same as what is permitted by the
    :zeek:see:`string` substring extraction operations.

    An element can be added to a vector by assigning the value (a value
    that already exists at that index will be overwritten):

    .. sourcecode:: zeek

        v[3] = "four";

    A range of elements can be *replaced* by assigning to a vector slice:

    .. sourcecode:: zeek

        # Note that the number of elements in the slice being replaced
        # may differ from the number of elements being inserted.  This
        # causes the vector to grow or shrink accordingly.
        v[0:2] = vector("five", "six", "seven");

    The size of a vector (this is one greater than the highest index value, and
    is normally equal to the number of elements in the vector) can be obtained
    by placing the vector identifier between vertical pipe characters:

    .. sourcecode:: zeek

        |v|

    A particularly common operation on a vector is to append an element
    to its end.  You can do so using:

    .. sourcecode:: zeek

        v += e;

    where if e's type is ``X``, v's type is ``vector of X``.  Note that
    this expression is equivalent to:

    .. sourcecode:: zeek

        v[|v|] = e;

    The "in" operator can be used to check if a value has been assigned at a
    specified index value in the vector.  For example, if a vector has size 4,
    then the expression ``3 in v`` would yield true and ``4 in v`` would yield
    false.

    Vectors of integral types (``int`` or ``count``) support the pre-increment
    (``++``) and pre-decrement operators (``--``), which will increment or
    decrement each element in the vector.

    Vectors of arithmetic types (``int``, ``count``, or ``double``) can be
    operands of the arithmetic operators (``+``, ``-``, ``*``, ``/``, ``%``),
    but both operands must have the same number of elements (and the modulus
    operator ``%`` cannot be used if either operand is a ``vector of double``).
    The resulting vector contains the result of the operation applied to each
    of the elements in the operand vectors.

    Vectors of bool can be operands of the logical "and" (``&&``) and logical
    "or" (``||``) operators (both operands must have same number of elements).
    The resulting vector of bool is the logical "and" (or logical "or") of
    each element of the operand vectors.

    Vectors of type ``count`` can also be operands for the bitwise and/or/xor
    operators, ``&``, ``|`` and ``^``.

    See the :zeek:keyword:`for` statement for info on how to iterate over
    the elements in a vector.

.. zeek:type:: record

    A "record" is a collection of values.  Each value has a field name
    and a type.  Values do not need to have the same type and the types
    have no restrictions.  Field names must follow the same syntax as
    regular variable names (except that field names are allowed to be the
    same as local or global variables).  An example record type
    definition:

    .. sourcecode:: zeek

        type MyRecordType: record {
            c: count;
            s: string &optional;
        };

    Records can be initialized or assigned as a whole in three different ways.
    When assigning a whole record value, all fields that are not
    :zeek:attr:`&optional` or have a :zeek:attr:`&default` attribute must
    be specified.  First, there's a constructor syntax:

    .. sourcecode:: zeek

        local r: MyRecordType = record($c = 7);

    And the constructor can be explicitly named by type, too, which
    is arguably more readable:

    .. sourcecode:: zeek

        local r = MyRecordType($c = 42);

    And the third way is like this:

    .. sourcecode:: zeek

        local r: MyRecordType = [$c = 13, $s = "thirteen"];

    Access to a record field uses the dollar sign (``$``) operator, and
    record fields can be assigned with this:

    .. sourcecode:: zeek

        local r: MyRecordType;
        r$c = 13;

    To test if a field that is :zeek:attr:`&optional` has been assigned a
    value, use the ``?$`` operator (it returns a :zeek:type:`bool` value of
    ``T`` if the field has been assigned a value, or ``F`` if not):

    .. sourcecode:: zeek

        if ( r ?$ s )
            ...

.. zeek:type:: function

    Function types in Zeek are declared using::

        function( argument*  ): type

    where *argument* is a (possibly empty) comma-separated list of
    arguments, and *type* is an optional return type.  For example:

    .. sourcecode:: zeek

        global greeting: function(name: string): string;

    Here ``greeting`` is an identifier with a certain function type.
    The function body is not defined yet and ``greeting`` could even
    have different function body values at different times.  To define
    a function including a body value, the syntax is like:

    .. sourcecode:: zeek

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

    .. sourcecode:: zeek

        function my_func()
            {
            print "my_func";
            }

    Function types don't need to have a name and can be assigned anonymously:

    .. sourcecode:: zeek

        greeting = function(name: string): string { return "Hi, " + name; };

    And finally, the function can be called like:

    .. sourcecode:: zeek

        print greeting("Dave");

    Anonymously defined functions capture their closures. This means that they
    can use and modify variables from their enclosing scope at the time of their
    creation. Here is an example of a simple anonymous function that captures its
    closure in Zeek:

    .. sourcecode:: zeek

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

    Here `make_adder` is generating a function that captures `n` in its closure.

    Anonymous functions capture their closures by reference. This means that they
    can modify the variables in their closures. For example:

    .. sourcecode:: zeek

        local n = 3;
        local f = function() { n += 1; };
        f();
        print n; # prints 4

    When anonymous functions are serialized over Broker they keep their closures,
    but they will not continue to mutate the values from the sending script. At
    the time of serialization they create a copy of their closure. Anonymous
    function's do not capture global variables in their closures though and will
    use the receivers global variables.

    In order to serialize an anonymous function, that function must have been
    already declared on the receivers end because Zeek will not serialize the
    function's source code. See `testing/btest/language/closure-sending.zeek` for
    an example of how to serialize anonymous functions over Broker.

    Function parameters may specify default values as long as they appear
    last in the parameter list:

    .. sourcecode:: zeek

        global foo: function(s: string, t: string &default="abc", u: count &default=0);

    If a function was previously declared with default parameters, the
    default expressions can be omitted when implementing the function
    body and they will still be used for function calls that lack those
    arguments.

    .. sourcecode:: zeek

        function foo(s: string, t: string, u: count)
            {
            print s, t, u;
            }

    And calls to the function may omit the defaults from the argument list:

    .. sourcecode:: zeek

        foo("test");

.. zeek:type:: event

    Event handlers are nearly identical in both syntax and semantics to
    a :zeek:type:`function`, with the two differences being that event
    handlers have no return type since they never return a value, and
    you cannot call an event handler.

    Example:

    .. sourcecode:: zeek

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

        .. sourcecode:: zeek

            event password_exposed(user, password);

        This assumes that ``password_exposed`` was previously declared
        as an event handler type with compatible arguments.

    - Via the :zeek:keyword:`schedule` expression in a script

        This delays the invocation of event handlers until some time in
        the future.  For example:

        .. sourcecode:: zeek

            schedule 5 secs { password_exposed(user, password) };

    Multiple event handler bodies can be defined for the same event handler
    identifier and the body of each will be executed in turn.  Ordering
    of execution can be influenced with :zeek:attr:`&priority`.

.. zeek:type:: hook

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

    where *argument* is a (possibly empty) comma-separated list of
    arguments.  For example:

    .. sourcecode:: zeek

        global myhook: hook(s: string)

    Here ``myhook`` is the hook type identifier and no hook handler
    bodies have been defined for it yet.  To define some hook handler
    bodies the syntax looks like:

    .. sourcecode:: zeek

        hook myhook(s: string) &priority=10
            {
            print "priority 10 myhook handler", s;
            s = "bye";
            }

        hook myhook(s: string)
            {
            print "break out of myhook handling", s;
            break;
            }

        hook myhook(s: string) &priority=-5
            {
            print "not going to happen", s;
            }

    Note that the first (forward) declaration of ``myhook`` as a hook
    type isn't strictly required.  Argument types must match for all
    hook handlers and any forward declaration of a given hook.

    To invoke immediate execution of all hook handler bodies, they
    are called similarly to a function, except preceded by the ``hook``
    keyword:

    .. sourcecode:: zeek

        hook myhook("hi");

    or

    .. sourcecode:: zeek

        if ( hook myhook("hi") )
            print "all handlers ran";

    And the output would look like::

        priority 10 myhook handler, hi
        break out of myhook handling, bye

    Note how the modification to arguments can be seen by remaining
    hook handlers.

    The return value of a hook call is an implicit :zeek:type:`bool`
    value with ``T`` meaning that all handlers for the hook were
    executed and ``F`` meaning that only some of the handlers may have
    executed due to one handler body exiting as a result of a ``break``
    statement.

.. zeek:type:: file

    Zeek supports writing to files, but not reading from them (to read from
    files see the :doc:`/frameworks/input`).  Files
    can be opened using either the :zeek:id:`open` or :zeek:id:`open_for_append`
    built-in functions, and closed using the :zeek:id:`close` built-in
    function.  For example, declare, open, and write to a file and finally
    close it like:

    .. sourcecode:: zeek

        local f = open("myfile");
        print f, "hello, world";
        close(f);

    Writing to files like this for logging usually isn't recommended, for better
    logging support see :doc:`/frameworks/logging`.

.. zeek:type:: opaque

    A data type whose actual representation/implementation is
    intentionally hidden, but whose values may be passed to certain
    built-in functions that can actually access the internal/hidden resources.
    Opaque types are differentiated from each other by qualifying them
    like "opaque of md5" or "opaque of sha1".

    An example use of this type is the set of built-in functions which
    perform hashing:

    .. sourcecode:: zeek

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

      An opqaue type for creating and using paraglob data structures inside of
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

      .. sourcecode:: zeek

        local v = vector("*", "d?g", "*og", "d?", "d[!wl]g");
        local p : opaque of paraglob = paraglob_init(v);
        print paraglob_match(p1, "dog");
        # out: [*, *og, d?g, d[!wl]g]

      For more documentation on paraglob see :doc:`/components/index`.

    .. zeek:see:: md5_hash_init sha1_hash_init sha256_hash_init
                  hll_cardinality_add bloomfilter_basic_init


.. zeek:type:: any

    Used to bypass strong typing.  For example, a function can take an
    argument of type ``any`` when it may be of different types.
    The only operation allowed on a variable of type ``any`` is assignment.

    Note that users aren't expected to use this type.  It's provided mainly
    for use by some built-in functions and scripts included with Zeek. For
    example, passing a vector into a ``.bif`` function is best accomplished by
    taking :zeek:type:`any` as an argument and casting it to a vector.

.. zeek:type:: void

    An internal Zeek type (i.e., "void" is not a reserved keyword in the Zeek
    scripting language) representing the absence of a return type for a
    function.
