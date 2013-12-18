Types and Attributes
====================

Types
-----

Every value in a Bro script has a type (see below for a list of all built-in
types).  Although Bro variables have static types (meaning that their type
is fixed), their type is inferred from the value to which they are
initially assigned when the variable is declared without an explicit type
name.

Automatic conversions happen when a binary operator has operands of 
different types.  Automatic conversions are limited to converting between
numeric types.  The numeric types are ``int``, ``count``, and ``double``
(``bool`` is not a numeric type).
When an automatic conversion occurs, values are promoted to the "highest"
type in the expression. In general, this promotion follows a simple
hierarchy: ``double`` is highest, ``int`` comes next, and ``count`` is
lowest.

The Bro scripting language supports the following built-in types.

.. bro:type:: void

    An internal Bro type (i.e., "void" is not a reserved keyword in the Bro
    scripting language) representing the absence of a return type for a
    function.

.. bro:type:: bool

    Reflects a value with one of two meanings: true or false.  The two
    ``bool`` constants are ``T`` and ``F``.

    The ``bool`` type supports the following operators: equality/inequality
    (``==``, ``!=``), logical and/or (``&&``, ``||``), logical
    negation (``!``), and absolute value (where ``|T|`` is 1, and ``|F|`` is 0).

.. bro:type:: int

    A numeric type representing a 64-bit signed integer.  An ``int`` constant
    is a string of digits preceded by a ``+`` or ``-`` sign, e.g.
    ``-42`` or ``+5`` (the "+" sign is optional but see note about type
    inferencing below).  An ``int`` constant can also be written in
    hexadecimal notation (in which case "0x" must be between the sign and
    the hex digits), e.g. ``-0xFF`` or ``+0xabc123``.

    The ``int`` type supports the following operators:  arithmetic
    operators (``+``, ``-``, ``*``, ``/``, ``%``), comparison operators
    (``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``), assignment operators
    (``=``, ``+=``, ``-=``), pre-increment (``++``), pre-decrement
    (``--``), and absolute value (e.g., ``|-3|`` is 3).

    When using type inferencing use care so that the
    intended type is inferred, e.g. ``local size_difference = 0`` will
    infer :bro:type:`count`, while ``local size_difference = +0``
    will infer :bro:type:`int`.

.. bro:type:: count

    A numeric type representing a 64-bit unsigned integer.  A ``count``
    constant is a string of digits, e.g. ``1234`` or ``0``.  A ``count``
    can also be written in hexadecimal notation (in which case "0x" must
    precede the hex digits), e.g. ``0xff`` or ``0xABC123``.

    The ``count`` type supports the same operators as the :bro:type:`int`
    type.  A unary plus or minus applied to a ``count`` results in an ``int``.

.. bro:type:: counter

    An alias to :bro:type:`count`.

.. bro:type:: double

    A numeric type representing a double-precision floating-point
    number.  Floating-point constants are written as a string of digits
    with an optional decimal point, optional scale-factor in scientific
    notation, and optional ``+`` or ``-`` sign.  Examples are ``-1234``,
    ``-1234e0``, ``3.14159``, and ``.003E-23``.

    The ``double`` type supports the following operators:  arithmetic
    operators (``+``, ``-``, ``*``, ``/``), comparison operators
    (``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``), assignment operators
    (``=``, ``+=``, ``-=``), and absolute value (e.g., ``|-3.14|`` is 3.14).

    When using type inferencing use care so that the
    intended type is inferred, e.g. ``local size_difference = 5`` will
    infer :bro:type:`count`, while ``local size_difference = 5.0``
    will infer :bro:type:`double`.

.. bro:type:: time

    A temporal type representing an absolute time.  There is currently
    no way to specify a ``time`` constant, but one can use the
    :bro:id:`double_to_time`, :bro:id:`current_time`, or :bro:id:`network_time`
    built-in functions to assign a value to a ``time``-typed variable.  

    Time values support the comparison operators (``==``, ``!=``, ``<``,
    ``<=``, ``>``, ``>=``).  A ``time`` value can be subtracted from
    another ``time`` value to produce an ``interval`` value.  An ``interval``
    value can be added to, or subtracted from, a ``time`` value to produce a
    ``time`` value.  The absolute value of a ``time`` value is a ``double``
    with the same numeric value.

.. bro:type:: interval

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

    Intervals support addition and subtraction.  Intervals also support
    division (in which case the result is a ``double`` value), the
    comparison operators (``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``),
    and the assignment operators (``=``, ``+=``, ``-=``).  Also, an
    ``interval`` can be multiplied or divided by an arithmetic type
    (``count``, ``int``, or ``double``) to produce an ``interval`` value.
    The absolute value of an ``interval`` is a ``double`` value equal to the
    number of seconds in the ``interval`` (e.g., ``|-1 min|`` is 60).

.. bro:type:: string

    A type used to hold character-string values which represent text.
    String constants are created by enclosing text in double quotes (")
    and the backslash character (\\) introduces escape sequences (all of
    the C-style escape sequences are supported).

    Strings support concatenation (``+``), and assignment (``=``, ``+=``).
    Strings also support the comparison operators (``==``, ``!=``, ``<``,
    ``<=``, ``>``, ``>=``).  The number of characters in a string can be
    found by enclosing the string within pipe characters (e.g., ``|"abc"|``
    is 3).

    The subscript operator can extract an individual character or a substring
    of a string (string indexing is zero-based, but an index of
    -1 refers to the last character in the string, and -2 refers to the
    second-to-last character, etc.).  When extracting a substring, the
    starting and ending index values are separated by a colon.  For example::

        local orig = "0123456789";
        local third_char = orig[2];
        local last_char = orig[-1];
        local first_three_chars = orig[0:2];

    Substring searching can be performed using the "in" or "!in"
    operators (e.g., "bar" in "foobar" yields true).

    Note that Bro represents strings internally as a count and vector of
    bytes rather than a NUL-terminated byte string (although string
    constants are also automatically NUL-terminated).  This is because
    network traffic can easily introduce NULs into strings either by
    nature of an application, inadvertently, or maliciously.  And while
    NULs are allowed in Bro strings, when present in strings passed as
    arguments to many functions, a run-time error can occur as their
    presence likely indicates a sort of problem.  In that case, the
    string will also only be represented to the user as the literal
    "<string-with-NUL>" string.

.. bro:type:: pattern

    A type representing regular-expression patterns which can be used
    for fast text-searching operations.  Pattern constants are created
    by enclosing text within forward slashes (/) and is the same syntax
    as the patterns supported by the `flex lexical analyzer
    <http://flex.sourceforge.net/manual/Patterns.html>`_.  The speed of
    regular expression matching does not depend on the complexity or
    size of the patterns.  Patterns support two types of matching, exact
    and embedded.

    In exact matching the ``==`` equality relational operator is used
    with one :bro:type:`pattern` operand and one :bro:type:`string`
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
    :bro:type:`pattern` operand (which must be on the left-hand side) and
    one :bro:type:`string` operand, but tests whether the pattern
    appears anywhere within the given string.  For example::

        /foo|bar/ in "foobar"

    yields true, while::

        /^oob/ in "foobar"

    is false since "oob" does not appear at the start of "foobar".  The
    ``!in`` operator would yield the negation of ``in``.

.. bro:type:: enum

    A type allowing the specification of a set of related values that
    have no further structure.  An example declaration:

    .. code:: bro

        type color: enum { Red, White, Blue, };

    The last comma after ``Blue`` is optional.

    The only operations allowed on enumerations are equality comparisons
    (``==``, ``!=``) and assignment (``=``).
    Enumerations do not have associated values or ordering.

.. bro:type:: port

    A type representing transport-level port numbers.  Besides TCP and
    UDP ports, there is a concept of an ICMP "port" where the source
    port is the ICMP message type and the destination port the ICMP
    message code.  A ``port`` constant is written as an unsigned integer
    followed by one of ``/tcp``, ``/udp``, ``/icmp``, or ``/unknown``.

    Ports support the comparison operators (``==``, ``!=``, ``<``, ``<=``,
    ``>``, ``>=``).  When comparing order across transport-level protocols,
    ``unknown`` < ``tcp`` < ``udp`` < ``icmp``, for example ``65535/tcp``
    is smaller than ``0/udp``.

    Note that you can obtain the transport-level protocol type of a ``port``
    with the :bro:id:`get_port_transport_proto` built-in function, and
    the numeric value of a ``port`` with the :bro:id:`port_to_count`
    built-in function.

.. bro:type:: addr

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

    Hostname constants can also be used, but since a hostname can
    correspond to multiple IP addresses, the type of such a variable is a
    :bro:type:`set` of :bro:type:`addr` elements. For example:

    .. code:: bro

        local a = www.google.com;

    Addresses can be compared for equality (``==``, ``!=``),
    and also for ordering (``<``, ``<=``, ``>``, ``>=``).  The absolute value
    of an address gives the size in bits (32 for IPv4, and 128 for IPv6).
    Addresses can also be masked with ``/`` to produce a :bro:type:`subnet`:

    .. code:: bro

        local a: addr = 192.168.1.100;
        local s: subnet = 192.168.0.0/16;
        if ( a/16 == s )
            print "true";

    And checked for inclusion within a :bro:type:`subnet` using ``in``
    or ``!in``:

    .. code:: bro

        local a: addr = 192.168.1.100;
        local s: subnet = 192.168.0.0/16;
        if ( a in s )
            print "true";

    Note that you can check if a given ``addr`` is IPv4 or IPv6 using
    the :bro:id:`is_v4_addr` and :bro:id:`is_v6_addr` built-in functions.

.. bro:type:: subnet

    A type representing a block of IP addresses in CIDR notation.  A
    ``subnet`` constant is written as an :bro:type:`addr` followed by a
    slash (/) and then the network prefix size specified as a decimal
    number.  For example, ``192.168.0.0/16`` or ``[fe80::]/64``.

    Subnets can be compared for equality (``==``, ``!=``).  An
    :bro:type:`addr` can be checked for inclusion in a subnet using
    the "in" or "!in" operators.

.. bro:type:: any

    Used to bypass strong typing.  For example, a function can take an
    argument of type ``any`` when it may be of different types.

.. bro:type:: table

    An associate array that maps from one set of values to another.  The
    values being mapped are termed the *index* or *indices* and the
    result of the mapping is called the *yield*.  Indexing into tables
    is very efficient, and internally it is just a single hash table
    lookup.

    The table declaration syntax is::

        table [ type^+ ] of type

    where *type^+* is one or more types, separated by commas.  For example:

    .. code:: bro

        global a: table[count] of string;

    declares a table indexed by :bro:type:`count` values and yielding
    :bro:type:`string` values.  The yield type can also be more complex:

    .. code:: bro

        global a: table[count] of table[addr, port] of string;

    which declares a table indexed by :bro:type:`count` and yielding
    another :bro:type:`table` which is indexed by an :bro:type:`addr`
    and :bro:type:`port` to yield a :bro:type:`string`.

    Initialization of tables occurs by enclosing a set of initializers within
    braces, for example:

    .. code:: bro

        global t: table[count] of string = {
            [11] = "eleven",
            [5] = "five",
        };

    A table constructor (equivalent to above example) can also be used
    to create a table:

    .. code:: bro

        global t2: table[count] of string = table(
            [11] = "eleven",
            [5] = "five"
        );

    Table constructors can also be explicitly named by a type, which is
    useful for when a more complex index type could otherwise be
    ambiguous:

    .. code:: bro

        type MyRec: record {
            a: count &optional;
            b: count;
        };

        type MyTable: table[MyRec] of string;

        global t3 = MyTable([[$b=5]] = "b5", [[$b=7]] = "b7");

    Accessing table elements is provided by enclosing index values within
    square brackets (``[]``), for example:

    .. code:: bro

        print t[11];

    And membership can be tested with ``in`` or ``!in``:

    .. code:: bro

        if ( 13 in t )
            ...

    Iterate over tables with a ``for`` loop:

    .. code:: bro

        local t: table[count] of string;
        for ( n in t )
            ...

        local services: table[addr, port] of string;
        for ( [a, p] in services )
            ...

    Add or overwrite individual table elements by assignment:

    .. code:: bro

        t[13] = "thirteen";

    Remove individual table elements with ``delete``:

    .. code:: bro

        delete t[13];

    Nothing happens if the element with index value ``13`` isn't present in
    the table.

    The number of elements in a table can be obtained by placing the table
    identifier between vertical pipe characters:

    .. code:: bro

        |t|

.. bro:type:: set

    A set is like a :bro:type:`table`, but it is a collection of indices
    that do not map to any yield value.  They are declared with the
    syntax::

        set [ type^+ ]

    where *type^+* is one or more types separated by commas.

    Sets are initialized by listing elements enclosed by curly braces:

    .. code:: bro

        global s: set[port] = { 21/tcp, 23/tcp, 80/tcp, 443/tcp };
        global s2: set[port, string] = { [21/tcp, "ftp"], [23/tcp, "telnet"] };

    The types are explicitly shown in the example above, but they could
    have been left to type inference.

    A set constructor (equivalent to above example) can also be used to
    create a set:

    .. code:: bro

        global s3: set[port] = set(21/tcp, 23/tcp, 80/tcp, 443/tcp);

    Set constructors can also be explicitly named by a type, which is
    useful for when a more complex index type could otherwise be
    ambiguous:

    .. code:: bro

        type MyRec: record {
            a: count &optional;
            b: count;
        };

        type MySet: set[MyRec];

        global s4 = MySet([$b=1], [$b=2]);

    Set membership is tested with ``in`` or ``!in``:

    .. code:: bro

        if ( 21/tcp in s )
            ...

        if ( 21/tcp !in s )
            ...

    Iterate over a set with a ``for`` loop:

    .. code:: bro

        local s: set[port];
        for ( p in s )
            ...

    Elements are added with ``add``:

    .. code:: bro

        add s[22/tcp];

    Nothing happens if the element with value ``22/tcp`` was already present in
    the set.

    And removed with ``delete``:

    .. code:: bro

        delete s[21/tcp];

    Nothing happens if the element with value ``21/tcp`` isn't present in
    the set.

    The number of elements in a set can be obtained by placing the set
    identifier between vertical pipe characters:

    .. code:: bro

        |s|

.. bro:type:: vector

    A vector is like a :bro:type:`table`, except it's always indexed by a
    :bro:type:`count` (and vector indexing is always zero-based).  A vector
    is declared like:

    .. code:: bro

        global v: vector of string;

    And can be initialized with the vector constructor:

    .. code:: bro

        global v: vector of string = vector("one", "two", "three");

    Vector constructors can also be explicitly named by a type, which
    is useful for when a more complex yield type could otherwise be
    ambiguous.

    .. code:: bro

        type MyRec: record {
            a: count &optional;
            b: count;
        };

        type MyVec: vector of MyRec;

        global v2 = MyVec([$b=1], [$b=2], [$b=3]);

    Accessing vector elements is provided by enclosing index values within
    square brackets (``[]``), for example:

    .. code:: bro

        print v[2];

    Iterate over a vector with a ``for`` loop:

    .. code:: bro

        local v: vector of string;
        for ( n in v )
            ...

    An element can be added to a vector by assigning the value (a value
    that already exists at that index will be overwritten):

    .. code:: bro

        v[3] = "four";

    The number of elements in a vector can be obtained by placing the vector
    identifier between vertical pipe characters:

    .. code:: bro

        |v|

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

.. bro:type:: record

    A ``record`` is a collection of values.  Each value has a field name
    and a type.  Values do not need to have the same type and the types
    have no restrictions.  An example record type definition:

    .. code:: bro

        type MyRecordType: record {
            c: count;
            s: string &optional;
        };

    Access to a record field uses the dollar sign (``$``) operator:

    .. code:: bro

        global r: MyRecordType;
        r$c = 13;

    Record assignment can be done field by field or as a whole like:

    .. code:: bro

        r = [$c = 13, $s = "thirteen"];

    When assigning a whole record value, all fields that are not
    :bro:attr:`&optional` or have a :bro:attr:`&default` attribute must
    be specified.

    To test for existence of a field that is :bro:attr:`&optional`, use the
    ``?$`` operator:

    .. code:: bro

        if ( r?$s )
            ...

    Records can also be created using a constructor syntax:

    .. code:: bro

        global r2: MyRecordType = record($c = 7);

    And the constructor can be explicitly named by type, too, which
    is arguably more readable code:

    .. code:: bro

        global r3 = MyRecordType($c = 42);

.. bro:type:: opaque

    A data type whose actual representation/implementation is
    intentionally hidden, but whose values may be passed to certain
    functions that can actually access the internal/hidden resources.
    Opaque types are differentiated from each other by qualifying them
    like ``opaque of md5`` or ``opaque of sha1``.  Any valid identifier
    can be used as the type qualifier.

    An example use of this type is the set of built-in functions which
    perform hashing:

    .. code:: bro

        local handle: opaque of md5 = md5_hash_init();
        md5_hash_update(handle, "test");
        md5_hash_update(handle, "testing");
        print md5_hash_finish(handle);

    Here the opaque type is used to provide a handle to a particular
    resource which is calculating an MD5 checksum incrementally over
    time, but the details of that resource aren't relevant, it's only
    necessary to have a handle as a way of identifying it and
    distinguishing it from other such resources.

.. bro:type:: file

    Bro supports writing to files, but not reading from them.  Files
    can be opened using either the :bro:id:`open` or :bro:id:`open_for_append`
    built-in functions, and closed using the :bro:id:`close` built-in
    function. For example, declare, open, and write to a file
    and finally close it like:

    .. code:: bro

        global f: file = open("myfile");
        print f, "hello, world";
        close(f);

    Writing to files like this for logging usually isn't recommended, for better
    logging support see :doc:`/frameworks/logging`.

.. bro:type:: function

    Function types in Bro are declared using::

        function( argument*  ): type

    where *argument* is a (possibly empty) comma-separated list of
    arguments, and *type* is an optional return type.  For example:

    .. code:: bro

        global greeting: function(name: string): string;

    Here ``greeting`` is an identifier with a certain function type.
    The function body is not defined yet and ``greeting`` could even
    have different function body values at different times.  To define
    a function including a body value, the syntax is like:

    .. code:: bro

        function greeting(name: string): string
            {
            return "Hello, " + name;
            }

    Note that in the definition above, it's not necessary for us to have
    done the first (forward) declaration of ``greeting`` as a function
    type, but when it is, the return type and argument list (including the
    name of each argument) must match exactly.

    Function types don't need to have a name and can be assigned anonymously:

    .. code:: bro

        greeting = function(name: string): string { return "Hi, " + name; };

    And finally, the function can be called like:

    .. code:: bro

        print greeting("Dave");

    Function parameters may specify default values as long as they appear
    last in the parameter list:

    .. code:: bro

        global foo: function(s: string, t: string &default="abc", u: count &default=0);

    If a function was previously declared with default parameters, the
    default expressions can be omitted when implementing the function
    body and they will still be used for function calls that lack those
    arguments.

    .. code:: bro

        function foo(s: string, t: string, u: count)
            {
            print s, t, u;
            }

    And calls to the function may omit the defaults from the argument list:

    .. code:: bro

        foo("test");

.. bro:type:: event

    Event handlers are nearly identical in both syntax and semantics to
    a :bro:type:`function`, with the two differences being that event
    handlers have no return type since they never return a value, and
    you cannot call an event handler.  Instead of directly calling an
    event handler from a script, event handler bodies are executed when
    they are invoked by one of three different methods:

    - From the event engine

        When the event engine detects an event for which you have
        defined a corresponding event handler, it queues an event for
        that handler.  The handler is invoked as soon as the event
        engine finishes processing the current packet and flushing the
        invocation of other event handlers that were queued first.

    - With the ``event`` statement from a script

        Immediately queuing invocation of an event handler occurs like:

        .. code:: bro

            event password_exposed(user, password);

        This assumes that ``password_exposed`` was previously declared
        as an event handler type with compatible arguments.

    - Via the ``schedule`` expression in a script

        This delays the invocation of event handlers until some time in
        the future.  For example:

        .. code:: bro

            schedule 5 secs { password_exposed(user, password) };

    Multiple event handler bodies can be defined for the same event handler
    identifier and the body of each will be executed in turn.  Ordering
    of execution can be influenced with :bro:attr:`&priority`.

.. bro:type:: hook

    A hook is another flavor of function that shares characteristics of
    both a :bro:type:`function` and an :bro:type:`event`.  They are like
    events in that many handler bodies can be defined for the same hook
    identifier and the order of execution can be enforced with
    :bro:attr:`&priority`.  They are more like functions in the way they
    are invoked/called, because, unlike events, their execution is
    immediate and they do not get scheduled through an event queue.
    Also, a unique feature of a hook is that a given hook handler body
    can short-circuit the execution of remaining hook handlers simply by
    exiting from the body as a result of a ``break`` statement (as
    opposed to a ``return`` or just reaching the end of the body).

    A hook type is declared like::

        hook( argument* )

    where *argument* is a (possibly empty) comma-separated list of
    arguments.  For example:

    .. code:: bro

        global myhook: hook(s: string)

    Here ``myhook`` is the hook type identifier and no hook handler
    bodies have been defined for it yet.  To define some hook handler
    bodies the syntax looks like:

    .. code:: bro

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

    .. code:: bro

        hook myhook("hi");

    or

    .. code:: bro

        if ( hook myhook("hi") )
            print "all handlers ran";

    And the output would look like::

        priority 10 myhook handler, hi
        break out of myhook handling, bye

    Note how the modification to arguments can be seen by remaining
    hook handlers.

    The return value of a hook call is an implicit :bro:type:`bool`
    value with ``T`` meaning that all handlers for the hook were
    executed and ``F`` meaning that only some of the handlers may have
    executed due to one handler body exiting as a result of a ``break``
    statement.

Attributes
----------

Attributes occur at the end of type/event declarations and change their
behavior. The syntax is ``&key`` or ``&key=val``, e.g., ``type T:
set[count] &read_expire=5min`` or ``event foo() &priority=-3``.  The Bro
scripting language supports the following built-in attributes.

.. bro:attr:: &optional

    Allows a record field to be missing. For example the type ``record {
    a: addr; b: port &optional; }`` could be instantiated both as
    singleton ``[$a=127.0.0.1]`` or pair ``[$a=127.0.0.1, $b=80/tcp]``.

.. bro:attr:: &default

    Uses a default value for a record field, a function/hook/event
    parameter, or container elements.  For example, ``table[int] of
    string &default="foo"`` would create a table that returns the
    :bro:type:`string` ``"foo"`` for any non-existing index.

.. bro:attr:: &redef

    Allows for redefinition of initial object values. This is typically
    used with constants, for example, ``const clever = T &redef;`` would
    allow the constant to be redefined at some later point during script
    execution.

.. bro:attr:: &rotate_interval

    Rotates a file after a specified interval.

.. bro:attr:: &rotate_size

    Rotates a file after it has reached a given size in bytes.

.. bro:attr:: &add_func

    Can be applied to an identifier with &redef to specify a function to
    be called any time a "redef <id> += ..." declaration is parsed.  The
    function takes two arguments of the same type as the identifier, the first
    being the old value of the variable and the second being the new
    value given after the "+=" operator in the "redef" declaration.  The
    return value of the function will be the actual new value of the
    variable after the "redef" declaration is parsed.

.. bro:attr:: &delete_func

    Same as &add_func, except for "redef" declarations that use the "-="
    operator.

.. bro:attr:: &expire_func

    Called right before a container element expires.  The function's
    first parameter is of the same type of the container and the second
    parameter the same type of the container's index.  The return
    value is an :bro:type:`interval` indicating the amount of additional
    time to wait before expiring the container element at the given
    index (which will trigger another execution of this function).

.. bro:attr:: &read_expire

    Specifies a read expiration timeout for container elements. That is,
    the element expires after the given amount of time since the last
    time it has been read. Note that a write also counts as a read.

.. bro:attr:: &write_expire

    Specifies a write expiration timeout for container elements. That
    is, the element expires after the given amount of time since the
    last time it has been written.

.. bro:attr:: &create_expire

    Specifies a creation expiration timeout for container elements. That
    is, the element expires after the given amount of time since it has
    been inserted into the container, regardless of any reads or writes.

.. bro:attr:: &persistent

    Makes a variable persistent, i.e., its value is written to disk (per
    default at shutdown time).

.. bro:attr:: &synchronized

    Synchronizes variable accesses across nodes. The value of a
    ``&synchronized`` variable is automatically propagated to all peers
    when it changes.

.. bro:attr:: &encrypt

    Encrypts files right before writing them to disk.

.. TODO: needs to be documented in more detail.

.. bro:attr:: &raw_output

    Opens a file in raw mode, i.e., non-ASCII characters are not
    escaped.

.. bro:attr:: &mergeable

    Prefers set union to assignment for synchronized state. This
    attribute is used in conjunction with :bro:attr:`&synchronized`
    container types: when the same container is updated at two peers
    with different value, the propagation of the state causes a race
    condition, where the last update succeeds. This can cause
    inconsistencies and can be avoided by unifying the two sets, rather
    than merely overwriting the old value.

.. bro:attr:: &priority

    Specifies the execution priority (as a signed integer) of a hook or
    event handler. Higher values are executed before lower ones. The
    default value is 0.

.. bro:attr:: &group

    Groups event handlers such that those in the same group can be
    jointly activated or deactivated.

.. bro:attr:: &log

    Writes a record field to the associated log stream.

.. bro:attr:: &error_handler

    Internally set on the events that are associated with the reporter
    framework: :bro:id:`reporter_info`, :bro:id:`reporter_warning`, and
    :bro:id:`reporter_error`.  It prevents any handlers of those events
    from being able to generate reporter messages that go through any of
    those events (i.e., it prevents an infinite event recursion).  Instead,
    such nested reporter messages are output to stderr.

.. bro:attr:: &type_column

    Used by the input framework. It can be used on columns of type
    :bro:type:`port` and specifies the name of an additional column in
    the input file which specifies the protocol of the port (tcp/udp/icmp).
