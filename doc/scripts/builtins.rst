Builtin Types and Attributes
============================

Types
-----

The Bro scripting language supports the following built-in types.

.. bro:type:: void

    An internal Bro type representing an absence of a type.  Should
    most often be seen as a possible function return type.

.. bro:type:: bool

    Reflects a value with one of two meanings: true or false.  The two
    ``bool`` constants are ``T`` and ``F``.

.. bro:type:: int

    A numeric type representing a signed integer.  An ``int`` constant
    is a string of digits preceded by a ``+`` or ``-`` sign, e.g.
    ``-42`` or ``+5``.  When using type inferencing use care so that the
    intended type is inferred, e.g. ``local size_difference = 0`` will
    infer :bro:type:`count`, while ``local size_difference = +0``
    will infer :bro:type:`int`.

.. bro:type:: count

    A numeric type representing an unsigned integer.  A ``count``
    constant is a string of digits, e.g. ``1234`` or ``0``.

.. bro:type:: counter

    An alias to :bro:type:`count`.

.. TODO: is there anything special about this type?

.. bro:type:: double

    A numeric type representing a double-precision floating-point
    number.  Floating-point constants are written as a string of digits
    with an optional decimal point, optional scale-factor in scientific
    notation, and optional ``+`` or ``-`` sign.  Examples are ``-1234``,
    ``-1234e0``, ``3.14159``, and ``.003e-23``.

.. bro:type:: time

    A temporal type representing an absolute time.  There is currently
    no way to specify a ``time`` constant, but one can use the
    :bro:id:`current_time` or :bro:id:`network_time` built-in functions
    to assign a value to a ``time``-typed variable.

.. bro:type:: interval

    A temporal type representing a relative time.  An ``interval``
    constant can be written as a numeric constant followed by a time
    unit where the time unit is one of ``usec``, ``msec``, ``sec``, ``min``,
    ``hr``, or ``day`` which respectively represent microseconds, milliseconds,
    seconds, minutes, hours, and days.  Whitespace between the numeric
    constant and time unit is optional.  Appending the letter "s" to the
    time unit in order to pluralize it is also optional (to no semantic
    effect).  Examples of ``interval`` constants are ``3.5 min`` and
    ``3.5mins``.  An ``interval`` can also be negated, for example ``-
    12 hr`` represents "twelve hours in the past".  Intervals also
    support addition, subtraction, multiplication, division, and
    comparison operations.

.. bro:type:: string

    A type used to hold character-string values which represent text.
    String constants are created by enclosing text in double quotes (")
    and the backslash character (\\) introduces escape sequences.

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
    have no further structure.  The only operations allowed on
    enumerations are equality comparisons and they do not have
    associated values or ordering.  An example declaration:

    .. code:: bro

        type color: enum { Red, White, Blue, };

    The last comma after ``Blue`` is optional.

.. bro:type:: timer

.. TODO: is this a type that's exposed to users?

.. bro:type:: port

    A type representing transport-level port numbers.  Besides TCP and
    UDP ports, there is a concept of an ICMP "port" where the source
    port is the ICMP message type and the destination port the ICMP
    message code.  A ``port`` constant is written as an unsigned integer
    followed by one of ``/tcp``, ``/udp``, ``/icmp``, or ``/unknown``.

    Ports can be compared for equality and also for ordering.  When
    comparing order across transport-level protocols, ``unknown`` <
    ``tcp`` < ``udp`` < ``icmp``, for example ``65535/tcp`` is smaller
    than ``0/udp``.

.. bro:type:: addr

    A type representing an IP address.

    IPv4 address constants are written in "dotted quad" format,
    ``A1.A2.A3.A4``, where Ai all lie between 0 and 255.

    IPv6 address constants are written as colon-separated hexadecimal form
    as described by :rfc:`2373`, but additionally encased in square brackets.
    The mixed notation with embedded IPv4 addresses as dotted-quads in the
    lower 32 bits is also allowed.
    Some examples: ``[2001:db8::1]``, ``[::ffff:192.168.1.100]``, or
    ``[aaaa:bbbb:cccc:dddd:eeee:ffff:1111:2222]``.

    Hostname constants can also be used, but since a hostname can
    correspond to multiple IP addresses, the type of such variable is a
    :bro:type:`set` of :bro:type:`addr` elements. For example:

    .. code:: bro

        local a = www.google.com;

    Addresses can be compared for (in)equality using ``==`` and ``!=``.
    They can also be masked with ``/`` to produce a :bro:type:`subnet`:

    .. code:: bro

        local a: addr = 192.168.1.100;
        local s: subnet = 192.168.0.0/16;
        if ( a/16 == s )
            print "true";

    And checked for inclusion within a :bro:type:`subnet` using ``in`` :

    .. code:: bro

        local a: addr = 192.168.1.100;
        local s: subnet = 192.168.0.0/16;
        if ( a in s )
            print "true";

.. bro:type:: subnet

    A type representing a block of IP addresses in CIDR notation.  A
    ``subnet`` constant is written as an :bro:type:`addr` followed by a
    slash (/) and then the network prefix size specified as a decimal
    number.  For example, ``192.168.0.0/16`` or ``[fe80::]/64``.

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

    Accessing table elements if provided by enclosing values within square
    brackets (``[]``), for example:

    .. code:: bro

        t[13] = "thirteen";

    And membership can be tested with ``in``:

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

    Remove individual table elements with ``delete``:

    .. code:: bro

        delete t[13];

    Nothing happens if the element with value ``13`` isn't present in
    the table.

    Table size can be obtained by placing the table identifier between
    vertical pipe (|) characters:

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

    Set membership is tested with ``in``:

    .. code:: bro

        if ( 21/tcp in s )
            ...

    Elements are added with ``add``:

    .. code:: bro

        add s[22/tcp];

    And removed with ``delete``:

    .. code:: bro

        delete s[21/tcp];

    Set size can be obtained by placing the set identifier between
    vertical pipe (|) characters:

    .. code:: bro

        |s|

.. bro:type:: vector

    A vector is like a :bro:type:`table`, except it's always indexed by a
    :bro:type:`count`.  A vector is declared like:

    .. code:: bro

        global v: vector of string;

    And can be initialized with the vector constructor:

    .. code:: bro

        global v: vector of string = vector("one", "two", "three");

    Adding an element to a vector involves accessing/assigning it:

    .. code:: bro

        v[3] = "four"

    Note how the vector indexing is 0-based.

    Vector size can be obtained by placing the vector identifier between
    vertical pipe (|) characters:

    .. code:: bro

        |v|

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

.. bro:type:: file

    Bro supports writing to files, but not reading from them.  For
    example, declare, open, and write to a file and finally close it
    like:

    .. code:: bro

        global f: file = open("myfile");
        print f, "hello, world";
        close(f);

    Writing to files like this for logging usually isn't recommended, for better
    logging support see :doc:`/logging`.

.. bro:type:: func

    See :bro:type:`function`.

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
    type, but when it is, the argument list and return type much match
    exactly.

    Function types don't need to have a name and can be assigned anonymously:

    .. code:: bro

        greeting = function(name: string): string { return "Hi, " + name; };

    And finally, the function can be called like:

    .. code:: bro

        print greeting("Dave");

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

Attributes
----------

Attributes occur at the end of type/event declarations and change their
behavior. The syntax is ``&key`` or ``&key=val``, e.g., ``type T:
set[count] &read_expire=5min`` or ``event foo() &priority=-3``.  The Bro
scripting language supports the following built-in attributes.

.. bro:attr:: &optional

    Allows a record field to be missing. For example the type ``record {
    a: int, b: port &optional }`` could be instantiated both as
    singleton ``[$a=127.0.0.1]`` or pair ``[$a=127.0.0.1, $b=80/tcp]``.

.. bro:attr:: &default

    Uses a default value for a record field or container elements. For
    example, ``table[int] of string &default="foo" }`` would create a
    table that returns the :bro:type:`string` ``"foo"`` for any
    non-existing index.

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

.. TODO: needs to be documented.

.. bro:attr:: &delete_func

.. TODO: needs to be documented.

.. bro:attr:: &expire_func

    Called right before a container element expires.  The function's
    first parameter is of the same type of the container and the second
    parameter the same type of the container's index.  The return
    value is a :bro:type:`interval` indicating the amount of additional
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

    Makes a variable persistent, i.e., its value is writen to disk (per
    default at shutdown time).

.. bro:attr:: &synchronized

    Synchronizes variable accesses across nodes. The value of a
    ``&synchronized`` variable is automatically propagated to all peers
    when it changes.

.. bro:attr:: &postprocessor

.. TODO: needs to be documented.

.. bro:attr:: &encrypt

    Encrypts files right before writing them to disk.

.. TODO: needs to be documented in more detail.

.. bro:attr:: &match

.. TODO: needs to be documented.

.. bro:attr:: &disable_print_hook

    Deprecated. Will be removed.

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

    Specifies the execution priority of an event handler. Higher values
    are executed before lower ones. The default value is 0.

.. bro:attr:: &group

    Groups event handlers such that those in the same group can be
    jointly activated or deactivated.

.. bro:attr:: &log

    Writes a record field to the associated log stream.

.. bro:attr:: &error_handler

.. TODO: needs documented

.. bro:attr:: (&tracked)

.. TODO: needs documented or removed if it's not used anywhere.
