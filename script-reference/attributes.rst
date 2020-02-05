Attributes
==========

The Zeek scripting language supports the following attributes.

+------------------------------+-----------------------------------------------+
| Name                         | Description                                   |
+==============================+===============================================+
| :zeek:attr:`&redef`          |Redefine a global constant or extend a type.   |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&priority`       |Specify priority for event handler or hook.    |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&log`            |Mark a record field as to be written to a log. |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&optional`       |Allow a record field value to be missing.      |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&default`        |Specify a default value.                       |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&add_func`       |Specify a function to call for each "redef +=".|
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&delete_func`    |Same as "&add_func", except for "redef -=".    |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&expire_func`    |Specify a function to call when container      |
|                              |element expires.                               |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&read_expire`    |Specify a read timeout interval.               |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&write_expire`   |Specify a write timeout interval.              |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&create_expire`  |Specify a creation timeout interval.           |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&on_change`      |Specify a function to call on set/table changes|
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&raw_output`     |Open file in raw mode (chars. are not escaped).|
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&error_handler`  |Used internally for reporter framework events. |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&type_column`    |Used by input framework for "port" type.       |
+------------------------------+-----------------------------------------------+
| :zeek:attr:`&deprecated`     |Marks an identifier as deprecated.             |
+------------------------------+-----------------------------------------------+

.. _attribute-propagation-pitfalls:

.. warning::

    A confusing pitfall can be mistaking that attributes bind to a *variable*
    or a *type*, where in reality they bind to a *value*.  Example:

    .. sourcecode:: zeek

        global my_table: table[count] of string &create_expire=1sec;

        event zeek_init()
            {
            my_table = table();
            my_table[1] = "foo";
            }

    In the above, the re-assignment of ``my_table`` will also drop the original
    *value*'s :zeek:attr:`&create_expire` and no entries will ever be expired
    from ``my_table``.  The alternate way of re-assignment that creates a new
    table *value* with the expected attribute would be:

    .. sourcecode:: zeek

        my_table = table() &create_expire=1sec;

Here is a more detailed explanation of each attribute:

.. zeek:attr:: &redef

    Allows use of a :zeek:keyword:`redef` to redefine initial values of
    global variables (i.e., variables declared either :zeek:keyword:`global`
    or :zeek:keyword:`const`).  Example:

    .. sourcecode:: zeek

        const clever = T &redef;
        global cache_size = 256 &redef;

    Note that a variable declared "global" can also have its value changed
    with assignment statements (doesn't matter if it has the "&redef"
    attribute or not).

.. zeek:attr:: &priority

    Specifies the execution priority (as a signed integer) of a hook or
    event handler. Higher values are executed before lower ones. The
    default value is 0.  Example:

    .. sourcecode:: zeek

        event zeek_init() &priority=10
            {
            print "high priority";
            }

.. zeek:attr:: &log

    Writes a :zeek:type:`record` field to the associated log stream.

.. zeek:attr:: &optional

    Allows a record field value to be missing (i.e., neither initialized nor
    ever assigned a value).

    In this example, the record could be instantiated with either
    "myrec($a=127.0.0.1)" or "myrec($a=127.0.0.1, $b=80/tcp)":

    .. sourcecode:: zeek

        type myrec: record { a: addr; b: port &optional; };

    The ``?$`` operator can be used to check if a record field has a value or
    not (it returns a ``bool`` value of ``T`` if the field has a value,
    and ``F`` if not).

.. zeek:attr:: &default

    Specifies a default value for a record field, container element, or a
    function/hook/event parameter.

    In this example, the record could be instantiated with either
    "myrec($a=5, $c=3.14)" or "myrec($a=5, $b=53/udp, $c=3.14)":

    .. sourcecode:: zeek

        type myrec: record { a: count; b: port &default=80/tcp; c: double; };

    In this example, the table will return the string ``"foo"`` for any
    attempted access to a non-existing index:

    .. sourcecode:: zeek

        global mytable: table[count] of string &default="foo";

    When used with function/hook/event parameters, all of the parameters
    with the "&default" attribute must come after all other parameters.
    For example, the following function could be called either as "myfunc(5)"
    or as "myfunc(5, 53/udp)":

    .. sourcecode:: zeek

        function myfunc(a: count, b: port &default=80/tcp)
            {
            print a, b;
            }

.. zeek:attr:: &add_func

    Can be applied to an identifier with &redef to specify a function to
    be called any time a "redef <id> += ..." declaration is parsed.  The
    function takes two arguments of the same type as the identifier, the first
    being the old value of the variable and the second being the new
    value given after the "+=" operator in the "redef" declaration.  The
    return value of the function will be the actual new value of the
    variable after the "redef" declaration is parsed.

.. zeek:attr:: &delete_func

    Same as :zeek:attr:`&add_func`, except for :zeek:keyword:`redef` declarations
    that use the "-=" operator.

.. zeek:attr:: &expire_func

    Called right before a container element expires. The function's first
    argument is of the same type as the container it is associated with.
    The function then takes a variable number of arguments equal to the
    number of indexes in the container. For example, for a
    ``table[string,string] of count`` the expire function signature is:

    .. sourcecode:: zeek

        function(t: table[string, string] of count, s: string, s2: string): interval

    The return value is an :zeek:type:`interval` indicating the amount of
    additional time to wait before expiring the container element at the
    given index (which will trigger another execution of this function).

.. zeek:attr:: &read_expire

    Specifies a read expiration timeout for container elements. That is,
    the element expires after the given amount of time since the last
    time it has been read. Note that a write also counts as a read.

.. zeek:attr:: &write_expire

    Specifies a write expiration timeout for container elements. That
    is, the element expires after the given amount of time since the
    last time it has been written.

.. zeek:attr:: &create_expire

    Specifies a creation expiration timeout for container elements. That
    is, the element expires after the given amount of time since it has

.. zeek:attr:: &on_change

    Called right after a change has been applied to a container. The
    function's first argument is of the same type as the container it is
    associated with, followed by a :zeek:see:`TableChange` record which specifies the
    type of change that happened. The function then takes a variable number
    of arguments equal to the number of indexes in the container, followed by an
    argument for the value of the container (if the container has a value)
    For example, for a ``table[string,string] of count`` the on_change
    function signature is:

    .. sourcecode:: zeek

        function(t: table[string, string] of count, tpe: TableChange, s: string, s2: string, val: count)

    For a ``set[count]`` the function signature is:

    .. sourcecode:: zeek

        function(s: set[count], tpe: TableChange, c: count)

    The passed value specifies the state of a value before the change, where this makes
    sense. In case a element is changed, removed, or expired, the passed value will be
    the value before the change, removal, or expiration. When an element is added, the
    passed value will be the value of the added element (since no old element existed).

    Note that the on_change function is only changed when the container itself
    is modified (due to an assignment, delete operation, or expiry). When
    a container contains a complex element (like a record, set, or vector),
    changes to these complex elements are not propagated back to the parent.
    For example, in this example the ``change_function`` for the table will only
    be called once, when ``s`` is inserted - but it will not be called when ``s`` is
    changed:

    .. sourcecode:: zeek

        local t: table[string] of set[string] &on_change=change_function;
        local s: set[string] = set();
        t["s"] = s; # change_function of t is called
        add s["a"]; # change_function of t is _not_ called.

    Also note that the on_change function of a container will not be called
    when the container is already handling on_change_function. Thus, writing
    a on_change function like this is supported and will not lead to a infinite
    loop :

    .. sourcecode:: zeek

        local t: table[string] of set[string] &on_change=hange_function;
        function change_function(t: table[string, int] of count, tpe: TableChange, idxa: string, idxb: int, val: count)
          {
          t[idxa, idxb] = val+1;
          }

.. zeek:attr:: &raw_output

    Opens a file in raw mode, i.e., non-ASCII characters are not
    escaped.

.. zeek:attr:: &error_handler

    Internally set on the events that are associated with the reporter
    framework: :zeek:id:`reporter_info`, :zeek:id:`reporter_warning`, and
    :zeek:id:`reporter_error`.  It prevents any handlers of those events
    from being able to generate reporter messages that go through any of
    those events (i.e., it prevents an infinite event recursion).  Instead,
    such nested reporter messages are output to stderr.

.. zeek:attr:: &type_column

    Used by the input framework. It can be used on columns of type
    :zeek:type:`port` (such a column only contains the port number) and
    specifies the name of an additional column in
    the input file which specifies the protocol of the port (tcp/udp/icmp).

    In the following example, the input file would contain four columns
    named "ip", "srcp", "proto", and "msg":

    .. sourcecode:: zeek

        type Idx: record {
            ip: addr;
        };


        type Val: record {
            srcp: port &type_column = "proto";
            msg: string;
        };

.. zeek:attr:: &deprecated

    The associated identifier is marked as deprecated and will be
    removed in a future version of Zeek.  Look in the NEWS file for more
    instructions to migrate code that uses deprecated functionality.
    This attribute can be assigned an optional string literal value to
    print along with the deprecation warning. The preferred format of
    this warning message should include the version number in which
    the identifier will be removed:

    .. sourcecode:: zeek

        type warned: string &deprecated="This type is deprecated. Removed in x.y.z.";
