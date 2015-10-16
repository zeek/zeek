Attributes
==========

The Bro scripting language supports the following attributes.

+-----------------------------+-----------------------------------------------+
| Name                        | Description                                   |
+=============================+===============================================+
| :bro:attr:`&redef`          |Redefine a global constant or extend a type.   |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&priority`       |Specify priority for event handler or hook.    |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&log`            |Mark a record field as to be written to a log. |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&optional`       |Allow a record field value to be missing.      |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&default`        |Specify a default value.                       |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&add_func`       |Specify a function to call for each "redef +=".|
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&delete_func`    |Same as "&add_func", except for "redef -=".    |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&expire_func`    |Specify a function to call when container      |
|                             |element expires.                               |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&read_expire`    |Specify a read timeout interval.               |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&write_expire`   |Specify a write timeout interval.              |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&create_expire`  |Specify a creation timeout interval.           |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&synchronized`   |Synchronize a variable across nodes.           |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&persistent`     |Make a variable persistent (written to disk).  |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&rotate_interval`|Rotate a file after specified interval.        |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&rotate_size`    |Rotate a file after specified file size.       |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&encrypt`        |Encrypt a file when writing to disk.           |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&raw_output`     |Open file in raw mode (chars. are not escaped).|
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&mergeable`      |Prefer set union for synchronized state.       |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&error_handler`  |Used internally for reporter framework events. |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&type_column`    |Used by input framework for "port" type.       |
+-----------------------------+-----------------------------------------------+
| :bro:attr:`&deprecated`     |Marks an identifier as deprecated.             |
+-----------------------------+-----------------------------------------------+

Here is a more detailed explanation of each attribute:

.. bro:attr:: &redef

    Allows use of a :bro:keyword:`redef` to redefine initial values of
    global variables (i.e., variables declared either :bro:keyword:`global`
    or :bro:keyword:`const`).  Example::

        const clever = T &redef;
        global cache_size = 256 &redef;

    Note that a variable declared "global" can also have its value changed
    with assignment statements (doesn't matter if it has the "&redef"
    attribute or not).

.. bro:attr:: &priority

    Specifies the execution priority (as a signed integer) of a hook or
    event handler. Higher values are executed before lower ones. The
    default value is 0.  Example::

        event bro_init() &priority=10
        {
            print "high priority";
        }

.. bro:attr:: &log

    Writes a :bro:type:`record` field to the associated log stream.

.. bro:attr:: &optional

    Allows a record field value to be missing (i.e., neither initialized nor
    ever assigned a value).

    In this example, the record could be instantiated with either
    "myrec($a=127.0.0.1)" or "myrec($a=127.0.0.1, $b=80/tcp)"::

        type myrec: record { a: addr; b: port &optional; };

    The ``?$`` operator can be used to check if a record field has a value or
    not (it returns a ``bool`` value of ``T`` if the field has a value,
    and ``F`` if not).

.. bro:attr:: &default

    Specifies a default value for a record field, container element, or a
    function/hook/event parameter.

    In this example, the record could be instantiated with either
    "myrec($a=5, $c=3.14)" or "myrec($a=5, $b=53/udp, $c=3.14)"::

        type myrec: record { a: count; b: port &default=80/tcp; c: double; };

    In this example, the table will return the string ``"foo"`` for any
    attempted access to a non-existing index::

        global mytable: table[count] of string &default="foo";

    When used with function/hook/event parameters, all of the parameters
    with the "&default" attribute must come after all other parameters.
    For example, the following function could be called either as "myfunc(5)"
    or as "myfunc(5, 53/udp)"::

        function myfunc(a: count, b: port &default=80/tcp)
        {
            print a, b;
        }

.. bro:attr:: &add_func

    Can be applied to an identifier with &redef to specify a function to
    be called any time a "redef <id> += ..." declaration is parsed.  The
    function takes two arguments of the same type as the identifier, the first
    being the old value of the variable and the second being the new
    value given after the "+=" operator in the "redef" declaration.  The
    return value of the function will be the actual new value of the
    variable after the "redef" declaration is parsed.

.. bro:attr:: &delete_func

    Same as :bro:attr:`&add_func`, except for :bro:keyword:`redef` declarations
    that use the "-=" operator.

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

.. bro:attr:: &synchronized

    Synchronizes variable accesses across nodes. The value of a
    ``&synchronized`` variable is automatically propagated to all peers
    when it changes.

.. bro:attr:: &persistent

    Makes a variable persistent, i.e., its value is written to disk (per
    default at shutdown time).

.. bro:attr:: &rotate_interval

    Rotates a file after a specified interval.

    Note: This attribute is deprecated and will be removed in a future release.

.. bro:attr:: &rotate_size

    Rotates a file after it has reached a given size in bytes.

    Note: This attribute is deprecated and will be removed in a future release.

.. bro:attr:: &encrypt

    Encrypts files right before writing them to disk.

    Note: This attribute is deprecated and will be removed in a future release.

.. bro:attr:: &raw_output

    Opens a file in raw mode, i.e., non-ASCII characters are not
    escaped.

.. bro:attr:: &mergeable

    Prefers merging sets on assignment for synchronized state. This
    attribute is used in conjunction with :bro:attr:`&synchronized`
    container types: when the same container is updated at two peers
    with different values, the propagation of the state causes a race
    condition, where the last update succeeds. This can cause
    inconsistencies and can be avoided by unifying the two sets, rather
    than merely overwriting the old value.

.. bro:attr:: &error_handler

    Internally set on the events that are associated with the reporter
    framework: :bro:id:`reporter_info`, :bro:id:`reporter_warning`, and
    :bro:id:`reporter_error`.  It prevents any handlers of those events
    from being able to generate reporter messages that go through any of
    those events (i.e., it prevents an infinite event recursion).  Instead,
    such nested reporter messages are output to stderr.

.. bro:attr:: &type_column

    Used by the input framework. It can be used on columns of type
    :bro:type:`port` (such a column only contains the port number) and
    specifies the name of an additional column in
    the input file which specifies the protocol of the port (tcp/udp/icmp).

    In the following example, the input file would contain four columns
    named "ip", "srcp", "proto", and "msg"::

        type Idx: record {
            ip: addr;
        };


        type Val: record {
            srcp: port &type_column = "proto";
            msg: string;
        };

.. bro:attr:: &deprecated

    The associated identifier is marked as deprecated and will be
    removed in a future version of Bro.  Look in the NEWS file for more
    instructions to migrate code that uses deprecated functionality.
