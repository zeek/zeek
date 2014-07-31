Attributes
==========

Attributes occur at the end of type or event declarations and change their
behavior. The syntax is ``&key`` or ``&key=val``, e.g., ``type T:
set[count] &read_expire=5min`` or ``event foo() &priority=-3``.  The Bro
scripting language supports the following attributes.

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
