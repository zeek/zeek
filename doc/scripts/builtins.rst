Builtin Types and Attributes
============================

Types
-----

The Bro scripting language supports the following built-in types.

.. TODO: add documentation

.. bro:type:: void

.. bro:type:: bool

.. bro:type:: int

.. bro:type:: count

.. bro:type:: counter

.. bro:type:: double

.. bro:type:: time

.. bro:type:: interval

.. bro:type:: string

.. bro:type:: pattern

.. bro:type:: enum

.. bro:type:: timer

.. bro:type:: port

.. bro:type:: addr

.. bro:type:: net

.. bro:type:: subnet

.. bro:type:: any

.. bro:type:: table

.. bro:type:: union

.. bro:type:: record

.. bro:type:: types

.. bro:type:: func

.. bro:type:: file

.. bro:type:: vector

.. TODO: below are kind of "special cases" that bro knows about?

.. bro:type:: set

.. bro:type:: function

.. bro:type:: event

Attributes
----------

Attributes occur at the end of type/event declarations and change their
behavior. The syntax is ``&key`` or ``&key=val``, e.g.,
``type T: set[count] &read_expire=5min`` or ``event foo() &priority=-3``.
The Bro scripting language supports the following built-in attributes.

## Allows record field to be missing. For example the type 
## ``record { a: int, b: port &optional }`` could be instantiated both as
## singleton ``[$a=127.0.0.1]`` or pair ``[$a=127.0.0.1, $b=80/tcp]``.
.. bro:attr:: &optional

## Uses a default value for a record field or container elements. For example,
## ``table[int] of string &default="foo" }`` would create table that returns
## The :bro:type:`string` ``"foo"`` for any non-existing index.
.. bro:attr:: &default

## Allows for redefinition of initial object values. This is typically used
## with constants, for example, ``const clever = T &redef;`` would allow the
## constant to be redifined at some later point during script execution.
.. bro:attr:: &redef

## Rotates a file after a specified interval.
.. bro:attr:: &rotate_interval

## Rotates af file after it has reached a given size in bytes.
.. bro:attr:: &rotate_size

## ..TODO: needs to be documented.
.. bro:attr:: &add_func

## ..TODO: needs to be documented.
.. bro:attr:: &delete_func

## Called right before a container element expires.
.. bro:attr:: &expire_func

## Specifies a read expiration timeout for container elements. That is, the
## element expires after the given amount of time since the last time it has
## been read. Note that a write also counts as a read.
.. bro:attr:: &read_expire

## Specifies a write expiration timeout for container elements. That is, the
## element expires after the given amount of time since the last time it has
## been written.
.. bro:attr:: &write_expire

## Specifies a creation expiration timeout for container elements. That is, the
## element expires after the given amount of time since it has been inserted
## into the container, regardless of any reads or writes.
.. bro:attr:: &create_expire

## Makes a variable persistent, i.e., its value is writen to disk (per default
## at shutdown time).
.. bro:attr:: &persistent

## Synchronizes variable accesses across nodes. The value of a
## ``&synchronized`` variable is automatically propagated to all peers when it
## changes.
.. bro:attr:: &synchronized

## ..TODO: needs to be documented.
.. bro:attr:: &postprocessor

## Encryptes files right before writing them to disk.
## ..TODO: needs to be documented in more detail.
.. bro:attr:: &encrypt

## ..TODO: needs to be documented.
.. bro:attr:: &match

## Deprecated. Will be removed.
.. bro:attr:: &disable_print_hook

## Opens a file in raw mode, i.e., non-ASCII characters are not escaped.
.. bro:attr:: &raw_output

## Prefers set union to assignment for synchronized state. This attribute is 
## used in conjunction with :bro:attr:`synchronized` container types: when the
## same container is updated at two peers with different value, the propagation
## of the state causes a race condition, where the last update succeeds. This
## can cause inconsistencies and can be avoided by unifying the two sets,
## rather than merely overwriting the old value.
.. bro:attr:: &mergeable

## Specifies the execution priority of an event handler. Higher values are
## executed before lower ones. The default value is 0.
.. bro:attr:: &priority

## Groups event handlers such that those in the same group can be jointly
## activated or deactivated.
.. bro:attr:: &group

## Writes a record field to the associated log stream.
.. bro:attr:: &log

.. bro:attr:: (&tracked)
