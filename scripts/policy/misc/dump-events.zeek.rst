:tocdepth: 3

policy/misc/dump-events.zeek
============================
.. zeek:namespace:: DumpEvents

This script dumps the events that Bro raises out to standard output in a
readable form. This is for debugging only and allows to understand events and
their parameters as Bro processes input. Note that it will show only events
for which a handler is defined.

:Namespace: DumpEvents

Summary
~~~~~~~
Runtime Options
###############
========================================================================== ===========================================================
:zeek:id:`DumpEvents::include`: :zeek:type:`pattern` :zeek:attr:`&redef`   Only include events matching the given pattern into output.
:zeek:id:`DumpEvents::include_args`: :zeek:type:`bool` :zeek:attr:`&redef` If true, include event arguments in output.
========================================================================== ===========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DumpEvents::include

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

   ::

      /^?(.*)$?/

   Only include events matching the given pattern into output. By default, the
   pattern matches all events.

.. zeek:id:: DumpEvents::include_args

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, include event arguments in output.


