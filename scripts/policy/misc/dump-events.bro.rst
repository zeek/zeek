:tocdepth: 3

policy/misc/dump-events.bro
===========================
.. bro:namespace:: DumpEvents

This script dumps the events that Bro raises out to standard output in a
readable form. This is for debugging only and allows to understand events and
their parameters as Bro processes input. Note that it will show only events
for which a handler is defined.

:Namespace: DumpEvents

Summary
~~~~~~~
Runtime Options
###############
======================================================================= ===========================================================
:bro:id:`DumpEvents::include`: :bro:type:`pattern` :bro:attr:`&redef`   Only include events matching the given pattern into output.
:bro:id:`DumpEvents::include_args`: :bro:type:`bool` :bro:attr:`&redef` If true, include event arguments in output.
======================================================================= ===========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: DumpEvents::include

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /^?(.*)$?/

   Only include events matching the given pattern into output. By default, the
   pattern matches all events.

.. bro:id:: DumpEvents::include_args

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, include event arguments in output.


