:tocdepth: 3

policy/misc/dump-events.zeek
============================
.. zeek:namespace:: DumpEvents

This script dumps the events that Zeek raises out to standard output in a
readable form. This is for debugging only and allows to understand events and
their parameters as Zeek processes input. Note that it will show only events
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

Redefinable Options
###################
============================================================================= ================================================================
:zeek:id:`DumpEvents::dump_all_events`: :zeek:type:`bool` :zeek:attr:`&redef` By default, only events that are handled in a script are dumped.
============================================================================= ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DumpEvents::include
   :source-code: policy/misc/dump-events.zeek 18 18

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?(.*)$?/


   Only include events matching the given pattern into output. By default, the
   pattern matches all events.

.. zeek:id:: DumpEvents::include_args
   :source-code: policy/misc/dump-events.zeek 10 10

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, include event arguments in output.

Redefinable Options
###################
.. zeek:id:: DumpEvents::dump_all_events
   :source-code: policy/misc/dump-events.zeek 14 14

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   By default, only events that are handled in a script are dumped. Setting this option to true
   will cause unhandled events to be dumped too.


