:tocdepth: 3

base/frameworks/input/readers/raw.zeek
======================================
.. zeek:namespace:: InputRaw

Interface for the raw input reader.

:Namespace: InputRaw

Summary
~~~~~~~
Redefinable Options
###################
============================================================================== ================================
:zeek:id:`InputRaw::record_separator`: :zeek:type:`string` :zeek:attr:`&redef` Separator between input records.
============================================================================== ================================

Events
######
========================================================= ====================================================================
:zeek:id:`InputRaw::process_finished`: :zeek:type:`event` Event that is called when a process created by the raw reader exits.
========================================================= ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: InputRaw::record_separator
   :source-code: base/frameworks/input/readers/raw.zeek 8 8

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"\x0a"``

   Separator between input records.
   Please note that the separator has to be exactly one character long.

Events
######
.. zeek:id:: InputRaw::process_finished
   :source-code: base/utils/exec.zeek 129 151

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, source: :zeek:type:`string`, exit_code: :zeek:type:`count`, signal_exit: :zeek:type:`bool`)

   Event that is called when a process created by the raw reader exits.
   

   :param name: name of the input stream.

   :param source: source of the input stream.

   :param exit_code: exit code of the program, or number of the signal that forced
              the program to exit.

   :param signal_exit: false when program exited normally, true when program was
                forced to exit by a signal.


