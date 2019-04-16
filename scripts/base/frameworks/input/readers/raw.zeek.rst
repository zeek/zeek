:tocdepth: 3

base/frameworks/input/readers/raw.zeek
======================================
.. bro:namespace:: InputRaw

Interface for the raw input reader.

:Namespace: InputRaw

Summary
~~~~~~~
Redefinable Options
###################
=========================================================================== ================================
:bro:id:`InputRaw::record_separator`: :bro:type:`string` :bro:attr:`&redef` Separator between input records.
=========================================================================== ================================

Events
######
======================================================= ====================================================================
:bro:id:`InputRaw::process_finished`: :bro:type:`event` Event that is called when a process created by the raw reader exits.
======================================================= ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: InputRaw::record_separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"\x0a"``

   Separator between input records.
   Please note that the separator has to be exactly one character long.

Events
######
.. bro:id:: InputRaw::process_finished

   :Type: :bro:type:`event` (name: :bro:type:`string`, source: :bro:type:`string`, exit_code: :bro:type:`count`, signal_exit: :bro:type:`bool`)

   Event that is called when a process created by the raw reader exits.
   

   :name: name of the input stream.

   :source: source of the input stream.

   :exit_code: exit code of the program, or number of the signal that forced
              the program to exit.

   :signal_exit: false when program exited normally, true when program was
                forced to exit by a signal.


