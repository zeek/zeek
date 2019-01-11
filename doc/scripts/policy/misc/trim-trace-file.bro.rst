:tocdepth: 3

policy/misc/trim-trace-file.bro
===============================
.. bro:namespace:: TrimTraceFile

Deletes the ``-w`` tracefile at regular intervals and starts a new file
from scratch.

:Namespace: TrimTraceFile

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================== ================================================================
:bro:id:`TrimTraceFile::trim_interval`: :bro:type:`interval` :bro:attr:`&redef` The interval between times that the output tracefile is rotated.
=============================================================================== ================================================================

Events
######
============================================== ===================================================================
:bro:id:`TrimTraceFile::go`: :bro:type:`event` This event can be generated externally to this script if on-demand
                                               tracefile rotation is required with the caveat that the script
                                               doesn't currently attempt to get back on schedule automatically and
                                               the next trim likely won't happen on the
                                               :bro:id:`TrimTraceFile::trim_interval`.
============================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: TrimTraceFile::trim_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 mins``

   The interval between times that the output tracefile is rotated.

Events
######
.. bro:id:: TrimTraceFile::go

   :Type: :bro:type:`event` (first_trim: :bro:type:`bool`)

   This event can be generated externally to this script if on-demand
   tracefile rotation is required with the caveat that the script
   doesn't currently attempt to get back on schedule automatically and
   the next trim likely won't happen on the
   :bro:id:`TrimTraceFile::trim_interval`.


