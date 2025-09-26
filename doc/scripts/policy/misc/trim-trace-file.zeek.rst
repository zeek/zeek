:tocdepth: 3

policy/misc/trim-trace-file.zeek
================================
.. zeek:namespace:: TrimTraceFile

Deletes the ``-w`` tracefile at regular intervals and starts a new file
from scratch.

:Namespace: TrimTraceFile

Summary
~~~~~~~
Redefinable Options
###################
================================================================================== ================================================================
:zeek:id:`TrimTraceFile::trim_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The interval between times that the output tracefile is rotated.
================================================================================== ================================================================

Events
######
================================================ ===================================================================
:zeek:id:`TrimTraceFile::go`: :zeek:type:`event` This event can be generated externally to this script if on-demand
                                                 tracefile rotation is required with the caveat that the script
                                                 doesn't currently attempt to get back on schedule automatically and
                                                 the next trim likely won't happen on the
                                                 :zeek:id:`TrimTraceFile::trim_interval`.
================================================ ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: TrimTraceFile::trim_interval
   :source-code: policy/misc/trim-trace-file.zeek 8 8

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 mins``

   The interval between times that the output tracefile is rotated.

Events
######
.. zeek:id:: TrimTraceFile::go
   :source-code: policy/misc/trim-trace-file.zeek 18 31

   :Type: :zeek:type:`event` (first_trim: :zeek:type:`bool`)

   This event can be generated externally to this script if on-demand
   tracefile rotation is required with the caveat that the script
   doesn't currently attempt to get back on schedule automatically and
   the next trim likely won't happen on the
   :zeek:id:`TrimTraceFile::trim_interval`.


