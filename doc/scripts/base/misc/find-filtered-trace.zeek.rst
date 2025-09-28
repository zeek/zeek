:tocdepth: 3

base/misc/find-filtered-trace.zeek
==================================
.. zeek:namespace:: FilteredTraceDetection

Discovers trace files that contain TCP traffic consisting only of
control packets (e.g. it's been filtered to contain only SYN/FIN/RST
packets and no content).  On finding such a trace, a warning is
emitted that suggests toggling the :zeek:see:`detect_filtered_trace`
option may be desired if the user does not want Zeek to report
missing TCP segments.

:Namespace: FilteredTraceDetection

Summary
~~~~~~~
State Variables
###############
================================================================================ =================================================================
:zeek:id:`FilteredTraceDetection::enable`: :zeek:type:`bool` :zeek:attr:`&redef` Flag to enable filtered trace file detection and warning message.
================================================================================ =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: FilteredTraceDetection::enable
   :source-code: base/misc/find-filtered-trace.zeek 13 13

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Flag to enable filtered trace file detection and warning message.


