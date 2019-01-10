:tocdepth: 3

base/misc/find-filtered-trace.bro
=================================
.. bro:namespace:: FilteredTraceDetection

Discovers trace files that contain TCP traffic consisting only of
control packets (e.g. it's been filtered to contain only SYN/FIN/RST
packets and no content).  On finding such a trace, a warning is
emitted that suggests toggling the :bro:see:`detect_filtered_trace`
option may be desired if the user does not want Bro to report
missing TCP segments.

:Namespace: FilteredTraceDetection

Summary
~~~~~~~
State Variables
###############
============================================================================= =================================================================
:bro:id:`FilteredTraceDetection::enable`: :bro:type:`bool` :bro:attr:`&redef` Flag to enable filtered trace file detection and warning message.
============================================================================= =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. bro:id:: FilteredTraceDetection::enable

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Flag to enable filtered trace file detection and warning message.


