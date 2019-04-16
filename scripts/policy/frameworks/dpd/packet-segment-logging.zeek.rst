:tocdepth: 3

policy/frameworks/dpd/packet-segment-logging.zeek
=================================================
.. bro:namespace:: DPD

This script enables logging of packet segment data when a protocol
parsing violation is encountered.  The amount of data from the
packet logged is set by the :bro:see:`DPD::packet_segment_size` variable.
A caveat to logging packet data is that in some cases, the packet may
not be the packet that actually caused the protocol violation.

:Namespace: DPD
:Imports: :doc:`base/frameworks/dpd </scripts/base/frameworks/dpd/index>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================== =====================================================
:bro:id:`DPD::packet_segment_size`: :bro:type:`int` :bro:attr:`&redef` Size of the packet segment to display in the DPD log.
====================================================================== =====================================================

Redefinitions
#############
========================================= =
:bro:type:`DPD::Info`: :bro:type:`record` 
========================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: DPD::packet_segment_size

   :Type: :bro:type:`int`
   :Attributes: :bro:attr:`&redef`
   :Default: ``255``

   Size of the packet segment to display in the DPD log.


