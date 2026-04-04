:tocdepth: 3

policy/frameworks/analyzer/packet-segment-logging.zeek
======================================================
.. zeek:namespace:: Analyzer::Logging

This script enables logging of packet segment data when a protocol
parsing violation is encountered.  The amount of data from the
packet logged is set by the :zeek:see:`Analyzer::Logging::packet_segment_size` variable.
A caveat to logging packet data is that in some cases, the packet may
not be the packet that actually caused the protocol violation.

:Namespace: Analyzer::Logging

Summary
~~~~~~~
Runtime Options
###############
======================================================================================= =====================================================
:zeek:id:`Analyzer::Logging::packet_segment_size`: :zeek:type:`int` :zeek:attr:`&redef` Size of the packet segment to display in the DPD log.
======================================================================================= =====================================================

Redefinitions
#############
========================================================= ==============================================================================
:zeek:type:`Analyzer::Logging::Info`: :zeek:type:`record`

                                                          :New Fields: :zeek:type:`Analyzer::Logging::Info`

                                                            packet_segment: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                              A chunk of the payload that most likely resulted in the
                                                              analyzer violation.
:zeek:type:`connection`: :zeek:type:`record`

                                                          :New Fields: :zeek:type:`connection`

                                                            packet_segment: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                              A chunk of the payload that most likely resulted in a
                                                              analyzer violation.
========================================================= ==============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Analyzer::Logging::packet_segment_size
   :source-code: policy/frameworks/analyzer/packet-segment-logging.zeek 23 23

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``255``

   Size of the packet segment to display in the DPD log.


