:tocdepth: 3

policy/misc/detect-traceroute/main.zeek
=======================================
.. zeek:namespace:: Traceroute

This script detects a large number of ICMP Time Exceeded messages heading
toward hosts that have sent low TTL packets. It generates a notice when the
number of ICMP Time Exceeded messages for a source-destination pair exceeds
a threshold.

:Namespace: Traceroute
:Imports: :doc:`base/frameworks/signatures </scripts/base/frameworks/signatures/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================================================= ===================================================================
:zeek:id:`Traceroute::icmp_time_exceeded_interval`: :zeek:type:`interval` :zeek:attr:`&redef` Interval at which to watch for the
                                                                                              :zeek:id:`Traceroute::icmp_time_exceeded_threshold` variable to be
                                                                                              crossed.
:zeek:id:`Traceroute::icmp_time_exceeded_threshold`: :zeek:type:`double` :zeek:attr:`&redef`  Defines the threshold for ICMP Time Exceeded messages for a src-dst
                                                                                              pair.
:zeek:id:`Traceroute::require_low_ttl_packets`: :zeek:type:`bool` :zeek:attr:`&redef`         By default this script requires that any host detected running
                                                                                              traceroutes first send low TTL packets (TTL < 10) to the traceroute
                                                                                              destination host.
============================================================================================= ===================================================================

Types
#####
================================================== ======================================
:zeek:type:`Traceroute::Info`: :zeek:type:`record` The log record for the traceroute log.
================================================== ======================================

Redefinitions
#############
============================================================================ =====================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                                      
                                                                             
                                                                             * :zeek:enum:`Traceroute::LOG`
:zeek:type:`Notice::Type`: :zeek:type:`enum`                                 
                                                                             
                                                                             * :zeek:enum:`Traceroute::Detected`:
                                                                               Indicates that a host was seen running traceroutes.
:zeek:id:`Signatures::ignored_ids`: :zeek:type:`pattern` :zeek:attr:`&redef` 
============================================================================ =====================================================

Events
######
========================================================= =
:zeek:id:`Traceroute::log_traceroute`: :zeek:type:`event` 
========================================================= =

Hooks
#####
=============================================================== =
:zeek:id:`Traceroute::log_policy`: :zeek:type:`Log::PolicyHook` 
=============================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Traceroute::icmp_time_exceeded_interval
   :source-code: policy/misc/detect-traceroute/main.zeek 41 41

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``3.0 mins``

   Interval at which to watch for the
   :zeek:id:`Traceroute::icmp_time_exceeded_threshold` variable to be
   crossed.  At the end of each interval the counter is reset.

.. zeek:id:: Traceroute::icmp_time_exceeded_threshold
   :source-code: policy/misc/detect-traceroute/main.zeek 36 36

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``3.0``

   Defines the threshold for ICMP Time Exceeded messages for a src-dst
   pair.  This threshold only comes into play after a host is found to
   be sending low TTL packets.

.. zeek:id:: Traceroute::require_low_ttl_packets
   :source-code: policy/misc/detect-traceroute/main.zeek 31 31

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   By default this script requires that any host detected running
   traceroutes first send low TTL packets (TTL < 10) to the traceroute
   destination host.  Changing this setting to F will relax the
   detection a bit by solely relying on ICMP time-exceeded messages to
   detect traceroute.

Types
#####
.. zeek:type:: Traceroute::Info
   :source-code: policy/misc/detect-traceroute/main.zeek 44 53

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp

      src: :zeek:type:`addr` :zeek:attr:`&log`
         Address initiating the traceroute.

      dst: :zeek:type:`addr` :zeek:attr:`&log`
         Destination address of the traceroute.

      proto: :zeek:type:`string` :zeek:attr:`&log`
         Protocol used for the traceroute.

   The log record for the traceroute log.

Events
######
.. zeek:id:: Traceroute::log_traceroute
   :source-code: policy/misc/detect-traceroute/main.zeek 55 55

   :Type: :zeek:type:`event` (rec: :zeek:type:`Traceroute::Info`)


Hooks
#####
.. zeek:id:: Traceroute::log_policy
   :source-code: policy/misc/detect-traceroute/main.zeek 17 17

   :Type: :zeek:type:`Log::PolicyHook`



