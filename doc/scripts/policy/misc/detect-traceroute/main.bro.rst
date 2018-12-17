:tocdepth: 3

policy/misc/detect-traceroute/main.bro
======================================
.. bro:namespace:: Traceroute

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
========================================================================================== ===================================================================
:bro:id:`Traceroute::icmp_time_exceeded_interval`: :bro:type:`interval` :bro:attr:`&redef` Interval at which to watch for the
                                                                                           :bro:id:`Traceroute::icmp_time_exceeded_threshold` variable to be
                                                                                           crossed.
:bro:id:`Traceroute::icmp_time_exceeded_threshold`: :bro:type:`double` :bro:attr:`&redef`  Defines the threshold for ICMP Time Exceeded messages for a src-dst
                                                                                           pair.
:bro:id:`Traceroute::require_low_ttl_packets`: :bro:type:`bool` :bro:attr:`&redef`         By default this script requires that any host detected running
                                                                                           traceroutes first send low TTL packets (TTL < 10) to the traceroute
                                                                                           destination host.
========================================================================================== ===================================================================

Types
#####
================================================ ======================================
:bro:type:`Traceroute::Info`: :bro:type:`record` The log record for the traceroute log.
================================================ ======================================

Redefinitions
#############
========================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                                     
:bro:type:`Notice::Type`: :bro:type:`enum`                                
:bro:id:`Signatures::ignored_ids`: :bro:type:`pattern` :bro:attr:`&redef` 
========================================================================= =

Events
######
======================================================= =
:bro:id:`Traceroute::log_traceroute`: :bro:type:`event` 
======================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Traceroute::icmp_time_exceeded_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``3.0 mins``

   Interval at which to watch for the
   :bro:id:`Traceroute::icmp_time_exceeded_threshold` variable to be
   crossed.  At the end of each interval the counter is reset.

.. bro:id:: Traceroute::icmp_time_exceeded_threshold

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``3.0``

   Defines the threshold for ICMP Time Exceeded messages for a src-dst
   pair.  This threshold only comes into play after a host is found to
   be sending low TTL packets.

.. bro:id:: Traceroute::require_low_ttl_packets

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   By default this script requires that any host detected running
   traceroutes first send low TTL packets (TTL < 10) to the traceroute
   destination host.  Changing this setting to F will relax the
   detection a bit by solely relying on ICMP time-exceeded messages to
   detect traceroute.

Types
#####
.. bro:type:: Traceroute::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp

      src: :bro:type:`addr` :bro:attr:`&log`
         Address initiating the traceroute.

      dst: :bro:type:`addr` :bro:attr:`&log`
         Destination address of the traceroute.

      proto: :bro:type:`string` :bro:attr:`&log`
         Protocol used for the traceroute.

   The log record for the traceroute log.

Events
######
.. bro:id:: Traceroute::log_traceroute

   :Type: :bro:type:`event` (rec: :bro:type:`Traceroute::Info`)



