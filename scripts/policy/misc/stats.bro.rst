:tocdepth: 3

policy/misc/stats.bro
=====================
.. bro:namespace:: Stats

Log memory/packet/lag statistics.

:Namespace: Stats
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================= =============================
:bro:id:`Stats::report_interval`: :bro:type:`interval` :bro:attr:`&redef` How often stats are reported.
========================================================================= =============================

Types
#####
=========================================== =
:bro:type:`Stats::Info`: :bro:type:`record` 
=========================================== =

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
============================================= ===============================================================
:bro:id:`Stats::log_stats`: :bro:type:`event` Event to catch stats as they are written to the logging stream.
============================================= ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Stats::report_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 mins``

   How often stats are reported.

Types
#####
.. bro:type:: Stats::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for the measurement.

      peer: :bro:type:`string` :bro:attr:`&log`
         Peer that generated this log.  Mostly for clusters.

      mem: :bro:type:`count` :bro:attr:`&log`
         Amount of memory currently in use in MB.

      pkts_proc: :bro:type:`count` :bro:attr:`&log`
         Number of packets processed since the last stats interval.

      bytes_recv: :bro:type:`count` :bro:attr:`&log`
         Number of bytes received since the last stats interval if
         reading live traffic.

      pkts_dropped: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Number of packets dropped since the last stats interval if
         reading live traffic.

      pkts_link: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Number of packets seen on the link since the last stats
         interval if reading live traffic.

      pkt_lag: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         Lag between the wall clock and packet timestamps if reading
         live traffic.

      events_proc: :bro:type:`count` :bro:attr:`&log`
         Number of events processed since the last stats interval.

      events_queued: :bro:type:`count` :bro:attr:`&log`
         Number of events that have been queued since the last stats
         interval.

      active_tcp_conns: :bro:type:`count` :bro:attr:`&log`
         TCP connections currently in memory.

      active_udp_conns: :bro:type:`count` :bro:attr:`&log`
         UDP connections currently in memory.

      active_icmp_conns: :bro:type:`count` :bro:attr:`&log`
         ICMP connections currently in memory.

      tcp_conns: :bro:type:`count` :bro:attr:`&log`
         TCP connections seen since last stats interval.

      udp_conns: :bro:type:`count` :bro:attr:`&log`
         UDP connections seen since last stats interval.

      icmp_conns: :bro:type:`count` :bro:attr:`&log`
         ICMP connections seen since last stats interval.

      timers: :bro:type:`count` :bro:attr:`&log`
         Number of timers scheduled since last stats interval.

      active_timers: :bro:type:`count` :bro:attr:`&log`
         Current number of scheduled timers.

      files: :bro:type:`count` :bro:attr:`&log`
         Number of files seen since last stats interval.

      active_files: :bro:type:`count` :bro:attr:`&log`
         Current number of files actively being seen.

      dns_requests: :bro:type:`count` :bro:attr:`&log`
         Number of DNS requests seen since last stats interval.

      active_dns_requests: :bro:type:`count` :bro:attr:`&log`
         Current number of DNS requests awaiting a reply.

      reassem_tcp_size: :bro:type:`count` :bro:attr:`&log`
         Current size of TCP data in reassembly.

      reassem_file_size: :bro:type:`count` :bro:attr:`&log`
         Current size of File data in reassembly.

      reassem_frag_size: :bro:type:`count` :bro:attr:`&log`
         Current size of packet fragment data in reassembly.

      reassem_unknown_size: :bro:type:`count` :bro:attr:`&log`
         Current size of unknown data in reassembly (this is only PIA buffer right now).


Events
######
.. bro:id:: Stats::log_stats

   :Type: :bro:type:`event` (rec: :bro:type:`Stats::Info`)

   Event to catch stats as they are written to the logging stream.


