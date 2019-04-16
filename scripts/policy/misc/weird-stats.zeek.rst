:tocdepth: 3

policy/misc/weird-stats.zeek
============================
.. bro:namespace:: SumStats
.. bro:namespace:: WeirdStats

Log weird statistics.

:Namespaces: SumStats, WeirdStats
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================================== =============================
:bro:id:`WeirdStats::weird_stat_interval`: :bro:type:`interval` :bro:attr:`&redef` How often stats are reported.
================================================================================== =============================

Types
#####
================================================ =
:bro:type:`WeirdStats::Info`: :bro:type:`record` 
================================================ =

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
======================================================== =
:bro:id:`WeirdStats::log_weird_stats`: :bro:type:`event` 
======================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: WeirdStats::weird_stat_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15.0 mins``

   How often stats are reported.

Types
#####
.. bro:type:: WeirdStats::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for the measurement.

      name: :bro:type:`string` :bro:attr:`&log`
         Name of the weird.

      num_seen: :bro:type:`count` :bro:attr:`&log`
         Number of times weird was seen since the last stats interval.


Events
######
.. bro:id:: WeirdStats::log_weird_stats

   :Type: :bro:type:`event` (rec: :bro:type:`WeirdStats::Info`)



