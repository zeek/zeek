:tocdepth: 3

policy/misc/weird-stats.zeek
============================
.. zeek:namespace:: SumStats
.. zeek:namespace:: WeirdStats

Log weird statistics.

:Namespaces: SumStats, WeirdStats
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`

Summary
~~~~~~~
Redefinable Options
###################
===================================================================================== =============================
:zeek:id:`WeirdStats::weird_stat_interval`: :zeek:type:`interval` :zeek:attr:`&redef` How often stats are reported.
===================================================================================== =============================

Types
#####
================================================== =
:zeek:type:`WeirdStats::Info`: :zeek:type:`record` 
================================================== =

Redefinitions
#############
======================================= ==============================
:zeek:type:`Log::ID`: :zeek:type:`enum` 
                                        
                                        * :zeek:enum:`WeirdStats::LOG`
======================================= ==============================

Events
######
========================================================== =
:zeek:id:`WeirdStats::log_weird_stats`: :zeek:type:`event` 
========================================================== =

Hooks
#####
=============================================================== =
:zeek:id:`WeirdStats::log_policy`: :zeek:type:`Log::PolicyHook` 
=============================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: WeirdStats::weird_stat_interval
   :source-code: policy/misc/weird-stats.zeek 14 14

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 mins``

   How often stats are reported.

Types
#####
.. zeek:type:: WeirdStats::Info
   :source-code: policy/misc/weird-stats.zeek 16 23

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for the measurement.

      name: :zeek:type:`string` :zeek:attr:`&log`
         Name of the weird.

      num_seen: :zeek:type:`count` :zeek:attr:`&log`
         Number of times weird was seen since the last stats interval.


Events
######
.. zeek:id:: WeirdStats::log_weird_stats
   :source-code: policy/misc/weird-stats.zeek 25 25

   :Type: :zeek:type:`event` (rec: :zeek:type:`WeirdStats::Info`)


Hooks
#####
.. zeek:id:: WeirdStats::log_policy
   :source-code: policy/misc/weird-stats.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`



