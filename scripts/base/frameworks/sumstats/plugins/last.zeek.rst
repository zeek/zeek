:tocdepth: 3

base/frameworks/sumstats/plugins/last.zeek
==========================================
.. zeek:namespace:: SumStats

Keep the last X observations.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/utils/queue.zeek </scripts/base/utils/queue.zeek>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== =
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
:zeek:type:`SumStats::Reducer`: :zeek:type:`record`   
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
===================================================== =

Functions
#########
==================================================== ================================================
:zeek:id:`SumStats::get_last`: :zeek:type:`function` Get a vector of element values from a ResultVal.
==================================================== ================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: SumStats::get_last

   :Type: :zeek:type:`function` (rv: :zeek:type:`SumStats::ResultVal`) : :zeek:type:`vector` of :zeek:type:`SumStats::Observation`

   Get a vector of element values from a ResultVal.


