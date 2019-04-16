:tocdepth: 3

base/frameworks/sumstats/plugins/last.zeek
==========================================
.. bro:namespace:: SumStats

Keep the last X observations.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/utils/queue.zeek </scripts/base/utils/queue.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=================================================== =
:bro:type:`SumStats::Calculation`: :bro:type:`enum` 
:bro:type:`SumStats::Reducer`: :bro:type:`record`   
:bro:type:`SumStats::ResultVal`: :bro:type:`record` 
=================================================== =

Functions
#########
================================================== ================================================
:bro:id:`SumStats::get_last`: :bro:type:`function` Get a vector of element values from a ResultVal.
================================================== ================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: SumStats::get_last

   :Type: :bro:type:`function` (rv: :bro:type:`SumStats::ResultVal`) : :bro:type:`vector` of :bro:type:`SumStats::Observation`

   Get a vector of element values from a ResultVal.


