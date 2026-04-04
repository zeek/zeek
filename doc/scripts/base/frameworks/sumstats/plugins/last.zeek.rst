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
===================================================== ============================================================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum`

                                                      * :zeek:enum:`SumStats::LAST`:
                                                        Keep last X observations in a queue.
:zeek:type:`SumStats::Reducer`: :zeek:type:`record`

                                                      :New Fields: :zeek:type:`SumStats::Reducer`

                                                        num_last_elements: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                          Number of elements to keep.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record`

                                                      :New Fields: :zeek:type:`SumStats::ResultVal`

                                                        last_elements: :zeek:type:`Queue::Queue` :zeek:attr:`&optional`
                                                          This is the queue where elements are maintained.
===================================================== ============================================================================================

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
   :source-code: base/frameworks/sumstats/plugins/last.zeek 31 48

   :Type: :zeek:type:`function` (rv: :zeek:type:`SumStats::ResultVal`) : :zeek:type:`vector` of :zeek:type:`SumStats::Observation`

   Get a vector of element values from a ResultVal.


