:tocdepth: 3

base/frameworks/sumstats/plugins/unique.zeek
============================================
.. zeek:namespace:: SumStats

Calculate the number of unique values.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats/main.zeek </scripts/base/frameworks/sumstats/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== ===========================================================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::UNIQUE`:
                                                        Calculate the number of unique values.
:zeek:type:`SumStats::Reducer`: :zeek:type:`record`   
                                                      
                                                      :New Fields: :zeek:type:`SumStats::Reducer`
                                                      
                                                        unique_max: :zeek:type:`count` :zeek:attr:`&optional`
                                                          Maximum number of unique values to store.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        unique: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                          If cardinality is being tracked, the number of unique
                                                          values is tracked here.
                                                      
                                                        unique_max: :zeek:type:`count` :zeek:attr:`&optional`
                                                      
                                                        unique_vals: :zeek:type:`set` [:zeek:type:`SumStats::Observation`] :zeek:attr:`&optional`
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        unique: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                          If cardinality is being tracked, the number of unique
                                                          values is tracked here.
                                                      
                                                        unique_max: :zeek:type:`count` :zeek:attr:`&optional`
                                                      
                                                        unique_vals: :zeek:type:`set` [:zeek:type:`SumStats::Observation`] :zeek:attr:`&optional`
===================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

