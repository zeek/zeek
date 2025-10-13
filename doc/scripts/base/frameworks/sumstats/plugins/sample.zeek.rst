:tocdepth: 3

base/frameworks/sumstats/plugins/sample.zeek
============================================
.. zeek:namespace:: SumStats

Keep a random sample of values.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats/main.zeek </scripts/base/frameworks/sumstats/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== ==========================================================================================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::SAMPLE`:
                                                        Get uniquely distributed random samples from the observation
                                                        stream.
:zeek:type:`SumStats::Reducer`: :zeek:type:`record`   
                                                      
                                                      :New Fields: :zeek:type:`SumStats::Reducer`
                                                      
                                                        num_samples: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                          The number of sample Observations to collect.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        samples: :zeek:type:`vector` of :zeek:type:`SumStats::Observation` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
                                                          This is the vector in which the samples are maintained.
                                                      
                                                        sample_elements: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                          Number of total observed elements.
                                                      
                                                        num_samples: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        samples: :zeek:type:`vector` of :zeek:type:`SumStats::Observation` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
                                                          This is the vector in which the samples are maintained.
                                                      
                                                        sample_elements: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                          Number of total observed elements.
                                                      
                                                        num_samples: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
===================================================== ==========================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

