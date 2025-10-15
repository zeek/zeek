:tocdepth: 3

base/frameworks/sumstats/plugins/hll_unique.zeek
================================================
.. zeek:namespace:: SumStats

Calculate the number of unique values (using the HyperLogLog algorithm).

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== ===============================================================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::HLL_UNIQUE`:
                                                        Calculate the number of unique values.
:zeek:type:`SumStats::Reducer`: :zeek:type:`record`   
                                                      
                                                      :New Fields: :zeek:type:`SumStats::Reducer`
                                                      
                                                        hll_error_margin: :zeek:type:`double` :zeek:attr:`&default` = ``0.01`` :zeek:attr:`&optional`
                                                          The error margin for HLL.
                                                      
                                                        hll_confidence: :zeek:type:`double` :zeek:attr:`&default` = ``0.95`` :zeek:attr:`&optional`
                                                          The confidence for HLL.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        hll_unique: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                          If cardinality is being tracked, the number of unique
                                                          items is tracked here.
                                                      
                                                        card: :zeek:type:`opaque` of cardinality :zeek:attr:`&optional`
                                                      
                                                        hll_error_margin: :zeek:type:`double` :zeek:attr:`&optional`
                                                      
                                                        hll_confidence: :zeek:type:`double` :zeek:attr:`&optional`
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        hll_unique: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                          If cardinality is being tracked, the number of unique
                                                          items is tracked here.
                                                      
                                                        card: :zeek:type:`opaque` of cardinality :zeek:attr:`&optional`
                                                      
                                                        hll_error_margin: :zeek:type:`double` :zeek:attr:`&optional`
                                                      
                                                        hll_confidence: :zeek:type:`double` :zeek:attr:`&optional`
===================================================== ===============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

