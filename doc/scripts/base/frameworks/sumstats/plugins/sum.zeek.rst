:tocdepth: 3

base/frameworks/sumstats/plugins/sum.zeek
=========================================
.. zeek:namespace:: SumStats

Calculate the sum.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats/main.zeek </scripts/base/frameworks/sumstats/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== =================================================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::SUM`:
                                                        Calculate the sum of the values.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        sum: :zeek:type:`double` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`
                                                          For numeric data, this tracks the sum of all values.
===================================================== =================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

