:tocdepth: 3

base/frameworks/sumstats/plugins/average.zeek
=============================================
.. zeek:namespace:: SumStats

Calculate the average.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats/main.zeek </scripts/base/frameworks/sumstats/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== ========================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::AVERAGE`:
                                                        Calculate the average of the values.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        average: :zeek:type:`double` :zeek:attr:`&optional`
                                                          For numeric data, this is the average of all values.
===================================================== ========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

