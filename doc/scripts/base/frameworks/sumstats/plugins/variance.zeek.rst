:tocdepth: 3

base/frameworks/sumstats/plugins/variance.zeek
==============================================
.. zeek:namespace:: SumStats

Calculate the variance.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats/main.zeek </scripts/base/frameworks/sumstats/main.zeek>`, :doc:`base/frameworks/sumstats/plugins/average.zeek </scripts/base/frameworks/sumstats/plugins/average.zeek>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== ===================================================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::VARIANCE`:
                                                        Calculate the variance of the values.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        variance: :zeek:type:`double` :zeek:attr:`&optional`
                                                          For numeric data, this is the variance.
                                                      
                                                        prev_avg: :zeek:type:`double` :zeek:attr:`&optional`
                                                      
                                                        var_s: :zeek:type:`double` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        variance: :zeek:type:`double` :zeek:attr:`&optional`
                                                          For numeric data, this is the variance.
                                                      
                                                        prev_avg: :zeek:type:`double` :zeek:attr:`&optional`
                                                      
                                                        var_s: :zeek:type:`double` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`
===================================================== ===================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

