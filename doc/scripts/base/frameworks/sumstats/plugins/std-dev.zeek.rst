:tocdepth: 3

base/frameworks/sumstats/plugins/std-dev.zeek
=============================================
.. zeek:namespace:: SumStats

Calculate the standard deviation.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats/main.zeek </scripts/base/frameworks/sumstats/main.zeek>`, :doc:`base/frameworks/sumstats/plugins/variance.zeek </scripts/base/frameworks/sumstats/plugins/variance.zeek>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== =====================================================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::STD_DEV`:
                                                        Calculate the standard deviation of the values.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        std_dev: :zeek:type:`double` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`
                                                          For numeric data, this calculates the standard deviation.
===================================================== =====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

