:tocdepth: 3

base/frameworks/sumstats/plugins/max.zeek
=========================================
.. zeek:namespace:: SumStats

Find the maximum value.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats/main.zeek </scripts/base/frameworks/sumstats/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== ====================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::MAX`:
                                                        Find the maximum value.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        max: :zeek:type:`double` :zeek:attr:`&optional`
                                                          For numeric data, this tracks the maximum value.
===================================================== ====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

