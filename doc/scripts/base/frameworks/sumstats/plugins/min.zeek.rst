:tocdepth: 3

base/frameworks/sumstats/plugins/min.zeek
=========================================
.. zeek:namespace:: SumStats

Find the minimum value.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats/main.zeek </scripts/base/frameworks/sumstats/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== ====================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::MIN`:
                                                        Find the minimum value.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        min: :zeek:type:`double` :zeek:attr:`&optional`
                                                          For numeric data, this tracks the minimum value.
===================================================== ====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

