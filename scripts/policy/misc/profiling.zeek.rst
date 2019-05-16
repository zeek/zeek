:tocdepth: 3

policy/misc/profiling.zeek
==========================
.. zeek:namespace:: Profiling

Turns on profiling of Zeek resource consumption.

:Namespace: Profiling

Summary
~~~~~~~
Redefinitions
#############
=============================================================================== =================================================
:zeek:id:`expensive_profiling_multiple`: :zeek:type:`count` :zeek:attr:`&redef` Set the expensive profiling interval (multiple of
                                                                                :zeek:id:`profiling_interval`).
:zeek:id:`profiling_file`: :zeek:type:`file` :zeek:attr:`&redef`                Set the profiling output file.
:zeek:id:`profiling_interval`: :zeek:type:`interval` :zeek:attr:`&redef`        Set the cheap profiling interval.
=============================================================================== =================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

