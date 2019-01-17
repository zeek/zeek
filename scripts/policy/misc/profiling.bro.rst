:tocdepth: 3

policy/misc/profiling.bro
=========================
.. bro:namespace:: Profiling

Turns on profiling of Bro resource consumption.

:Namespace: Profiling

Summary
~~~~~~~
Redefinitions
#############
============================================================================ =================================================
:bro:id:`expensive_profiling_multiple`: :bro:type:`count` :bro:attr:`&redef` Set the expensive profiling interval (multiple of
                                                                             :bro:id:`profiling_interval`).
:bro:id:`profiling_file`: :bro:type:`file` :bro:attr:`&redef`                Set the profiling output file.
:bro:id:`profiling_interval`: :bro:type:`interval` :bro:attr:`&redef`        Set the cheap profiling interval.
============================================================================ =================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

