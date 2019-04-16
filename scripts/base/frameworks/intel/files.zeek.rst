:tocdepth: 3

base/frameworks/intel/files.zeek
================================
.. bro:namespace:: Intel

File analysis framework integration for the intelligence framework. This
script manages file information in intelligence framework data structures.

:Namespace: Intel
:Imports: :doc:`base/frameworks/intel/main.zeek </scripts/base/frameworks/intel/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== =============================================================
:bro:type:`Intel::Info`: :bro:type:`record` Record used for the logging framework representing a positive
                                            hit within the intelligence framework.
:bro:type:`Intel::Seen`: :bro:type:`record` Information about a piece of "seen" data.
:bro:type:`Intel::Type`: :bro:type:`enum`   Enum type to represent various types of intelligence data.
=========================================== =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

