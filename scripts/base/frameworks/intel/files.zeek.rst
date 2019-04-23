:tocdepth: 3

base/frameworks/intel/files.zeek
================================
.. zeek:namespace:: Intel

File analysis framework integration for the intelligence framework. This
script manages file information in intelligence framework data structures.

:Namespace: Intel
:Imports: :doc:`base/frameworks/intel/main.zeek </scripts/base/frameworks/intel/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================= =============================================================
:zeek:type:`Intel::Info`: :zeek:type:`record` Record used for the logging framework representing a positive
                                              hit within the intelligence framework.
:zeek:type:`Intel::Seen`: :zeek:type:`record` Information about a piece of "seen" data.
:zeek:type:`Intel::Type`: :zeek:type:`enum`   Enum type to represent various types of intelligence data.
============================================= =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

