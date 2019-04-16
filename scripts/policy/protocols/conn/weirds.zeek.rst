:tocdepth: 3

policy/protocols/conn/weirds.zeek
=================================
.. bro:namespace:: Conn

This script handles core generated connection related "weird" events to 
push weird information about connections into the weird framework.
For live operational deployments, this can frequently cause load issues
due to large numbers of these events and quite possibly shouldn't be
loaded.

:Namespace: Conn
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

