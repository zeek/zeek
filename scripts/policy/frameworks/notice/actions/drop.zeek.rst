:tocdepth: 3

policy/frameworks/notice/actions/drop.zeek
==========================================
.. zeek:namespace:: Notice

This script extends the built in notice code to implement the IP address
dropping functionality.

:Namespace: Notice
:Imports: :doc:`base/frameworks/netcontrol </scripts/base/frameworks/netcontrol/index>`, :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`, :doc:`policy/frameworks/netcontrol/catch-and-release.zeek </scripts/policy/frameworks/netcontrol/catch-and-release.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================== =
:zeek:type:`Notice::Action`: :zeek:type:`enum` 
:zeek:type:`Notice::Info`: :zeek:type:`record` 
============================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

