:tocdepth: 3

policy/protocols/conn/disable-unknown-ip-proto-support.zeek
===========================================================

This script filters the ip_proto field out of the conn.log and disables
logging of connections with unknown IP protocols.

:Imports: :doc:`base/frameworks/analyzer/main.zeek </scripts/base/frameworks/analyzer/main.zeek>`, :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =
:zeek:type:`Conn::Info`: :zeek:type:`record` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~

