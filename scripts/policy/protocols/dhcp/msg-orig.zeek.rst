:tocdepth: 3

policy/protocols/dhcp/msg-orig.zeek
===================================
.. zeek:namespace:: DHCP

Add a field that logs the order of hosts sending messages
using the same DHCP transaction ID.  This information is
occasionally needed on some networks to fully explain the
DHCP sequence.

:Namespace: DHCP
:Imports: :doc:`base/protocols/dhcp </scripts/base/protocols/dhcp/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =
:zeek:type:`DHCP::Info`: :zeek:type:`record` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~

