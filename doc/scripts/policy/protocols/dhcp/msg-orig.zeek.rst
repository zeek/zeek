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
============================================ ============================================================================================================================
:zeek:type:`DHCP::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`DHCP::Info`
                                             
                                               msg_orig: :zeek:type:`vector` of :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
                                                 The address that originated each message from the
                                                 `msg_types` field.
============================================ ============================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

