:tocdepth: 3

policy/protocols/dns/auth-addl.zeek
===================================
.. zeek:namespace:: DNS

This script adds authoritative and additional responses for the current
query to the DNS log.  It can cause severe overhead due to the need
for all authoritative and additional responses to have events generated.
This script is not recommended for use on heavily loaded links.

:Namespace: DNS
:Imports: :doc:`base/protocols/dns/main.zeek </scripts/base/protocols/dns/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=================================================================== =
:zeek:type:`DNS::Info`: :zeek:type:`record`                         
:zeek:id:`dns_skip_all_addl`: :zeek:type:`bool` :zeek:attr:`&redef` 
:zeek:id:`dns_skip_all_auth`: :zeek:type:`bool` :zeek:attr:`&redef` 
=================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

