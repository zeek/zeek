:tocdepth: 3

policy/protocols/dns/auth-addl.bro
==================================
.. bro:namespace:: DNS

This script adds authoritative and additional responses for the current
query to the DNS log.  It can cause severe overhead due to the need
for all authoritative and additional responses to have events generated.
This script is not recommended for use on heavily loaded links.

:Namespace: DNS
:Imports: :doc:`base/protocols/dns/main.bro </scripts/base/protocols/dns/main.bro>`

Summary
~~~~~~~
Redefinitions
#############
================================================================ =
:bro:type:`DNS::Info`: :bro:type:`record`                        
:bro:id:`dns_skip_all_addl`: :bro:type:`bool` :bro:attr:`&redef` 
:bro:id:`dns_skip_all_auth`: :bro:type:`bool` :bro:attr:`&redef` 
================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~

