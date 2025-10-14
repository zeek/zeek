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
=================================================================== =======================================================================================
:zeek:type:`DNS::Info`: :zeek:type:`record`                         
                                                                    
                                                                    :New Fields: :zeek:type:`DNS::Info`
                                                                    
                                                                      auth: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                        Authoritative responses for the query.
                                                                    
                                                                      addl: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                        Additional responses for the query.
:zeek:id:`dns_skip_all_addl`: :zeek:type:`bool` :zeek:attr:`&redef` 
:zeek:id:`dns_skip_all_auth`: :zeek:type:`bool` :zeek:attr:`&redef` 
=================================================================== =======================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

