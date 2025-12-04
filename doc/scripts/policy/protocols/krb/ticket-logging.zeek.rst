:tocdepth: 3

policy/protocols/krb/ticket-logging.zeek
========================================
.. zeek:namespace:: KRB

Add Kerberos ticket hashes to the krb.log

:Namespace: KRB
:Imports: :doc:`base/protocols/krb </scripts/base/protocols/krb/index>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== ==================================================================================
:zeek:type:`KRB::Info`: :zeek:type:`record` 
                                            
                                            :New Fields: :zeek:type:`KRB::Info`
                                            
                                              auth_ticket_sha256: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                SHA256 hash of ticket used to authorize request/transaction
                                            
                                              new_ticket_sha256: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                SHA256 hash of ticket returned by the KDC
=========================================== ==================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

