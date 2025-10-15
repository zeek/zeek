:tocdepth: 3

policy/protocols/ssl/certificate-request-info.zeek
==================================================
.. zeek:namespace:: SSL

When the server requests a client certificate, it optionally may specify a list of CAs that
it accepts. If the server does this, this script adds this list to ssl.log.

:Namespace: SSL
:Imports: :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== ===============================================================================================================================
:zeek:type:`SSL::Info`: :zeek:type:`record` 
                                            
                                            :New Fields: :zeek:type:`SSL::Info`
                                            
                                              requested_client_certificate_authorities: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                List of cient certificate CAs accepted by the server
=========================================== ===============================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

