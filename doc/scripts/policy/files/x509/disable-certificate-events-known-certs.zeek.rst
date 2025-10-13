:tocdepth: 3

policy/files/x509/disable-certificate-events-known-certs.zeek
=============================================================
.. zeek:namespace:: DisableX509Events

This script disables repeat certificate events for hosts for hosts for which the same
certificate was seen in the recent past;

This script specifically plugs into the event caching mechanism that is set up by the
base X509 script certificate-event-cache.zeek. It adds another layer of tracking that
checks if the same certificate was seen for the server IP address before, when the same
SNI was used to connect. If the certificate is in the event cache and all of these conditions
apply, then no certificate related events will be raised.

Please note that while this optimization can lead to a considerable reduction of load in some
settings, it also means that certain detection scripts that rely on the certificate events being
raised do no longer work - since the events will not be raised for all connections.

Currently this script only works for X509 certificates that are sent via SSL/TLS connections.

If you use any script that requires certificate events for each single connection,
you should not load this script.

:Namespace: DisableX509Events
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinitions
#############
====================================================================================== ==================================================================================================
:zeek:type:`SSL::Info`: :zeek:type:`record`                                            
                                                                                       
                                                                                       :New Fields: :zeek:type:`SSL::Info`
                                                                                       
                                                                                         always_raise_x509_events: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                                                           Set to true to force certificate events to always be raised for this connection.
:zeek:type:`X509::Info`: :zeek:type:`record`                                           
                                                                                       
                                                                                       :New Fields: :zeek:type:`X509::Info`
                                                                                       
                                                                                         always_raise_x509_events: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                                                           Set to true to force certificate events to always be raised for this certificate.
:zeek:id:`X509::certificate_cache_max_entries`: :zeek:type:`count` :zeek:attr:`&redef` Let's be a bit more generous with the number of certificates that we allow to be put into
                                                                                       the cache.
====================================================================================== ==================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

