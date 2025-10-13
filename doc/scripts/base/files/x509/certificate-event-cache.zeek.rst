:tocdepth: 3

base/files/x509/certificate-event-cache.zeek
============================================
.. zeek:namespace:: X509

This script sets up the certificate event cache handling of Zeek.

The Zeek core provided a method to skip certificate processing for known certificates.
For more details about this functionality, see :zeek:see:`x509_set_certificate_cache`.

This script uses this feature to lower the amount of processing that has to be performed
by Zeek by caching all certificate events for common certificates. For these certificates,
the parsing of certificate information in the core is disabled. Instead, the cached events
and data structures from the previous certificates are used.

:Namespace: X509
:Imports: :doc:`base/files/x509/main.zeek </scripts/base/files/x509/main.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================================= =====================================================================
:zeek:id:`X509::caching_required_encounters`: :zeek:type:`count` :zeek:attr:`&redef`                    How often do you have to encounter a certificate before
                                                                                                        caching the events for it.
:zeek:id:`X509::caching_required_encounters_interval`: :zeek:type:`interval` :zeek:attr:`&redef`        The timespan over which caching_required_encounters has to be reached
:zeek:id:`X509::certificate_cache_max_entries`: :zeek:type:`count` :zeek:attr:`&redef`                  Maximum size of the certificate event cache
:zeek:id:`X509::certificate_cache_minimum_eviction_interval`: :zeek:type:`interval` :zeek:attr:`&redef` After a certificate has not been encountered for this time, it
                                                                                                        may be evicted from the certificate event cache.
======================================================================================================= =====================================================================

Hooks
#####
================================================================= ===================================================================
:zeek:id:`X509::x509_certificate_cache_replay`: :zeek:type:`hook` This hook performs event-replays in case a certificate that already
                                                                  is in the cache is encountered.
================================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: X509::caching_required_encounters
   :source-code: base/files/x509/certificate-event-cache.zeek 18 18

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   How often do you have to encounter a certificate before
   caching the events for it. Set to 0 to disable caching of certificates.

.. zeek:id:: X509::caching_required_encounters_interval
   :source-code: base/files/x509/certificate-event-cache.zeek 21 21

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min 2.0 secs``

   The timespan over which caching_required_encounters has to be reached

.. zeek:id:: X509::certificate_cache_max_entries
   :source-code: base/files/x509/certificate-event-cache.zeek 28 28

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10000``
   :Redefinition: from :doc:`/scripts/policy/files/x509/disable-certificate-events-known-certs.zeek`

      ``=``::

         100000


   Maximum size of the certificate event cache

.. zeek:id:: X509::certificate_cache_minimum_eviction_interval
   :source-code: base/files/x509/certificate-event-cache.zeek 25 25

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min 2.0 secs``

   After a certificate has not been encountered for this time, it
   may be evicted from the certificate event cache.

Hooks
#####
.. zeek:id:: X509::x509_certificate_cache_replay
   :source-code: base/files/x509/certificate-event-cache.zeek 35 35

   :Type: :zeek:type:`hook` (f: :zeek:type:`fa_file`, e: :zeek:type:`X509::Info`, sha256: :zeek:type:`string`) : :zeek:type:`bool`

   This hook performs event-replays in case a certificate that already
   is in the cache is encountered.
   
   It is possible to change this behavior/skip sending the events by
   installing a higher priority hook instead.


