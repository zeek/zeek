:orphan:

Package: base/files/x509
========================

Support for X509 certificates with the file analysis framework.
Also supports parsing OCSP requests and responses.

:doc:`/scripts/base/files/x509/__load__.zeek`


:doc:`/scripts/base/files/x509/main.zeek`


:doc:`/scripts/base/files/x509/certificate-event-cache.zeek`

   This script sets up the certificate event cache handling of Zeek.
   
   The Zeek core provided a method to skip certificate processing for known certificates.
   For more details about this functionality, see :zeek:see:`x509_set_certificate_cache`.
   
   This script uses this feature to lower the amount of processing that has to be performed
   by Zeek by caching all certificate events for common certificates. For these certificates,
   the parsing of certificate information in the core is disabled. Instead, the cached events
   and data structures from the previous certificates are used.

:doc:`/scripts/base/files/x509/log-ocsp.zeek`

   Enable logging of OCSP responses.

