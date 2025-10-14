:tocdepth: 3

policy/protocols/ssl/log-certs-base64.zeek
==========================================

This script is used to extract certificates seen on the wire to Zeek log files.
The certificates are base64-encoded and written to ssl.log, to the newly added cert
field.

:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ ====================================================================
:zeek:type:`X509::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`X509::Info`
                                             
                                               cert: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 Base64 encoded X.509 certificate.
============================================ ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

