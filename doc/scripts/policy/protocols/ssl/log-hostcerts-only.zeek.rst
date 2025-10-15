:tocdepth: 3

policy/protocols/ssl/log-hostcerts-only.zeek
============================================
.. zeek:namespace:: X509

When this script is loaded, only the host certificates (client and server)
will be logged to x509.log. Logging of all other certificates will be suppressed.

:Namespace: X509
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

