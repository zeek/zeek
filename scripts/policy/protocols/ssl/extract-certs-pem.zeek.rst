:tocdepth: 3

policy/protocols/ssl/extract-certs-pem.zeek
===========================================
.. zeek:namespace:: SSL

This script is used to extract host certificates seen on the wire to disk
after being converted to PEM files.  The certificates will be stored in
a single file, one for local certificates and one for remote certificates.

.. note::

    - It doesn't work well on a cluster because each worker will write its
      own certificate files and no duplicate checking is done across the
      cluster so each node would log each certificate.


:Namespace: SSL
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================== =========================================================
:zeek:id:`SSL::extract_certs_pem`: :zeek:type:`Host` :zeek:attr:`&redef` Control if host certificates offered by the defined hosts
                                                                         will be written to the PEM certificates file.
======================================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SSL::extract_certs_pem

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``

   Control if host certificates offered by the defined hosts
   will be written to the PEM certificates file.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.


