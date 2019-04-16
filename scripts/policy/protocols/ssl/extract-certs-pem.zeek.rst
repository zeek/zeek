:tocdepth: 3

policy/protocols/ssl/extract-certs-pem.zeek
===========================================
.. bro:namespace:: SSL

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
===================================================================== =========================================================
:bro:id:`SSL::extract_certs_pem`: :bro:type:`Host` :bro:attr:`&redef` Control if host certificates offered by the defined hosts
                                                                      will be written to the PEM certificates file.
===================================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SSL::extract_certs_pem

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``LOCAL_HOSTS``

   Control if host certificates offered by the defined hosts
   will be written to the PEM certificates file.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.


