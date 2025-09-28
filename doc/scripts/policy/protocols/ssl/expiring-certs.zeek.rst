:tocdepth: 3

policy/protocols/ssl/expiring-certs.zeek
========================================
.. zeek:namespace:: SSL

Generate notices when X.509 certificates over SSL/TLS are expired or
going to expire soon based on the date and time values stored within the
certificate.

:Namespace: SSL
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================= ======================================================================
:zeek:id:`SSL::notify_certs_expiration`: :zeek:type:`Host` :zeek:attr:`&redef`          The category of hosts you would like to be notified about which have
                                                                                        certificates that are going to be expiring soon.
:zeek:id:`SSL::notify_when_cert_expiring_in`: :zeek:type:`interval` :zeek:attr:`&redef` The time before a certificate is going to expire that you would like
                                                                                        to start receiving :zeek:enum:`SSL::Certificate_Expires_Soon` notices.
======================================================================================= ======================================================================

Redefinitions
#############
============================================ ==============================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`SSL::Certificate_Expired`:
                                               Indicates that a certificate's NotValidAfter date has lapsed
                                               and the certificate is now invalid.
                                             
                                             * :zeek:enum:`SSL::Certificate_Expires_Soon`:
                                               Indicates that a certificate is going to expire within
                                               :zeek:id:`SSL::notify_when_cert_expiring_in`.
                                             
                                             * :zeek:enum:`SSL::Certificate_Not_Valid_Yet`:
                                               Indicates that a certificate's NotValidBefore date is future
                                               dated.
============================================ ==============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SSL::notify_certs_expiration
   :source-code: policy/protocols/ssl/expiring-certs.zeek 30 30

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``

   The category of hosts you would like to be notified about which have
   certificates that are going to be expiring soon.  By default, these
   notices will be suppressed by the notice framework for 1 day after
   a particular certificate has had a notice generated.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS

.. zeek:id:: SSL::notify_when_cert_expiring_in
   :source-code: policy/protocols/ssl/expiring-certs.zeek 34 34

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30.0 days``

   The time before a certificate is going to expire that you would like
   to start receiving :zeek:enum:`SSL::Certificate_Expires_Soon` notices.


