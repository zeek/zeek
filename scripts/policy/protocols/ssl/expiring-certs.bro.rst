:tocdepth: 3

policy/protocols/ssl/expiring-certs.bro
=======================================
.. bro:namespace:: SSL

Generate notices when X.509 certificates over SSL/TLS are expired or 
going to expire soon based on the date and time values stored within the
certificate.

:Namespace: SSL
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`base/utils/directions-and-hosts.bro </scripts/base/utils/directions-and-hosts.bro>`

Summary
~~~~~~~
Runtime Options
###############
==================================================================================== =====================================================================
:bro:id:`SSL::notify_certs_expiration`: :bro:type:`Host` :bro:attr:`&redef`          The category of hosts you would like to be notified about which have 
                                                                                     certificates that are going to be expiring soon.
:bro:id:`SSL::notify_when_cert_expiring_in`: :bro:type:`interval` :bro:attr:`&redef` The time before a certificate is going to expire that you would like
                                                                                     to start receiving :bro:enum:`SSL::Certificate_Expires_Soon` notices.
==================================================================================== =====================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SSL::notify_certs_expiration

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``LOCAL_HOSTS``

   The category of hosts you would like to be notified about which have 
   certificates that are going to be expiring soon.  By default, these 
   notices will be suppressed by the notice framework for 1 day after 
   a particular certificate has had a notice generated.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS

.. bro:id:: SSL::notify_when_cert_expiring_in

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30.0 days``

   The time before a certificate is going to expire that you would like
   to start receiving :bro:enum:`SSL::Certificate_Expires_Soon` notices.


