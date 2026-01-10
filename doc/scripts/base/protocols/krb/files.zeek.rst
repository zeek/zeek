:tocdepth: 3

base/protocols/krb/files.zeek
=============================
.. zeek:namespace:: KRB


:Namespace: KRB
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/krb/main.zeek </scripts/base/protocols/krb/main.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== ===================================================================================
:zeek:type:`KRB::Info`: :zeek:type:`record`

                                            :New Fields: :zeek:type:`KRB::Info`

                                              client_cert: :zeek:type:`Files::Info` :zeek:attr:`&optional`
                                                Client certificate

                                              client_cert_subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Subject of client certificate, if any

                                              client_cert_fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                File unique ID of client cert, if any

                                              server_cert: :zeek:type:`Files::Info` :zeek:attr:`&optional`
                                                Server certificate

                                              server_cert_subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Subject of server certificate, if any

                                              server_cert_fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                File unique ID of server cert, if any
=========================================== ===================================================================================

Functions
#########
====================================================== =====================================
:zeek:id:`KRB::describe_file`: :zeek:type:`function`   Default file describer for KRB.
:zeek:id:`KRB::get_file_handle`: :zeek:type:`function` Default file handle provider for KRB.
====================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: KRB::describe_file
   :source-code: base/protocols/krb/files.zeek 38 62

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Default file describer for KRB.

.. zeek:id:: KRB::get_file_handle
   :source-code: base/protocols/krb/files.zeek 32 36

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for KRB.


