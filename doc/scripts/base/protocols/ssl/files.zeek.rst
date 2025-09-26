:tocdepth: 3

base/protocols/ssl/files.zeek
=============================
.. zeek:namespace:: SSL


:Namespace: SSL
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/ssl/main.zeek </scripts/base/protocols/ssl/main.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
==================================================================================================== ==============================================================
:zeek:id:`SSL::log_include_client_certificate_subject_issuer`: :zeek:type:`bool` :zeek:attr:`&redef` Set this to true to include the client certificate subject
                                                                                                     and issuer in the SSL logfile.
:zeek:id:`SSL::log_include_server_certificate_subject_issuer`: :zeek:type:`bool` :zeek:attr:`&redef` Set this to true to include the server certificate subject and
                                                                                                     issuer from the SSL log file.
==================================================================================================== ==============================================================

Redefinitions
#############
=========================================== ============================================================================================================
:zeek:type:`SSL::Info`: :zeek:type:`record` 
                                            
                                            :New Fields: :zeek:type:`SSL::Info`
                                            
                                              cert_chain: :zeek:type:`vector` of :zeek:type:`Files::Info` :zeek:attr:`&optional`
                                                Chain of certificates offered by the server to validate its
                                                complete signing chain.
                                            
                                              cert_chain_fps: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                An ordered vector of all certificate fingerprints for the
                                                certificates offered by the server.
                                            
                                              client_cert_chain: :zeek:type:`vector` of :zeek:type:`Files::Info` :zeek:attr:`&optional`
                                                Chain of certificates offered by the client to validate its
                                                complete signing chain.
                                            
                                              client_cert_chain_fps: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                An ordered vector of all certificate fingerprints for the
                                                certificates offered by the client.
                                            
                                              subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Subject of the X.509 certificate offered by the server.
                                            
                                              issuer: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Issuer of the signer of the X.509 certificate offered by the
                                                server.
                                            
                                              client_subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Subject of the X.509 certificate offered by the client.
                                            
                                              client_issuer: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Subject of the signer of the X.509 certificate offered by the
                                                client.
                                            
                                              sni_matches_cert: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Set to true if the hostname sent in the SNI matches the certificate.
                                            
                                              server_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                Current number of certificates seen from either side.
                                            
                                              client_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
=========================================== ============================================================================================================

Functions
#########
====================================================== =====================================
:zeek:id:`SSL::describe_file`: :zeek:type:`function`   Default file describer for SSL.
:zeek:id:`SSL::get_file_handle`: :zeek:type:`function` Default file handle provider for SSL.
====================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: SSL::log_include_client_certificate_subject_issuer
   :source-code: base/protocols/ssl/files.zeek 17 17

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Set this to true to include the client certificate subject
   and issuer in the SSL logfile. This information is rarely present
   and probably only interesting in very specific circumstances

.. zeek:id:: SSL::log_include_server_certificate_subject_issuer
   :source-code: base/protocols/ssl/files.zeek 12 12

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Set this to true to include the server certificate subject and
   issuer from the SSL log file. This information is still available
   in x509.log.

Functions
#########
.. zeek:id:: SSL::describe_file
   :source-code: base/protocols/ssl/files.zeek 74 95

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Default file describer for SSL.

.. zeek:id:: SSL::get_file_handle
   :source-code: base/protocols/ssl/files.zeek 68 72

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for SSL.


