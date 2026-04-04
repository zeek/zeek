:tocdepth: 3

policy/protocols/ssl/ssl-log-ext.zeek
=====================================
.. zeek:namespace:: SSL

This file adds a lot of additional information to the SSL log
It is not loaded by default since the information significantly expands
the log and is probably not interesting for a majority of people.

:Namespace: SSL
:Imports: :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== ===============================================================================================================
:zeek:type:`SSL::Info`: :zeek:type:`record`

                                            :New Fields: :zeek:type:`SSL::Info`

                                              server_version: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Numeric version of the server in the server hello

                                              client_version: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Numeric version of the client in the client hello

                                              client_ciphers: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Ciphers that were offered by the client for the connection

                                              ssl_client_exts: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                SSL Client extensions

                                              ssl_server_exts: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                SSL server extensions

                                              ticket_lifetime_hint: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Suggested ticket lifetime sent in the session ticket handshake
                                                by the server.

                                              dh_param_size: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                The diffie helman parameter size, when using DH.

                                              point_formats: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                supported elliptic curve point formats

                                              client_curves: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                The curves supported by the client.

                                              orig_alpn: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Application layer protocol negotiation extension sent by the client.

                                              client_supported_versions: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                TLS 1.3 supported versions

                                              server_supported_version: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                TLS 1.3 supported versions

                                              psk_key_exchange_modes: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                TLS 1.3 Pre-shared key exchange modes

                                              client_key_share_groups: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Key share groups from client hello

                                              server_key_share_group: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Selected key share group from server hello

                                              client_comp_methods: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Client supported compression methods

                                              comp_method: :zeek:type:`count` :zeek:attr:`&optional`
                                                Server chosen compression method

                                              sigalgs: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Client supported signature algorithms

                                              hashalgs: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Client supported hash algorithms
=========================================== ===============================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

