:tocdepth: 3

policy/protocols/conn/mac-logging.zeek
======================================
.. zeek:namespace:: Conn

This script adds link-layer address (MAC) information to the connection logs

:Namespace: Conn
:Imports: :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ ============================================================================
:zeek:type:`Conn::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`Conn::Info`
                                             
                                               orig_l2_addr: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 Link-layer address of the originator, if available.
                                             
                                               resp_l2_addr: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 Link-layer address of the responder, if available.
============================================ ============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

