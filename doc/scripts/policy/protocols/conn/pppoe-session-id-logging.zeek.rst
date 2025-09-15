:tocdepth: 3

policy/protocols/conn/pppoe-session-id-logging.zeek
===================================================
.. zeek:namespace:: Conn

This script adds PPPoE session ID information to the connection log.

:Namespace: Conn
:Imports: :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ ===============================================================================
:zeek:type:`Conn::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`Conn::Info`
                                             
                                               pppoe_session_id: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 The PPPoE session id, if applicable for this connection.
============================================ ===============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

