:tocdepth: 3

policy/protocols/conn/vlan-logging.zeek
=======================================
.. zeek:namespace:: Conn

This script adds VLAN information to the connection log.

:Namespace: Conn
:Imports: :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =======================================================================
:zeek:type:`Conn::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`Conn::Info`
                                             
                                               vlan: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 The outer VLAN for this connection, if applicable.
                                             
                                               inner_vlan: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 The inner VLAN for this connection, if applicable.
============================================ =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

