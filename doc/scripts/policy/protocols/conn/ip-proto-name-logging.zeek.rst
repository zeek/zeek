:tocdepth: 3

policy/protocols/conn/ip-proto-name-logging.zeek
================================================
.. zeek:namespace:: Conn

This script adds a string version of the ip_proto field. It's not recommended
to load this policy and the ip_proto removal policy at the same time, as
conn.log will end up with useless information in the log from this field.

:Namespace: Conn
:Imports: :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =============================================================================
:zeek:type:`Conn::Info`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`Conn::Info`

                                               ip_proto_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 A string version of the ip_proto field
============================================ =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

