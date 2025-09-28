:tocdepth: 3

policy/protocols/conn/failed-service-logging.zeek
=================================================
.. zeek:namespace:: Conn

This script adds the new column ``failed_service`` to the connection log.
The column contains the list of protocols in a connection that raised protocol
violations causing the analyzer to be removed. Protocols are listed in order
that they were removed.

:Namespace: Conn
:Imports: :doc:`base/frameworks/analyzer/dpd.zeek </scripts/base/frameworks/analyzer/dpd.zeek>`, :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =======================================================================================================================
:zeek:type:`Conn::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`Conn::Info`
                                             
                                               failed_service: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional` :zeek:attr:`&ordered`
                                                 List of analyzers in a connection that raised violations
                                                 causing their removal.
============================================ =======================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

