:tocdepth: 3

policy/protocols/conn/speculative-service.zeek
==============================================
.. zeek:namespace:: Conn

This script adds information about matched DPD signatures to the connection
log.

:Namespace: Conn
:Imports: :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Redefinitions
#############
========================================================================== =
:zeek:type:`Conn::Info`: :zeek:type:`record`                               
:zeek:type:`connection`: :zeek:type:`record`                               
:zeek:id:`dpd_late_match_stop`: :zeek:type:`bool` :zeek:attr:`&redef`      
:zeek:id:`dpd_match_only_beginning`: :zeek:type:`bool` :zeek:attr:`&redef` 
========================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

