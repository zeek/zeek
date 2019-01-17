:tocdepth: 3

policy/integration/barnyard2/main.bro
=====================================
.. bro:namespace:: Barnyard2

This script lets Barnyard2 integrate with Bro.  It receives alerts from
Barnyard2 and logs them.  In the future it will do more correlation
and derive new notices from the alerts.

:Namespace: Barnyard2
:Imports: :doc:`policy/integration/barnyard2/types.bro </scripts/policy/integration/barnyard2/types.bro>`

Summary
~~~~~~~
Types
#####
=============================================== =
:bro:type:`Barnyard2::Info`: :bro:type:`record` 
=============================================== =

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Functions
#########
================================================== =====================================================================
:bro:id:`Barnyard2::pid2cid`: :bro:type:`function` This can convert a Barnyard :bro:type:`Barnyard2::PacketID` value to
                                                   a :bro:type:`conn_id` value in the case that you might need to index 
                                                   into an existing data structure elsewhere within Bro.
================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Barnyard2::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp of the alert.

      pid: :bro:type:`Barnyard2::PacketID` :bro:attr:`&log`
         Associated packet ID.

      alert: :bro:type:`Barnyard2::AlertData` :bro:attr:`&log`
         Associated alert data.


Functions
#########
.. bro:id:: Barnyard2::pid2cid

   :Type: :bro:type:`function` (p: :bro:type:`Barnyard2::PacketID`) : :bro:type:`conn_id`

   This can convert a Barnyard :bro:type:`Barnyard2::PacketID` value to
   a :bro:type:`conn_id` value in the case that you might need to index 
   into an existing data structure elsewhere within Bro.


