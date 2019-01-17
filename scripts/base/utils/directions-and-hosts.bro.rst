:tocdepth: 3

base/utils/directions-and-hosts.bro
===================================


:Imports: :doc:`base/utils/site.bro </scripts/base/utils/site.bro>`

Summary
~~~~~~~
Types
#####
======================================= =
:bro:type:`Direction`: :bro:type:`enum` 
:bro:type:`Host`: :bro:type:`enum`      
======================================= =

Functions
#########
==================================================== ======================================================================
:bro:id:`addr_matches_host`: :bro:type:`function`    Checks whether a given host (IP address) matches a given host type.
:bro:id:`id_matches_direction`: :bro:type:`function` Checks whether a given connection is of a given direction with respect
                                                     to the locally-monitored network.
==================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Direction

   :Type: :bro:type:`enum`

      .. bro:enum:: INBOUND Direction

         The connection originator is not within the locally-monitored
         network, but the other endpoint is.

      .. bro:enum:: OUTBOUND Direction

         The connection originator is within the locally-monitored network,
         but the other endpoint is not.

      .. bro:enum:: BIDIRECTIONAL Direction

         Only one endpoint is within the locally-monitored network, meaning
         the connection is either outbound or inbound.

      .. bro:enum:: NO_DIRECTION Direction

         This value doesn't match any connection.


.. bro:type:: Host

   :Type: :bro:type:`enum`

      .. bro:enum:: LOCAL_HOSTS Host

         A host within the locally-monitored network.

      .. bro:enum:: REMOTE_HOSTS Host

         A host not within the locally-monitored network.

      .. bro:enum:: ALL_HOSTS Host

         Any host.

      .. bro:enum:: NO_HOSTS Host

         This value doesn't match any host.


Functions
#########
.. bro:id:: addr_matches_host

   :Type: :bro:type:`function` (ip: :bro:type:`addr`, h: :bro:type:`Host`) : :bro:type:`bool`

   Checks whether a given host (IP address) matches a given host type.
   

   :ip: address of a host.
   

   :h: a host type.
   

   :returns: T if the given host matches the given type, else F.

.. bro:id:: id_matches_direction

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`, d: :bro:type:`Direction`) : :bro:type:`bool`

   Checks whether a given connection is of a given direction with respect
   to the locally-monitored network.
   

   :id: a connection record containing the originator/responder hosts.
   

   :d: a direction with respect to the locally-monitored network.
   

   :returns: T if the two connection endpoints match the given direction, else F.


