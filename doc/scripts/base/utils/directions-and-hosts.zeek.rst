:tocdepth: 3

base/utils/directions-and-hosts.zeek
====================================


:Imports: :doc:`base/utils/site.zeek </scripts/base/utils/site.zeek>`

Summary
~~~~~~~
Types
#####
========================================= =
:zeek:type:`Direction`: :zeek:type:`enum` 
:zeek:type:`Host`: :zeek:type:`enum`      
========================================= =

Functions
#########
====================================================== ======================================================================
:zeek:id:`addr_matches_host`: :zeek:type:`function`    Checks whether a given host (IP address) matches a given host type.
:zeek:id:`id_matches_direction`: :zeek:type:`function` Checks whether a given connection is of a given direction with respect
                                                       to the locally-monitored network.
====================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Direction
   :source-code: base/utils/directions-and-hosts.zeek 3 16

   :Type: :zeek:type:`enum`

      .. zeek:enum:: INBOUND Direction

         The connection originator is not within the locally-monitored
         network, but the other endpoint is.

      .. zeek:enum:: OUTBOUND Direction

         The connection originator is within the locally-monitored network,
         but the other endpoint is not.

      .. zeek:enum:: BIDIRECTIONAL Direction

         Only one endpoint is within the locally-monitored network, meaning
         the connection is either outbound or inbound.

      .. zeek:enum:: NO_DIRECTION Direction

         This value doesn't match any connection.


.. zeek:type:: Host
   :source-code: base/utils/directions-and-hosts.zeek 40 50

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LOCAL_HOSTS Host

         A host within the locally-monitored network.

      .. zeek:enum:: REMOTE_HOSTS Host

         A host not within the locally-monitored network.

      .. zeek:enum:: ALL_HOSTS Host

         Any host.

      .. zeek:enum:: NO_HOSTS Host

         This value doesn't match any host.


Functions
#########
.. zeek:id:: addr_matches_host
   :source-code: base/utils/directions-and-hosts.zeek 58 65

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`, h: :zeek:type:`Host`) : :zeek:type:`bool`

   Checks whether a given host (IP address) matches a given host type.
   

   :param ip: address of a host.
   

   :param h: a host type.
   

   :returns: T if the given host matches the given type, else F.

.. zeek:id:: id_matches_direction
   :source-code: base/utils/directions-and-hosts.zeek 25 38

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`, d: :zeek:type:`Direction`) : :zeek:type:`bool`

   Checks whether a given connection is of a given direction with respect
   to the locally-monitored network.
   

   :param id: a connection record containing the originator/responder hosts.
   

   :param d: a direction with respect to the locally-monitored network.
   

   :returns: T if the two connection endpoints match the given direction, else F.


