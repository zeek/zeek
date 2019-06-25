:tocdepth: 3

base/protocols/socks/consts.zeek
================================
.. zeek:namespace:: SOCKS


:Namespace: SOCKS

Summary
~~~~~~~
Constants
#########
==================================================================================================================================== =
:zeek:id:`SOCKS::v4_status`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`                 
:zeek:id:`SOCKS::v5_authentication_methods`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional` 
:zeek:id:`SOCKS::v5_status`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`                 
==================================================================================================================================== =

Types
#####
================================================== =
:zeek:type:`SOCKS::RequestType`: :zeek:type:`enum` 
================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: SOCKS::v4_status

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [91] = "general SOCKS server failure",
            [93] = "request failed because client's identd could not confirm the user ID string in the request",
            [92] = "request failed because client is not running identd",
            [90] = "succeeded"
         }



.. zeek:id:: SOCKS::v5_authentication_methods

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [2] = "Username/Password",
            [6] = "Secure Sockets Layer",
            [1] = "GSSAPI",
            [8] = "Multi-Authentication Framework",
            [7] = "NDS Authentication",
            [255] = "No Acceptable Methods",
            [5] = "Challenge-Response Authentication Method",
            [0] = "No Authentication Required",
            [3] = "Challenge-Handshake Authentication Protocol"
         }



.. zeek:id:: SOCKS::v5_status

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [2] = "connection not allowed by ruleset",
            [6] = "TTL expired",
            [4] = "Host unreachable",
            [1] = "general SOCKS server failure",
            [8] = "Address type not supported",
            [7] = "Command not supported",
            [5] = "Connection refused",
            [0] = "succeeded",
            [3] = "Network unreachable"
         }



Types
#####
.. zeek:type:: SOCKS::RequestType

   :Type: :zeek:type:`enum`

      .. zeek:enum:: SOCKS::CONNECTION SOCKS::RequestType

      .. zeek:enum:: SOCKS::PORT SOCKS::RequestType

      .. zeek:enum:: SOCKS::UDP_ASSOCIATE SOCKS::RequestType



