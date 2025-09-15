:tocdepth: 3

base/protocols/socks/consts.zeek
================================
.. zeek:namespace:: SOCKS


:Namespace: SOCKS

Summary
~~~~~~~
Constants
#########
============================================================================================================= =
:zeek:id:`SOCKS::v4_status`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`                 
:zeek:id:`SOCKS::v5_authentication_methods`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
:zeek:id:`SOCKS::v5_status`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`                 
============================================================================================================= =

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
   :source-code: base/protocols/socks/consts.zeek 22 22

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [92] = "request failed because client is not running identd",
            [93] = "request failed because client's identd could not confirm the user ID string in the request",
            [90] = "succeeded",
            [91] = "general SOCKS server failure"
         }



.. zeek:id:: SOCKS::v5_authentication_methods
   :source-code: base/protocols/socks/consts.zeek 10 10

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "Username/Password",
            [8] = "Multi-Authentication Framework",
            [7] = "NDS Authentication",
            [5] = "Challenge-Response Authentication Method",
            [3] = "Challenge-Handshake Authentication Protocol",
            [0] = "No Authentication Required",
            [6] = "Secure Sockets Layer",
            [255] = "No Acceptable Methods",
            [1] = "GSSAPI"
         }



.. zeek:id:: SOCKS::v5_status
   :source-code: base/protocols/socks/consts.zeek 29 29

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "connection not allowed by ruleset",
            [8] = "Address type not supported",
            [5] = "Connection refused",
            [7] = "Command not supported",
            [3] = "Network unreachable",
            [0] = "succeeded",
            [6] = "TTL expired",
            [4] = "Host unreachable",
            [1] = "general SOCKS server failure"
         }



Types
#####
.. zeek:type:: SOCKS::RequestType
   :source-code: base/protocols/socks/consts.zeek 4 9

   :Type: :zeek:type:`enum`

      .. zeek:enum:: SOCKS::CONNECTION SOCKS::RequestType

      .. zeek:enum:: SOCKS::PORT SOCKS::RequestType

      .. zeek:enum:: SOCKS::UDP_ASSOCIATE SOCKS::RequestType



