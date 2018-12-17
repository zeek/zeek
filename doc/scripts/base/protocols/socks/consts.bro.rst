:tocdepth: 3

base/protocols/socks/consts.bro
===============================
.. bro:namespace:: SOCKS


:Namespace: SOCKS

Summary
~~~~~~~
Constants
#########
=============================================================================================================================== =
:bro:id:`SOCKS::v4_status`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`                 
:bro:id:`SOCKS::v5_authentication_methods`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` 
:bro:id:`SOCKS::v5_status`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`                 
=============================================================================================================================== =

Types
#####
================================================ =
:bro:type:`SOCKS::RequestType`: :bro:type:`enum` 
================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: SOCKS::v4_status

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [91] = "general SOCKS server failure",
         [93] = "request failed because client's identd could not confirm the user ID string in the request",
         [92] = "request failed because client is not running identd",
         [90] = "succeeded"
      }


.. bro:id:: SOCKS::v5_authentication_methods

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
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


.. bro:id:: SOCKS::v5_status

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
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
.. bro:type:: SOCKS::RequestType

   :Type: :bro:type:`enum`

      .. bro:enum:: SOCKS::CONNECTION SOCKS::RequestType

      .. bro:enum:: SOCKS::PORT SOCKS::RequestType

      .. bro:enum:: SOCKS::UDP_ASSOCIATE SOCKS::RequestType



