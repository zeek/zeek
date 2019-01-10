:tocdepth: 3

base/bif/plugins/Bro_SOCKS.events.bif.bro
=========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================= ===========================================================================
:bro:id:`socks_login_userpass_reply`: :bro:type:`event`   Generated when a SOCKS server replies to a username/password login attempt.
:bro:id:`socks_login_userpass_request`: :bro:type:`event` Generated when a SOCKS client performs username and password based login.
:bro:id:`socks_reply`: :bro:type:`event`                  Generated when a SOCKS reply is analyzed.
:bro:id:`socks_request`: :bro:type:`event`                Generated when a SOCKS request is analyzed.
========================================================= ===========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: socks_login_userpass_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, code: :bro:type:`count`)

   Generated when a SOCKS server replies to a username/password login attempt.
   

   :c: The parent connection of the proxy.
   

   :code: The response code for the attempted login.

.. bro:id:: socks_login_userpass_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, user: :bro:type:`string`, password: :bro:type:`string`)

   Generated when a SOCKS client performs username and password based login.
   

   :c: The parent connection of the proxy.
   

   :user: The given username.
   

   :password: The given password.

.. bro:id:: socks_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`count`, reply: :bro:type:`count`, sa: :bro:type:`SOCKS::Address`, p: :bro:type:`port`)

   Generated when a SOCKS reply is analyzed.
   

   :c: The parent connection of the proxy.
   

   :version: The version of SOCKS this message used.
   

   :reply: The status reply from the server.
   

   :sa: The address that the server sent the traffic to.
   

   :p: The destination port for the proxied traffic.

.. bro:id:: socks_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`count`, request_type: :bro:type:`count`, sa: :bro:type:`SOCKS::Address`, p: :bro:type:`port`, user: :bro:type:`string`)

   Generated when a SOCKS request is analyzed.
   

   :c: The parent connection of the proxy.
   

   :version: The version of SOCKS this message used.
   

   :request_type: The type of the request.
   

   :sa: Address that the tunneled traffic should be sent to.
   

   :p: The destination port for the proxied traffic.
   

   :user: Username given for the SOCKS connection.  This is not yet implemented
         for SOCKSv5.


