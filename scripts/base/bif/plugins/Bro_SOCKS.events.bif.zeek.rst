:tocdepth: 3

base/bif/plugins/Bro_SOCKS.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== ===========================================================================
:zeek:id:`socks_login_userpass_reply`: :zeek:type:`event`   Generated when a SOCKS server replies to a username/password login attempt.
:zeek:id:`socks_login_userpass_request`: :zeek:type:`event` Generated when a SOCKS client performs username and password based login.
:zeek:id:`socks_reply`: :zeek:type:`event`                  Generated when a SOCKS reply is analyzed.
:zeek:id:`socks_request`: :zeek:type:`event`                Generated when a SOCKS request is analyzed.
=========================================================== ===========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: socks_login_userpass_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, code: :zeek:type:`count`)

   Generated when a SOCKS server replies to a username/password login attempt.
   

   :c: The parent connection of the proxy.
   

   :code: The response code for the attempted login.

.. zeek:id:: socks_login_userpass_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated when a SOCKS client performs username and password based login.
   

   :c: The parent connection of the proxy.
   

   :user: The given username.
   

   :password: The given password.

.. zeek:id:: socks_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, reply: :zeek:type:`count`, sa: :zeek:type:`SOCKS::Address`, p: :zeek:type:`port`)

   Generated when a SOCKS reply is analyzed.
   

   :c: The parent connection of the proxy.
   

   :version: The version of SOCKS this message used.
   

   :reply: The status reply from the server.
   

   :sa: The address that the server sent the traffic to.
   

   :p: The destination port for the proxied traffic.

.. zeek:id:: socks_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, request_type: :zeek:type:`count`, sa: :zeek:type:`SOCKS::Address`, p: :zeek:type:`port`, user: :zeek:type:`string`)

   Generated when a SOCKS request is analyzed.
   

   :c: The parent connection of the proxy.
   

   :version: The version of SOCKS this message used.
   

   :request_type: The type of the request.
   

   :sa: Address that the tunneled traffic should be sent to.
   

   :p: The destination port for the proxied traffic.
   

   :user: Username given for the SOCKS connection.  This is not yet implemented
         for SOCKSv5.


