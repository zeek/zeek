:tocdepth: 3

base/bif/plugins/Zeek_SOCKS.events.bif.zeek
===========================================
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
   :source-code: base/protocols/socks/main.zeek 115 121

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, code: :zeek:type:`count`)

   Generated when a SOCKS server replies to a username/password login attempt.
   

   :param c: The parent connection of the proxy.
   

   :param code: The response code for the attempted login.

.. zeek:id:: socks_login_userpass_request
   :source-code: base/protocols/socks/main.zeek 104 113

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated when a SOCKS client performs username and password based login.
   

   :param c: The parent connection of the proxy.
   

   :param user: The given username.
   

   :param password: The given password.

.. zeek:id:: socks_reply
   :source-code: base/protocols/socks/main.zeek 91 102

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, reply: :zeek:type:`count`, sa: :zeek:type:`SOCKS::Address`, p: :zeek:type:`port`)

   Generated when a SOCKS reply is analyzed.
   

   :param c: The parent connection of the proxy.
   

   :param version: The version of SOCKS this message used.
   

   :param reply: The status reply from the server.
   

   :param sa: The address that the server sent the traffic to.
   

   :param p: The destination port for the proxied traffic.

.. zeek:id:: socks_request
   :source-code: base/protocols/socks/main.zeek 76 89

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, request_type: :zeek:type:`count`, sa: :zeek:type:`SOCKS::Address`, p: :zeek:type:`port`, user: :zeek:type:`string`)

   Generated when a SOCKS request is analyzed.
   

   :param c: The parent connection of the proxy.
   

   :param version: The version of SOCKS this message used.
   

   :param request_type: The type of the request.
   

   :param sa: Address that the tunneled traffic should be sent to.
   

   :param p: The destination port for the proxied traffic.
   

   :param user: Username given for the SOCKS connection.  This is not yet implemented
         for SOCKSv5.


