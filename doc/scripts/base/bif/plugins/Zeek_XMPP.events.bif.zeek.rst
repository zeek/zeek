:tocdepth: 3

base/bif/plugins/Zeek_XMPP.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================ ==================================================================
:zeek:id:`xmpp_starttls`: :zeek:type:`event` Generated when a XMPP connection goes encrypted after a successful
                                             StartTLS exchange between the client and the server.
============================================ ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: xmpp_starttls
   :source-code: base/bif/plugins/Zeek_XMPP.events.bif.zeek 8 8

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when a XMPP connection goes encrypted after a successful
   StartTLS exchange between the client and the server.
   

   :param c: The connection.


