:tocdepth: 3

base/bif/plugins/Bro_XMPP.events.bif.zeek
=========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================== ==================================================================
:bro:id:`xmpp_starttls`: :bro:type:`event` Generated when a XMPP connection goes encrypted after a successful
                                           StartTLS exchange between the client and the server.
========================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: xmpp_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when a XMPP connection goes encrypted after a successful
   StartTLS exchange between the client and the server.
   

   :c: The connection.


