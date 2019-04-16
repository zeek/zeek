:tocdepth: 3

base/bif/plugins/Bro_IMAP.events.bif.zeek
=========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================== ==================================================================
:bro:id:`imap_capabilities`: :bro:type:`event` Generated when a server sends a capability list to the client,
                                               after being queried using the CAPABILITY command.
:bro:id:`imap_starttls`: :bro:type:`event`     Generated when a IMAP connection goes encrypted after a successful
                                               StartTLS exchange between the client and the server.
============================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: imap_capabilities

   :Type: :bro:type:`event` (c: :bro:type:`connection`, capabilities: :bro:type:`string_vec`)

   Generated when a server sends a capability list to the client,
   after being queried using the CAPABILITY command.
   

   :c: The connection.
   

   :capabilities: The list of IMAP capabilities as sent by the server.

.. bro:id:: imap_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when a IMAP connection goes encrypted after a successful
   StartTLS exchange between the client and the server.
   

   :c: The connection.


