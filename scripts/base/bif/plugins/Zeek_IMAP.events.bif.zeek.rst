:tocdepth: 3

base/bif/plugins/Zeek_IMAP.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================ ==================================================================
:zeek:id:`imap_capabilities`: :zeek:type:`event` Generated when a server sends a capability list to the client,
                                                 after being queried using the CAPABILITY command.
:zeek:id:`imap_starttls`: :zeek:type:`event`     Generated when a IMAP connection goes encrypted after a successful
                                                 StartTLS exchange between the client and the server.
================================================ ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: imap_capabilities

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, capabilities: :zeek:type:`string_vec`)

   Generated when a server sends a capability list to the client,
   after being queried using the CAPABILITY command.
   

   :c: The connection.
   

   :capabilities: The list of IMAP capabilities as sent by the server.

.. zeek:id:: imap_starttls

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when a IMAP connection goes encrypted after a successful
   StartTLS exchange between the client and the server.
   

   :c: The connection.


