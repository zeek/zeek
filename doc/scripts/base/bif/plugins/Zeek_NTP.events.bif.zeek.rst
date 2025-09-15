:tocdepth: 3

base/bif/plugins/Zeek_NTP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================== ===============================
:zeek:id:`ntp_message`: :zeek:type:`event` Generated for all NTP messages.
========================================== ===============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: ntp_message
   :source-code: base/bif/plugins/Zeek_NTP.events.bif.zeek 15 15

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`NTP::Message`)

   Generated for all NTP messages. Different from many other of Zeek's events,
   this one is generated for both client-side and server-side messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Network_Time_Protocol>`__ for
   more information about the NTP protocol.
   

   :param c: The connection record describing the corresponding UDP flow.
   

   :param is_orig: True if the message was sent by the originator.
   

   :param msg: The parsed NTP message.


