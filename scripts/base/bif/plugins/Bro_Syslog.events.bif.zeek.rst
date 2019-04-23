:tocdepth: 3

base/bif/plugins/Bro_Syslog.events.bif.zeek
===========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================= ========================================
:zeek:id:`syslog_message`: :zeek:type:`event` Generated for monitored Syslog messages.
============================================= ========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: syslog_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, facility: :zeek:type:`count`, severity: :zeek:type:`count`, msg: :zeek:type:`string`)

   Generated for monitored Syslog messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Syslog>`__ for more
   information about the Syslog protocol.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :facility: The "facility" included in the message.
   

   :severity: The "severity" included in the message.
   

   :msg: The message logged.
   
   .. note:: Bro currently parses only UDP syslog traffic. Support for TCP
      syslog will be added soon.


