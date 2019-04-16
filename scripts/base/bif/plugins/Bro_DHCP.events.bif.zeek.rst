:tocdepth: 3

base/bif/plugins/Bro_DHCP.events.bif.zeek
=========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================= ================================
:bro:id:`dhcp_message`: :bro:type:`event` Generated for all DHCP messages.
========================================= ================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: dhcp_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`DHCP::Msg`, options: :bro:type:`DHCP::Options`)

   Generated for all DHCP messages.
   

   :c: The connection record describing the underlying UDP flow.
   

   :is_orig: Indicate if the message came in a packet from the
           originator/client of the udp flow or the responder/server.
   

   :msg: The parsed type-independent part of the DHCP message. The message
        type is indicated in this record.
   

   :options: The full set of supported and parsed DHCP options.


