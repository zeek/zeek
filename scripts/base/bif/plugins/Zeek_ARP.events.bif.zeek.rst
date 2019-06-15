:tocdepth: 3

base/bif/plugins/Zeek_ARP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================== =====================================================
:zeek:id:`arp_reply`: :zeek:type:`event`   Generated for ARP replies.
:zeek:id:`arp_request`: :zeek:type:`event` Generated for ARP requests.
:zeek:id:`bad_arp`: :zeek:type:`event`     Generated for ARP packets that Zeek cannot interpret.
========================================== =====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: arp_reply

   :Type: :zeek:type:`event` (mac_src: :zeek:type:`string`, mac_dst: :zeek:type:`string`, SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`)

   Generated for ARP replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :mac_src: The reply's source MAC address.
   

   :mac_dst: The reply's destination MAC address.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   
   .. zeek:see::  arp_request bad_arp

.. zeek:id:: arp_request

   :Type: :zeek:type:`event` (mac_src: :zeek:type:`string`, mac_dst: :zeek:type:`string`, SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`)

   Generated for ARP requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :mac_src: The request's source MAC address.
   

   :mac_dst: The request's destination MAC address.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   
   .. zeek:see:: arp_reply  bad_arp

.. zeek:id:: bad_arp

   :Type: :zeek:type:`event` (SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`, explanation: :zeek:type:`string`)

   Generated for ARP packets that Zeek cannot interpret. Examples are packets
   with non-standard hardware address formats or hardware addresses that do not
   match the originator of the packet.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   

   :explanation: A short description of why the ARP packet is considered "bad".
   
   .. zeek:see:: arp_reply arp_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


