:tocdepth: 3

base/bif/plugins/Bro_ARP.events.bif.bro
=======================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================== ====================================================
:bro:id:`arp_reply`: :bro:type:`event`   Generated for ARP replies.
:bro:id:`arp_request`: :bro:type:`event` Generated for ARP requests.
:bro:id:`bad_arp`: :bro:type:`event`     Generated for ARP packets that Bro cannot interpret.
======================================== ====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: arp_reply

   :Type: :bro:type:`event` (mac_src: :bro:type:`string`, mac_dst: :bro:type:`string`, SPA: :bro:type:`addr`, SHA: :bro:type:`string`, TPA: :bro:type:`addr`, THA: :bro:type:`string`)

   Generated for ARP replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :mac_src: The reply's source MAC address.
   

   :mac_dst: The reply's destination MAC address.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   
   .. bro:see::  arp_request bad_arp

.. bro:id:: arp_request

   :Type: :bro:type:`event` (mac_src: :bro:type:`string`, mac_dst: :bro:type:`string`, SPA: :bro:type:`addr`, SHA: :bro:type:`string`, TPA: :bro:type:`addr`, THA: :bro:type:`string`)

   Generated for ARP requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :mac_src: The request's source MAC address.
   

   :mac_dst: The request's destination MAC address.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   
   .. bro:see:: arp_reply  bad_arp

.. bro:id:: bad_arp

   :Type: :bro:type:`event` (SPA: :bro:type:`addr`, SHA: :bro:type:`string`, TPA: :bro:type:`addr`, THA: :bro:type:`string`, explanation: :bro:type:`string`)

   Generated for ARP packets that Bro cannot interpret. Examples are packets
   with non-standard hardware address formats or hardware addresses that do not
   match the originator of the packet.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   

   :explanation: A short description of why the ARP packet is considered "bad".
   
   .. bro:see:: arp_reply arp_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


