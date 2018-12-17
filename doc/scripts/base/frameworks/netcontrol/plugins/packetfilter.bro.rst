:tocdepth: 3

base/frameworks/netcontrol/plugins/packetfilter.bro
===================================================
.. bro:namespace:: NetControl

NetControl plugin for the process-level PacketFilter that comes with
Bro. Since the PacketFilter in Bro is quite limited in scope
and can only add/remove filters for addresses, this is quite
limited in scope at the moment. 

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/plugin.bro </scripts/base/frameworks/netcontrol/plugin.bro>`

Summary
~~~~~~~
Functions
#########
=============================================================== =====================================
:bro:id:`NetControl::create_packetfilter`: :bro:type:`function` Instantiates the packetfilter plugin.
=============================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: NetControl::create_packetfilter

   :Type: :bro:type:`function` () : :bro:type:`NetControl::PluginState`

   Instantiates the packetfilter plugin.


