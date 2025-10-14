:tocdepth: 3

base/frameworks/netcontrol/plugins/packetfilter.zeek
====================================================
.. zeek:namespace:: NetControl

NetControl plugin for the process-level PacketFilter that comes with
Zeek. Since the PacketFilter in Zeek is quite limited in scope
and can only add/remove filters for addresses, this is quite
limited in scope at the moment.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/plugin.zeek </scripts/base/frameworks/netcontrol/plugin.zeek>`

Summary
~~~~~~~
Functions
#########
================================================================= =====================================
:zeek:id:`NetControl::create_packetfilter`: :zeek:type:`function` Instantiates the packetfilter plugin.
================================================================= =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: NetControl::create_packetfilter
   :source-code: base/frameworks/netcontrol/plugins/packetfilter.zeek 107 112

   :Type: :zeek:type:`function` () : :zeek:type:`NetControl::PluginState`

   Instantiates the packetfilter plugin.


