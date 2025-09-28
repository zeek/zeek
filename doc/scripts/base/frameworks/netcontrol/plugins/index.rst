:orphan:

Package: base/frameworks/netcontrol/plugins
===========================================

Plugins for the NetControl framework.

:doc:`/scripts/base/frameworks/netcontrol/plugins/__load__.zeek`


:doc:`/scripts/base/frameworks/netcontrol/plugins/debug.zeek`

   Debugging plugin for the NetControl framework, providing insight into
   executed operations.

:doc:`/scripts/base/frameworks/netcontrol/plugins/openflow.zeek`

   OpenFlow plugin for the NetControl framework.

:doc:`/scripts/base/frameworks/netcontrol/plugins/packetfilter.zeek`

   NetControl plugin for the process-level PacketFilter that comes with
   Zeek. Since the PacketFilter in Zeek is quite limited in scope
   and can only add/remove filters for addresses, this is quite
   limited in scope at the moment.

:doc:`/scripts/base/frameworks/netcontrol/plugins/broker.zeek`

   Broker plugin for the NetControl framework. Sends the raw data structures
   used in NetControl on to Broker to allow for easy handling, e.g., of
   command-line scripts.

:doc:`/scripts/base/frameworks/netcontrol/plugins/acld.zeek`

   Acld plugin for the netcontrol framework.

