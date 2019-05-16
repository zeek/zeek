:orphan:

Package: base/frameworks/openflow
=================================

The OpenFlow framework exposes the data structures and functions
necessary to interface to OpenFlow capable hardware.

:doc:`/scripts/base/frameworks/openflow/__load__.zeek`


:doc:`/scripts/base/frameworks/openflow/consts.zeek`

   Constants used by the OpenFlow framework.

:doc:`/scripts/base/frameworks/openflow/types.zeek`

   Types used by the OpenFlow framework.

:doc:`/scripts/base/frameworks/openflow/main.zeek`

   Zeek's OpenFlow control framework.
   
   This plugin-based framework allows to control OpenFlow capable
   switches by implementing communication to an OpenFlow controller
   via plugins. The framework has to be instantiated via the new function
   in one of the plugins. This framework only offers very low-level
   functionality; if you want to use OpenFlow capable switches, e.g.,
   for shunting, please look at the NetControl framework, which provides higher
   level functions and can use the OpenFlow framework as a backend.

:doc:`/scripts/base/frameworks/openflow/plugins/__load__.zeek`


:doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek`

   OpenFlow plugin for the Ryu controller.

:doc:`/scripts/base/frameworks/openflow/plugins/log.zeek`

   OpenFlow plugin that outputs flow-modification commands
   to a Zeek log file.

:doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek`

   OpenFlow plugin for interfacing to controllers via Broker.

:doc:`/scripts/base/frameworks/openflow/non-cluster.zeek`


