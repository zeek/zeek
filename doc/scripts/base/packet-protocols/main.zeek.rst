:tocdepth: 3

base/packet-protocols/main.zeek
===============================
.. zeek:namespace:: PacketAnalyzer


:Namespace: PacketAnalyzer
:Imports: :doc:`base/frameworks/analyzer/main.zeek </scripts/base/frameworks/analyzer/main.zeek>`

Summary
~~~~~~~
Functions
#########
==================================================================== ========================================================
:zeek:id:`PacketAnalyzer::register_for_port`: :zeek:type:`function`  Registers an individual well-known port for an analyzer.
:zeek:id:`PacketAnalyzer::register_for_ports`: :zeek:type:`function` Registers a set of well-known ports for an analyzer.
==================================================================== ========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: PacketAnalyzer::register_for_port
   :source-code: base/packet-protocols/main.zeek 52 61

   :Type: :zeek:type:`function` (parent: :zeek:type:`PacketAnalyzer::Tag`, child: :zeek:type:`PacketAnalyzer::Tag`, p: :zeek:type:`port`) : :zeek:type:`bool`

   Registers an individual well-known port for an analyzer. If a future
   connection on this port is seen, the analyzer will be automatically
   assigned to parsing it. The function *adds* to all ports already
   registered, it doesn't replace them.
   

   :param tag: The tag of the analyzer.
   

   :param p: The well-known port to associate with the analyzer.
   

   :returns: True if the port was successfully registered.

.. zeek:id:: PacketAnalyzer::register_for_ports
   :source-code: base/packet-protocols/main.zeek 37 48

   :Type: :zeek:type:`function` (parent: :zeek:type:`PacketAnalyzer::Tag`, child: :zeek:type:`PacketAnalyzer::Tag`, ports: :zeek:type:`set` [:zeek:type:`port`]) : :zeek:type:`bool`

   Registers a set of well-known ports for an analyzer. If a future
   connection on one of these ports is seen, the analyzer will be
   automatically assigned to parsing it. The function *adds* to all ports
   already registered, it doesn't replace them.
   

   :param tag: The tag of the analyzer.
   

   :param ports: The set of well-known ports to associate with the analyzer.
   

   :returns: True if the ports were successfully registered.


