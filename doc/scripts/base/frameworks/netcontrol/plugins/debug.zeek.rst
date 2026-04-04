:tocdepth: 3

base/frameworks/netcontrol/plugins/debug.zeek
=============================================
.. zeek:namespace:: NetControl

Debugging plugin for the NetControl framework, providing insight into
executed operations.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/main.zeek </scripts/base/frameworks/netcontrol/main.zeek>`, :doc:`base/frameworks/netcontrol/plugin.zeek </scripts/base/frameworks/netcontrol/plugin.zeek>`

Summary
~~~~~~~
Functions
#########
================================================================= =========================================================
:zeek:id:`NetControl::create_debug`: :zeek:type:`function`        Instantiates a debug plugin for the NetControl framework.
:zeek:id:`NetControl::create_debug_error`: :zeek:type:`function`  Instantiates a debug plugin for the NetControl framework.
:zeek:id:`NetControl::create_debug_exists`: :zeek:type:`function` Instantiates a debug plugin for the NetControl framework.
================================================================= =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: NetControl::create_debug
   :source-code: base/frameworks/netcontrol/plugins/debug.zeek 118 131

   :Type: :zeek:type:`function` (do_something: :zeek:type:`bool`, name: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`NetControl::PluginState`

   Instantiates a debug plugin for the NetControl framework. The debug
   plugin simply logs the operations it receives.


   :param do_something: If true, the plugin will claim it supports all operations; if
                 false, it will indicate it doesn't support any.


   :param name: Optional name that for the plugin.

.. zeek:id:: NetControl::create_debug_error
   :source-code: base/frameworks/netcontrol/plugins/debug.zeek 133 140

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`NetControl::PluginState`

   Instantiates a debug plugin for the NetControl framework. This variation
   of the plugin will return "error" to any rule operations.


   :param name: Name of this plugin.

.. zeek:id:: NetControl::create_debug_exists
   :source-code: base/frameworks/netcontrol/plugins/debug.zeek 142 149

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`NetControl::PluginState`

   Instantiates a debug plugin for the NetControl framework. This variation
   of the plugin will return "exists" to any rule operations.


   :param name: Name of this plugin.


