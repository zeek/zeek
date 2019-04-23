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
========================================================== =========================================================
:zeek:id:`NetControl::create_debug`: :zeek:type:`function` Instantiates a debug plugin for the NetControl framework.
========================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: NetControl::create_debug

   :Type: :zeek:type:`function` (do_something: :zeek:type:`bool`) : :zeek:type:`NetControl::PluginState`

   Instantiates a debug plugin for the NetControl framework. The debug
   plugin simply logs the operations it receives.
   

   :do_something: If true, the plugin will claim it supports all operations; if
                 false, it will indicate it doesn't support any.


