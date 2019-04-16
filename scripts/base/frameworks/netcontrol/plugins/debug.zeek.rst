:tocdepth: 3

base/frameworks/netcontrol/plugins/debug.zeek
=============================================
.. bro:namespace:: NetControl

Debugging plugin for the NetControl framework, providing insight into
executed operations.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/main.zeek </scripts/base/frameworks/netcontrol/main.zeek>`, :doc:`base/frameworks/netcontrol/plugin.zeek </scripts/base/frameworks/netcontrol/plugin.zeek>`

Summary
~~~~~~~
Functions
#########
======================================================== =========================================================
:bro:id:`NetControl::create_debug`: :bro:type:`function` Instantiates a debug plugin for the NetControl framework.
======================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: NetControl::create_debug

   :Type: :bro:type:`function` (do_something: :bro:type:`bool`) : :bro:type:`NetControl::PluginState`

   Instantiates a debug plugin for the NetControl framework. The debug
   plugin simply logs the operations it receives.
   

   :do_something: If true, the plugin will claim it supports all operations; if
                 false, it will indicate it doesn't support any.


