:tocdepth: 3

base/frameworks/netcontrol/plugin.zeek
======================================
.. zeek:namespace:: NetControl

This file defines the plugin interface for NetControl.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/types.zeek </scripts/base/frameworks/netcontrol/types.zeek>`

Summary
~~~~~~~
Types
#####
========================================================= =====================================================
:zeek:type:`NetControl::Plugin`: :zeek:type:`record`      Definition of a plugin.
:zeek:type:`NetControl::PluginState`: :zeek:type:`record` This record keeps the per instance state of a plugin.
========================================================= =====================================================

Redefinitions
#############
========================================================= ========================================================================
:zeek:type:`NetControl::PluginState`: :zeek:type:`record` Table for a plugin to store instance-specific configuration information.
                                                          
                                                          :New Fields: :zeek:type:`NetControl::PluginState`
                                                          
                                                            plugin: :zeek:type:`NetControl::Plugin` :zeek:attr:`&optional`
                                                              The plugin that the state belongs to.
========================================================= ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: NetControl::Plugin
   :source-code: base/frameworks/netcontrol/plugin.zeek 38 72

   :Type: :zeek:type:`record`

      name: :zeek:type:`function` (state: :zeek:type:`NetControl::PluginState`) : :zeek:type:`string`
         Returns a descriptive name of the plugin instance, suitable for use in logging
         messages. Note that this function is not optional.

      can_expire: :zeek:type:`bool`
         If true, plugin can expire rules itself. If false, the NetControl
         framework will manage rule expiration.

      init: :zeek:type:`function` (state: :zeek:type:`NetControl::PluginState`) : :zeek:type:`void` :zeek:attr:`&optional`
         One-time initialization function called when plugin gets registered, and
         before any other methods are called.
         
         If this function is provided, NetControl assumes that the plugin has to
         perform, potentially lengthy, initialization before the plugin will become
         active. In this case, the plugin has to call ``NetControl::plugin_activated``,
         once initialization finishes.

      done: :zeek:type:`function` (state: :zeek:type:`NetControl::PluginState`) : :zeek:type:`void` :zeek:attr:`&optional`
         One-time finalization function called when a plugin is shutdown; no further
         functions will be called afterwards.

      add_rule: :zeek:type:`function` (state: :zeek:type:`NetControl::PluginState`, r: :zeek:type:`NetControl::Rule`) : :zeek:type:`bool` :zeek:attr:`&optional`
         Implements the add_rule() operation. If the plugin accepts the rule,
         it returns true, false otherwise. The rule will already have its
         ``id`` field set, which the plugin may use for identification
         purposes.

      remove_rule: :zeek:type:`function` (state: :zeek:type:`NetControl::PluginState`, r: :zeek:type:`NetControl::Rule`, reason: :zeek:type:`string`) : :zeek:type:`bool` :zeek:attr:`&optional`
         Implements the remove_rule() operation. This will only be called for
         rules that the plugin has previously accepted with add_rule(). The
         ``id`` field will match that of the add_rule() call.  Generally,
         a plugin that accepts an add_rule() should also accept the
         remove_rule().

   Definition of a plugin.
   
   Generally a plugin needs to implement only what it can support.  By
   returning failure, it indicates that it can't support something and
   the framework will then try another plugin, if available; or inform the
   that the operation failed. If a function isn't implemented by a plugin,
   that's considered an implicit failure to support the operation.
   
   If plugin accepts a rule operation, it *must* generate one of the reporting
   events ``rule_{added,remove,error}`` to signal if it indeed worked out;
   this is separate from accepting the operation because often a plugin
   will only know later (i.e., asynchronously) if that was an error for
   something it thought it could handle.

.. zeek:type:: NetControl::PluginState
   :source-code: base/frameworks/netcontrol/plugin.zeek 11 23

   :Type: :zeek:type:`record`

      config: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Table for a plugin to store custom, instance-specific state.

      _id: :zeek:type:`count` :zeek:attr:`&optional`
         Unique plugin identifier -- used for backlookup of plugins from Rules. Set internally.

      _priority: :zeek:type:`int` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Set internally.

      _activated: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Set internally. Signifies if the plugin has returned that it has activated successfully.

      plugin: :zeek:type:`NetControl::Plugin` :zeek:attr:`&optional`
         The plugin that the state belongs to. (Defined separately
         because of cyclic type dependency.)

      of_controller: :zeek:type:`OpenFlow::Controller` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/openflow.zeek` is loaded)

         OpenFlow controller for NetControl OpenFlow plugin.

      of_config: :zeek:type:`NetControl::OfConfig` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/openflow.zeek` is loaded)

         OpenFlow configuration record that is passed on initialization.

      broker_config: :zeek:type:`NetControl::BrokerConfig` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/broker.zeek` is loaded)

         OpenFlow controller for NetControl Broker plugin.

      broker_id: :zeek:type:`count` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/broker.zeek` is loaded)

         The ID of this broker instance - for the mapping to PluginStates.

      acld_config: :zeek:type:`NetControl::AcldConfig` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/acld.zeek` is loaded)


      acld_id: :zeek:type:`count` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/acld.zeek` is loaded)

         The ID of this acld instance - for the mapping to PluginStates.

   This record keeps the per instance state of a plugin.
   
   Individual plugins commonly extend this record to suit their needs.


