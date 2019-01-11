:tocdepth: 3

base/frameworks/netcontrol/plugin.bro
=====================================
.. bro:namespace:: NetControl

This file defines the plugin interface for NetControl.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/types.bro </scripts/base/frameworks/netcontrol/types.bro>`

Summary
~~~~~~~
Types
#####
======================================================= =====================================================
:bro:type:`NetControl::Plugin`: :bro:type:`record`      Definition of a plugin.
:bro:type:`NetControl::PluginState`: :bro:type:`record` This record keeps the per instance state of a plugin.
======================================================= =====================================================

Redefinitions
#############
======================================================= ========================================================================
:bro:type:`NetControl::PluginState`: :bro:type:`record` Table for a plugin to store instance-specific configuration information.
======================================================= ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: NetControl::Plugin

   :Type: :bro:type:`record`

      name: :bro:type:`function` (state: :bro:type:`NetControl::PluginState`) : :bro:type:`string`
         Returns a descriptive name of the plugin instance, suitable for use in logging
         messages. Note that this function is not optional.

      can_expire: :bro:type:`bool`
         If true, plugin can expire rules itself. If false, the NetControl
         framework will manage rule expiration. 

      init: :bro:type:`function` (state: :bro:type:`NetControl::PluginState`) : :bro:type:`void` :bro:attr:`&optional`
         One-time initialization function called when plugin gets registered, and
         before any other methods are called.
         
         If this function is provided, NetControl assumes that the plugin has to
         perform, potentially lengthy, initialization before the plugin will become
         active. In this case, the plugin has to call ``NetControl::plugin_activated``,
         once initialization finishes.

      done: :bro:type:`function` (state: :bro:type:`NetControl::PluginState`) : :bro:type:`void` :bro:attr:`&optional`
         One-time finalization function called when a plugin is shutdown; no further
         functions will be called afterwords.

      add_rule: :bro:type:`function` (state: :bro:type:`NetControl::PluginState`, r: :bro:type:`NetControl::Rule`) : :bro:type:`bool` :bro:attr:`&optional`
         Implements the add_rule() operation. If the plugin accepts the rule,
         it returns true, false otherwise. The rule will already have its
         ``id`` field set, which the plugin may use for identification
         purposes.

      remove_rule: :bro:type:`function` (state: :bro:type:`NetControl::PluginState`, r: :bro:type:`NetControl::Rule`, reason: :bro:type:`string`) : :bro:type:`bool` :bro:attr:`&optional`
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

.. bro:type:: NetControl::PluginState

   :Type: :bro:type:`record`

      config: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         Table for a plugin to store custom, instance-specific state.

      _id: :bro:type:`count` :bro:attr:`&optional`
         Unique plugin identifier -- used for backlookup of plugins from Rules. Set internally.

      _priority: :bro:type:`int` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Set internally.

      _activated: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Set internally. Signifies if the plugin has returned that it has activated successfully.

      plugin: :bro:type:`NetControl::Plugin` :bro:attr:`&optional`
         The plugin that the state belongs to. (Defined separately
         because of cyclic type dependency.)

      of_controller: :bro:type:`OpenFlow::Controller` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/openflow.bro` is loaded)

         OpenFlow controller for NetControl OpenFlow plugin.

      of_config: :bro:type:`NetControl::OfConfig` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/openflow.bro` is loaded)

         OpenFlow configuration record that is passed on initialization.

      broker_config: :bro:type:`NetControl::BrokerConfig` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/broker.bro` is loaded)

         OpenFlow controller for NetControl Broker plugin.

      broker_id: :bro:type:`count` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/broker.bro` is loaded)

         The ID of this broker instance - for the mapping to PluginStates.

      acld_config: :bro:type:`NetControl::AcldConfig` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/acld.bro` is loaded)


      acld_id: :bro:type:`count` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/plugins/acld.bro` is loaded)

         The ID of this acld instance - for the mapping to PluginStates.

   This record keeps the per instance state of a plugin.
   
   Individual plugins commonly extend this record to suit their needs.


