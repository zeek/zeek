##! This file defines the plugin interface for NetControl.

@load ./types

module NetControl;

export {
	## This record keeps the per instance state of a plugin.
	##
	## Individual plugins commonly extend this record to suit their needs.
	type PluginState: record {
		## Table for a plugin to store custom, instance-specific state.
		config: table[string] of string &default=table();

		## Unique plugin identifier -- used for backlookup of plugins from Rules. Set internally.
		_id: count &optional;

		## Set internally.
		_priority: int &default=+0;

		## Set internally. Signifies if the plugin has returned that it has activated successfully.
		_activated: bool &default=F;
	};

	## Definition of a plugin.
	##
	## Generally a plugin needs to implement only what it can support.  By
	## returning failure, it indicates that it can't support something and
	## the framework will then try another plugin, if available; or inform the
	## that the operation failed. If a function isn't implemented by a plugin,
	## that's considered an implicit failure to support the operation.
	##
	## If plugin accepts a rule operation, it *must* generate one of the reporting
	## events ``rule_{added,remove,error}`` to signal if it indeed worked out;
	## this is separate from accepting the operation because often a plugin
	## will only know later (i.e., asynchronously) if that was an error for
	## something it thought it could handle.
	type Plugin: record {
		## Returns a descriptive name of the plugin instance, suitable for use in logging
		## messages. Note that this function is not optional.
		name: function(state: PluginState) : string;

		## If true, plugin can expire rules itself. If false, the NetControl
		## framework will manage rule expiration.
		can_expire: bool;

		## One-time initialization function called when plugin gets registered, and
		## before any other methods are called.
		##
		## If this function is provided, NetControl assumes that the plugin has to
		## perform, potentially lengthy, initialization before the plugin will become
		## active. In this case, the plugin has to call ``NetControl::plugin_activated``,
		## once initialization finishes.
		init: function(state: PluginState) &optional;

		## One-time finalization function called when a plugin is shutdown; no further
		## functions will be called afterwards.
		done: function(state: PluginState) &optional;

		## Implements the add_rule() operation. If the plugin accepts the rule,
		## it returns true, false otherwise. The rule will already have its
		## ``id`` field set, which the plugin may use for identification
		## purposes.
		add_rule: function(state: PluginState, r: Rule) : bool &optional;

		## Implements the remove_rule() operation. This will only be called for
		## rules that the plugin has previously accepted with add_rule(). The
		## ``id`` field will match that of the add_rule() call.  Generally,
		## a plugin that accepts an add_rule() should also accept the
		## remove_rule().
		remove_rule: function(state: PluginState, r: Rule, reason: string) : bool &optional;
	};

	## Table for a plugin to store instance-specific configuration information.
	##
	## Note, it would be nicer to pass the Plugin instance to all the below, instead
	## of this state table. However Zeek's type resolver has trouble with referring to a
	## record type from inside itself.
	redef record PluginState += {
		## The plugin that the state belongs to. (Defined separately
		## because of cyclic type dependency.)
		plugin: Plugin &optional;
	};

}
