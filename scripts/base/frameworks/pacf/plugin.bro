
module Pacf;

@load ./types

export {
	## State for a plugin instance.
	type PluginState: record {
		## Table for a plugin to store custom, instance-specfific state. 
		config: table[string] of string &default=table();

		## Unique plugin identifier -- used for backlookup of plugins from Rules. Set internally.
		_id: count &optional;

		## Set internally.
		_priority: int &default=+0;
	};

	# Definition of a plugin.
	#
	# Generally a plugin needs to implement only what it can support.  By
	# returning failure, it indicates that it can't support something and the
	# the framework will then try another plugin, if available; or informn the
	# that the operation failed. If a function isn't implemented by a plugin,
	# that's considered an implicit failure to support the operation.
	#
	# If plugin accepts a rule operation, it *must* generate one of the reporting
	# events ``rule_{added,remove,error}`` to signal if it indeed worked out;
	# this is separate from accepting the operation because often a plugin
	# will only know later (i.e., asynchrously) if that was an error for
	# something it thought it could handle.
	type Plugin: record {
		# Returns a descriptive name of the plugin instance, suitable for use in logging
		# messages. Note that this function is not optional.
		name: function(state: PluginState) : string;

		## If true, plugin can expire rules itself. If false,
		## framework will manage rule expiration. 
		can_expire: bool;

		# One-time initialization function called when plugin gets registered, and
		# before any other methods are called.
		init: function(state: PluginState) &optional;

		# One-time finalization function called when a plugin is shutdown; no further
		# functions will be called afterwords.
		done: function(state: PluginState) &optional;

		# Implements the add_rule() operation. If the plugin accepts the rule,
		# it returns true, false otherwise. The rule will already have its
		# ``id`` field set, which the plugin may use for identification
		# purposes.
		add_rule: function(state: PluginState, r: Rule) : bool &optional;

		# Implements the remove_rule() operation. This will only be called for
		# rules that the plugins has previously accepted with add_rule(). The
		# ``id`` field will match that of the add_rule() call.  Generally,
		# a plugin that accepts an add_rule() should also accept the
		# remove_rule().
		remove_rule: function(state: PluginState, r: Rule) : bool &optional;

		# A transaction groups a number of operations. The plugin can add them internally
		# and postpone putting them into effect until committed. This allows to build a
		# configuration of multiple rules at once, including replaying a previous state.
		transaction_begin: function(state: PluginState) &optional;
		transaction_end: function(state: PluginState) &optional;
	};

	# Table for a plugin to store instance-specific configuration information.
	#
	# Note, it would be nicer to pass the Plugin instance to all the below, instead
	# of this state table. However Bro's type resolver has trouble with refering to a
	# record type from inside itself.
	redef record PluginState += {
		## The plugin that the state belongs to. (Defined separately
		## because of cyclic type dependency.)
		plugin: Plugin &optional &weaken;
	};

}
