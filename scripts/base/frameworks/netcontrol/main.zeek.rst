:tocdepth: 3

base/frameworks/netcontrol/main.zeek
====================================
.. bro:namespace:: NetControl

Bro's NetControl framework.

This plugin-based framework allows to control the traffic that Bro monitors
as well as, if having access to the forwarding path, the traffic the network
forwards. By default, the framework lets everything through, to both Bro
itself as well as on the network. Scripts can then add rules to impose
restrictions on entities, such as specific connections or IP addresses.

This framework has two APIs: a high-level and low-level. The high-level API
provides convenience functions for a set of common operations. The
low-level API provides full flexibility.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/plugin.zeek </scripts/base/frameworks/netcontrol/plugin.zeek>`, :doc:`base/frameworks/netcontrol/types.zeek </scripts/base/frameworks/netcontrol/types.zeek>`

Summary
~~~~~~~
Types
#####
====================================================== =================================================================
:bro:type:`NetControl::Info`: :bro:type:`record`       The record type defining the column fields of the NetControl log.
:bro:type:`NetControl::InfoCategory`: :bro:type:`enum` Type of an entry in the NetControl log.
:bro:type:`NetControl::InfoState`: :bro:type:`enum`    State of an entry in the NetControl log.
====================================================== =================================================================

Redefinitions
#############
================================================ ==========================================
:bro:type:`Log::ID`: :bro:type:`enum`            The framework's logging stream identifier.
:bro:type:`NetControl::Rule`: :bro:type:`record` 
================================================ ==========================================

Events
######
======================================================= ===========================================================================
:bro:id:`NetControl::init`: :bro:type:`event`           Event that is used to initialize plugins.
:bro:id:`NetControl::init_done`: :bro:type:`event`      Event that is raised once all plugins activated in ``NetControl::init``
                                                        have finished their initialization.
:bro:id:`NetControl::log_netcontrol`: :bro:type:`event` Event that can be handled to access the :bro:type:`NetControl::Info`
                                                        record as it is sent on to the logging framework.
:bro:id:`NetControl::rule_added`: :bro:type:`event`     Confirms that a rule was put in place by a plugin.
:bro:id:`NetControl::rule_destroyed`: :bro:type:`event` This event is raised when a rule is deleted from the NetControl framework,
                                                        because it is no longer in use.
:bro:id:`NetControl::rule_error`: :bro:type:`event`     Reports an error when operating on a rule.
:bro:id:`NetControl::rule_exists`: :bro:type:`event`    Signals that a rule that was supposed to be put in place was already
                                                        existing at the specified plugin.
:bro:id:`NetControl::rule_new`: :bro:type:`event`       This event is raised when a new rule is created by the NetControl framework
                                                        due to a call to add_rule.
:bro:id:`NetControl::rule_removed`: :bro:type:`event`   Reports that a plugin reports a rule was removed due to a
                                                        remove_rule function call.
:bro:id:`NetControl::rule_timeout`: :bro:type:`event`   Reports that a rule was removed from a plugin due to a timeout.
======================================================= ===========================================================================

Hooks
#####
=================================================== =========================================================================
:bro:id:`NetControl::rule_policy`: :bro:type:`hook` Hook that allows the modification of rules passed to add_rule before they
                                                    are passed on to the plugins.
=================================================== =========================================================================

Functions
#########
============================================================= ==============================================================================================
:bro:id:`NetControl::activate`: :bro:type:`function`          Activates a plugin.
:bro:id:`NetControl::add_rule`: :bro:type:`function`          Installs a rule.
:bro:id:`NetControl::clear`: :bro:type:`function`             Flushes all state by calling :bro:see:`NetControl::remove_rule` on all currently active rules.
:bro:id:`NetControl::delete_rule`: :bro:type:`function`       Deletes a rule without removing it from the backends to which it has been
                                                              added before.
:bro:id:`NetControl::find_rules_addr`: :bro:type:`function`   Searches all rules affecting a certain IP address.
:bro:id:`NetControl::find_rules_subnet`: :bro:type:`function` Searches all rules affecting a certain subnet.
:bro:id:`NetControl::plugin_activated`: :bro:type:`function`  Function called by plugins once they finished their activation.
:bro:id:`NetControl::quarantine_host`: :bro:type:`function`   Quarantines a host.
:bro:id:`NetControl::redirect_flow`: :bro:type:`function`     Redirects a uni-directional flow to another port.
:bro:id:`NetControl::remove_rule`: :bro:type:`function`       Removes a rule.
:bro:id:`NetControl::whitelist_address`: :bro:type:`function` Allows all traffic involving a specific IP address to be forwarded.
:bro:id:`NetControl::whitelist_subnet`: :bro:type:`function`  Allows all traffic involving a specific IP subnet to be forwarded.
============================================================= ==============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: NetControl::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time at which the recorded activity occurred.

      rule_id: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         ID of the rule; unique during each Bro run.

      category: :bro:type:`NetControl::InfoCategory` :bro:attr:`&log` :bro:attr:`&optional`
         Type of the log entry.

      cmd: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The command the log entry is about.

      state: :bro:type:`NetControl::InfoState` :bro:attr:`&log` :bro:attr:`&optional`
         State the log entry reflects.

      action: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         String describing an action the entry is about.

      target: :bro:type:`NetControl::TargetType` :bro:attr:`&log` :bro:attr:`&optional`
         The target type of the action.

      entity_type: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Type of the entity the log entry is about.

      entity: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         String describing the entity the log entry is about.

      mod: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         String describing the optional modification of the entry (e.h. redirect)

      msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         String with an additional message.

      priority: :bro:type:`int` :bro:attr:`&log` :bro:attr:`&optional`
         Number describing the priority of the log entry.

      expire: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         Expiry time of the log entry.

      location: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Location where the underlying action was triggered.

      plugin: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Plugin triggering the log entry.

   The record type defining the column fields of the NetControl log.

.. bro:type:: NetControl::InfoCategory

   :Type: :bro:type:`enum`

      .. bro:enum:: NetControl::MESSAGE NetControl::InfoCategory

         A log entry reflecting a framework message.

      .. bro:enum:: NetControl::ERROR NetControl::InfoCategory

         A log entry reflecting a framework message.

      .. bro:enum:: NetControl::RULE NetControl::InfoCategory

         A log entry about a rule.

   Type of an entry in the NetControl log.

.. bro:type:: NetControl::InfoState

   :Type: :bro:type:`enum`

      .. bro:enum:: NetControl::REQUESTED NetControl::InfoState

         The request to add/remove a rule was sent to the respective backend.

      .. bro:enum:: NetControl::SUCCEEDED NetControl::InfoState

         A rule was successfully added by a backend.

      .. bro:enum:: NetControl::EXISTS NetControl::InfoState

         A backend reported that a rule was already existing.

      .. bro:enum:: NetControl::FAILED NetControl::InfoState

         A rule addition failed.

      .. bro:enum:: NetControl::REMOVED NetControl::InfoState

         A rule was successfully removed by a backend.

      .. bro:enum:: NetControl::TIMEOUT NetControl::InfoState

         A rule timeout was triggered by the NetControl framework or a backend.

   State of an entry in the NetControl log.

Events
######
.. bro:id:: NetControl::init

   :Type: :bro:type:`event` ()

   Event that is used to initialize plugins. Place all plugin initialization
   related functionality in this event.

.. bro:id:: NetControl::init_done

   :Type: :bro:type:`event` ()

   Event that is raised once all plugins activated in ``NetControl::init``
   have finished their initialization.

.. bro:id:: NetControl::log_netcontrol

   :Type: :bro:type:`event` (rec: :bro:type:`NetControl::Info`)

   Event that can be handled to access the :bro:type:`NetControl::Info`
   record as it is sent on to the logging framework.

.. bro:id:: NetControl::rule_added

   :Type: :bro:type:`event` (r: :bro:type:`NetControl::Rule`, p: :bro:type:`NetControl::PluginState`, msg: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`)

   Confirms that a rule was put in place by a plugin.
   

   :r: The rule now in place.
   

   :p: The state for the plugin that put it into place.
   

   :msg: An optional informational message by the plugin.

.. bro:id:: NetControl::rule_destroyed

   :Type: :bro:type:`event` (r: :bro:type:`NetControl::Rule`)

   This event is raised when a rule is deleted from the NetControl framework,
   because it is no longer in use. This can be caused by the fact that a rule
   was removed by all plugins to which it was added, by the fact that it timed out
   or due to rule errors.
   
   To get the cause of a rule remove, catch the rule_removed, rule_timeout and
   rule_error events.

.. bro:id:: NetControl::rule_error

   :Type: :bro:type:`event` (r: :bro:type:`NetControl::Rule`, p: :bro:type:`NetControl::PluginState`, msg: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`)

   Reports an error when operating on a rule.
   

   :r: The rule that encountered an error.
   

   :p: The state for the plugin that reported the error.
   

   :msg: An optional informational message by the plugin.

.. bro:id:: NetControl::rule_exists

   :Type: :bro:type:`event` (r: :bro:type:`NetControl::Rule`, p: :bro:type:`NetControl::PluginState`, msg: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`)

   Signals that a rule that was supposed to be put in place was already
   existing at the specified plugin. Rules that already have been existing
   continue to be tracked like normal, but no timeout calls will be sent
   to the specified plugins. Removal of the rule from the hardware can
   still be forced by manually issuing a remove_rule call.
   

   :r: The rule that was already in place.
   

   :p: The plugin that reported that the rule already was in place.
   

   :msg: An optional informational message by the plugin.

.. bro:id:: NetControl::rule_new

   :Type: :bro:type:`event` (r: :bro:type:`NetControl::Rule`)

   This event is raised when a new rule is created by the NetControl framework
   due to a call to add_rule. From this moment, until the rule_destroyed event
   is raised, the rule is tracked internally by the NetControl framework.
   
   Note that this event does not mean that a rule was successfully added by
   any backend; it just means that the rule has been accepted and addition
   to the specified backend is queued. To get information when rules are actually
   installed by the hardware, use the rule_added, rule_exists, rule_removed, rule_timeout
   and rule_error events.

.. bro:id:: NetControl::rule_removed

   :Type: :bro:type:`event` (r: :bro:type:`NetControl::Rule`, p: :bro:type:`NetControl::PluginState`, msg: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`)

   Reports that a plugin reports a rule was removed due to a
   remove_rule function call.
   

   :r: The rule now removed.
   

   :p: The state for the plugin that had the rule in place and now
      removed it.
   

   :msg: An optional informational message by the plugin.

.. bro:id:: NetControl::rule_timeout

   :Type: :bro:type:`event` (r: :bro:type:`NetControl::Rule`, i: :bro:type:`NetControl::FlowInfo`, p: :bro:type:`NetControl::PluginState`)

   Reports that a rule was removed from a plugin due to a timeout.
   

   :r: The rule now removed.
   

   :i: Additional flow information, if supported by the protocol.
   

   :p: The state for the plugin that had the rule in place and now
      removed it.
   

   :msg: An optional informational message by the plugin.

Hooks
#####
.. bro:id:: NetControl::rule_policy

   :Type: :bro:type:`hook` (r: :bro:type:`NetControl::Rule`) : :bro:type:`bool`

   Hook that allows the modification of rules passed to add_rule before they
   are passed on to the plugins. If one of the hooks uses break, the rule is
   ignored and not passed on to any plugin.
   

   :r: The rule to be added.

Functions
#########
.. bro:id:: NetControl::activate

   :Type: :bro:type:`function` (p: :bro:type:`NetControl::PluginState`, priority: :bro:type:`int`) : :bro:type:`void`

   Activates a plugin.
   

   :p: The plugin to activate.
   

   :priority: The higher the priority, the earlier this plugin will be checked
             whether it supports an operation, relative to other plugins.

.. bro:id:: NetControl::add_rule

   :Type: :bro:type:`function` (r: :bro:type:`NetControl::Rule`) : :bro:type:`string`

   Installs a rule.
   

   :r: The rule to install.
   

   :returns: If successful, returns an ID string unique to the rule that can
            later be used to refer to it. If unsuccessful, returns an empty
            string. The ID is also assigned to ``r$id``. Note that
            "successful" means "a plugin knew how to handle the rule", it
            doesn't necessarily mean that it was indeed successfully put in
            place, because that might happen asynchronously and thus fail
            only later.

.. bro:id:: NetControl::clear

   :Type: :bro:type:`function` () : :bro:type:`void`

   Flushes all state by calling :bro:see:`NetControl::remove_rule` on all currently active rules.

.. bro:id:: NetControl::delete_rule

   :Type: :bro:type:`function` (id: :bro:type:`string`, reason: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`bool`

   Deletes a rule without removing it from the backends to which it has been
   added before. This means that no messages will be sent to the switches to which
   the rule has been added; if it is not removed from them by a separate mechanism,
   it will stay installed and not be removed later.
   

   :id: The rule to delete, specified as the ID returned by :bro:see:`NetControl::add_rule`.
   

   :reason: Optional string argument giving information on why the rule was deleted.
   

   :returns: True if removal is successful, or sent to manager.
            False if the rule could not be found.

.. bro:id:: NetControl::find_rules_addr

   :Type: :bro:type:`function` (ip: :bro:type:`addr`) : :bro:type:`vector` of :bro:type:`NetControl::Rule`

   Searches all rules affecting a certain IP address.
   
   This function works on both the manager and workers of a cluster. Note that on
   the worker, the internal rule variables (starting with _) will not reflect the
   current state.
   

   :ip: The ip address to search for.
   

   :returns: vector of all rules affecting the IP address.

.. bro:id:: NetControl::find_rules_subnet

   :Type: :bro:type:`function` (sn: :bro:type:`subnet`) : :bro:type:`vector` of :bro:type:`NetControl::Rule`

   Searches all rules affecting a certain subnet.
   
   A rule affects a subnet, if it covers the whole subnet. Note especially that
   this function will not reveal all rules that are covered by a subnet.
   
   For example, a search for 192.168.17.0/8 will reveal a rule that exists for
   192.168.0.0/16, since this rule affects the subnet. However, it will not reveal
   a more specific rule for 192.168.17.1/32, which does not directy affect the whole
   subnet.
   
   This function works on both the manager and workers of a cluster. Note that on
   the worker, the internal rule variables (starting with _) will not reflect the
   current state.
   

   :sn: The subnet to search for.
   

   :returns: vector of all rules affecting the subnet.

.. bro:id:: NetControl::plugin_activated

   :Type: :bro:type:`function` (p: :bro:type:`NetControl::PluginState`) : :bro:type:`void`

   Function called by plugins once they finished their activation. After all
   plugins defined in zeek_init finished to activate, rules will start to be sent
   to the plugins. Rules that scripts try to set before the backends are ready
   will be discarded.

.. bro:id:: NetControl::quarantine_host

   :Type: :bro:type:`function` (infected: :bro:type:`addr`, dns: :bro:type:`addr`, quarantine: :bro:type:`addr`, t: :bro:type:`interval`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`vector` of :bro:type:`string`

   Quarantines a host. This requires a special quarantine server, which runs a HTTP server explaining
   the quarantine and a DNS server which resolves all requests to the quarantine server. DNS queries
   from the host to the network DNS server will be rewritten and will be sent to the quarantine server
   instead. Only http communication infected to quarantinehost is allowed. All other network communication
   is blocked.
   

   :infected: the host to quarantine.
   

   :dns: the network dns server.
   

   :quarantine: the quarantine server running a dns and a web server.
   

   :t: how long to leave the quarantine in place.
   

   :returns: Vector of inserted rules on success, empty list on failure.

.. bro:id:: NetControl::redirect_flow

   :Type: :bro:type:`function` (f: :bro:type:`flow_id`, out_port: :bro:type:`count`, t: :bro:type:`interval`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`string`

   Redirects a uni-directional flow to another port.
   

   :f: The flow to redirect.
   

   :out_port: Port to redirect the flow to.
   

   :t: How long to leave the redirect in place, with 0 being indefinitely.
   

   :location: An optional string describing where the redirect was triggered.
   

   :returns: The id of the inserted rule on success and zero on failure.

.. bro:id:: NetControl::remove_rule

   :Type: :bro:type:`function` (id: :bro:type:`string`, reason: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`bool`

   Removes a rule.
   

   :id: The rule to remove, specified as the ID returned by :bro:see:`NetControl::add_rule`.
   

   :reason: Optional string argument giving information on why the rule was removed.
   

   :returns: True if successful, the relevant plugin indicated that it knew
            how to handle the removal. Note that again "success" means the
            plugin accepted the removal. It might still fail to put it
            into effect, as that might happen asynchronously and thus go
            wrong at that point.

.. bro:id:: NetControl::whitelist_address

   :Type: :bro:type:`function` (a: :bro:type:`addr`, t: :bro:type:`interval`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`string`

   Allows all traffic involving a specific IP address to be forwarded.
   

   :a: The address to be whitelisted.
   

   :t: How long to whitelist it, with 0 being indefinitely.
   

   :location: An optional string describing whitelist was triddered.
   

   :returns: The id of the inserted rule on success and zero on failure.

.. bro:id:: NetControl::whitelist_subnet

   :Type: :bro:type:`function` (s: :bro:type:`subnet`, t: :bro:type:`interval`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`string`

   Allows all traffic involving a specific IP subnet to be forwarded.
   

   :s: The subnet to be whitelisted.
   

   :t: How long to whitelist it, with 0 being indefinitely.
   

   :location: An optional string describing whitelist was triddered.
   

   :returns: The id of the inserted rule on success and zero on failure.


