:tocdepth: 3

base/frameworks/netcontrol/main.zeek
====================================
.. zeek:namespace:: NetControl

Zeek's NetControl framework.

This plugin-based framework allows to control the traffic that Zeek monitors
as well as, if having access to the forwarding path, the traffic the network
forwards. By default, the framework lets everything through, to both Zeek
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
======================================================== =================================================================
:zeek:type:`NetControl::Info`: :zeek:type:`record`       The record type defining the column fields of the NetControl log.
:zeek:type:`NetControl::InfoCategory`: :zeek:type:`enum` Type of an entry in the NetControl log.
:zeek:type:`NetControl::InfoState`: :zeek:type:`enum`    State of an entry in the NetControl log.
======================================================== =================================================================

Redefinitions
#############
================================================== ===================================================================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`            The framework's logging stream identifier.

                                                   * :zeek:enum:`NetControl::LOG`
:zeek:type:`NetControl::Rule`: :zeek:type:`record`

                                                   :New Fields: :zeek:type:`NetControl::Rule`

                                                     _plugin_ids: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
                                                       Internally set to the plugins handling the rule.

                                                     _active_plugin_ids: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
                                                       Internally set to the plugins on which the rule is currently active.

                                                     _no_expire_plugins: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
                                                       Internally set to plugins where the rule should not be removed upon timeout.

                                                     _added: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                       Track if the rule was added successfully by all responsible plugins.
================================================== ===================================================================================================================

Events
######
========================================================= ===========================================================================
:zeek:id:`NetControl::init`: :zeek:type:`event`           Event that is used to initialize plugins.
:zeek:id:`NetControl::init_done`: :zeek:type:`event`      Event that is raised once all plugins activated in ``NetControl::init``
                                                          have finished their initialization.
:zeek:id:`NetControl::log_netcontrol`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`NetControl::Info`
                                                          record as it is sent on to the logging framework.
:zeek:id:`NetControl::rule_added`: :zeek:type:`event`     Confirms that a rule was put in place by a plugin.
:zeek:id:`NetControl::rule_destroyed`: :zeek:type:`event` This event is raised when a rule is deleted from the NetControl framework,
                                                          because it is no longer in use.
:zeek:id:`NetControl::rule_error`: :zeek:type:`event`     Reports an error when operating on a rule.
:zeek:id:`NetControl::rule_exists`: :zeek:type:`event`    Signals that a rule that was supposed to be put in place was already
                                                          existing at the specified plugin.
:zeek:id:`NetControl::rule_new`: :zeek:type:`event`       This event is raised when a new rule is created by the NetControl framework
                                                          due to a call to add_rule.
:zeek:id:`NetControl::rule_removed`: :zeek:type:`event`   Reports that a plugin reports a rule was removed due to a
                                                          remove_rule function call.
:zeek:id:`NetControl::rule_timeout`: :zeek:type:`event`   Reports that a rule was removed from a plugin due to a timeout.
========================================================= ===========================================================================

Hooks
#####
=============================================================== =============================================================================
:zeek:id:`NetControl::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
:zeek:id:`NetControl::rule_added_policy`: :zeek:type:`hook`     Hook that allows the modification of rule states after they are returned from
                                                                the plugins and have been added to the rules database.
:zeek:id:`NetControl::rule_policy`: :zeek:type:`hook`           Hook that allows the modification of rules passed to add_rule before they
                                                                are passed on to the plugins.
=============================================================== =============================================================================

Functions
#########
=============================================================== ===============================================================================================
:zeek:id:`NetControl::activate`: :zeek:type:`function`          Activates a plugin.
:zeek:id:`NetControl::add_rule`: :zeek:type:`function`          Installs a rule.
:zeek:id:`NetControl::clear`: :zeek:type:`function`             Flushes all state by calling :zeek:see:`NetControl::remove_rule` on all currently active rules.
:zeek:id:`NetControl::delete_rule`: :zeek:type:`function`       Deletes a rule without removing it from the backends to which it has been
                                                                added before.
:zeek:id:`NetControl::find_rules_addr`: :zeek:type:`function`   Searches all rules affecting a certain IP address.
:zeek:id:`NetControl::find_rules_subnet`: :zeek:type:`function` Searches all rules affecting a certain subnet.
:zeek:id:`NetControl::plugin_activated`: :zeek:type:`function`  Function called by plugins once they finished their activation.
:zeek:id:`NetControl::quarantine_host`: :zeek:type:`function`   Quarantines a host.
:zeek:id:`NetControl::redirect_flow`: :zeek:type:`function`     Redirects a uni-directional flow to another port.
:zeek:id:`NetControl::remove_rule`: :zeek:type:`function`       Removes a rule.
:zeek:id:`NetControl::whitelist_address`: :zeek:type:`function` Allows all traffic involving a specific IP address to be forwarded.
:zeek:id:`NetControl::whitelist_subnet`: :zeek:type:`function`  Allows all traffic involving a specific IP subnet to be forwarded.
=============================================================== ===============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: NetControl::Info
   :source-code: base/frameworks/netcontrol/main.zeek 308 339

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Time at which the recorded activity occurred.


   .. zeek:field:: rule_id :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      ID of the rule; unique during each Zeek run.


   .. zeek:field:: category :zeek:type:`NetControl::InfoCategory` :zeek:attr:`&log` :zeek:attr:`&optional`

      Type of the log entry.


   .. zeek:field:: cmd :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The command the log entry is about.


   .. zeek:field:: state :zeek:type:`NetControl::InfoState` :zeek:attr:`&log` :zeek:attr:`&optional`

      State the log entry reflects.


   .. zeek:field:: action :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      String describing an action the entry is about.


   .. zeek:field:: target :zeek:type:`NetControl::TargetType` :zeek:attr:`&log` :zeek:attr:`&optional`

      The target type of the action.


   .. zeek:field:: entity_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Type of the entity the log entry is about.


   .. zeek:field:: entity :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      String describing the entity the log entry is about.


   .. zeek:field:: mod :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      String describing the optional modification of the entry (e.h. redirect)


   .. zeek:field:: msg :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      String with an additional message.


   .. zeek:field:: priority :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`

      Number describing the priority of the log entry.


   .. zeek:field:: expire :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      Expiry time of the log entry.


   .. zeek:field:: location :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Location where the underlying action was triggered.


   .. zeek:field:: plugin :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Plugin triggering the log entry.


   The record type defining the column fields of the NetControl log.

.. zeek:type:: NetControl::InfoCategory
   :source-code: base/frameworks/netcontrol/main.zeek 288 296

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NetControl::MESSAGE NetControl::InfoCategory

         A log entry reflecting a framework message.

      .. zeek:enum:: NetControl::ERROR NetControl::InfoCategory

         A log entry reflecting a framework message.

      .. zeek:enum:: NetControl::RULE NetControl::InfoCategory

         A log entry about a rule.

   Type of an entry in the NetControl log.

.. zeek:type:: NetControl::InfoState
   :source-code: base/frameworks/netcontrol/main.zeek 298 306

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NetControl::REQUESTED NetControl::InfoState

         The request to add/remove a rule was sent to the respective backend.

      .. zeek:enum:: NetControl::SUCCEEDED NetControl::InfoState

         A rule was successfully added by a backend.

      .. zeek:enum:: NetControl::EXISTS NetControl::InfoState

         A backend reported that a rule was already existing.

      .. zeek:enum:: NetControl::FAILED NetControl::InfoState

         A rule addition failed.

      .. zeek:enum:: NetControl::REMOVED NetControl::InfoState

         A rule was successfully removed by a backend.

      .. zeek:enum:: NetControl::TIMEOUT NetControl::InfoState

         A rule timeout was triggered by the NetControl framework or a backend.

   State of an entry in the NetControl log.

Events
######
.. zeek:id:: NetControl::init
   :source-code: base/frameworks/netcontrol/main.zeek 642 650

   :Type: :zeek:type:`event` ()

   Event that is used to initialize plugins. Place all plugin initialization
   related functionality in this event.

.. zeek:id:: NetControl::init_done
   :source-code: base/frameworks/netcontrol/main.zeek 43 43

   :Type: :zeek:type:`event` ()

   Event that is raised once all plugins activated in ``NetControl::init``
   have finished their initialization.

.. zeek:id:: NetControl::log_netcontrol
   :source-code: base/frameworks/netcontrol/main.zeek 343 343

   :Type: :zeek:type:`event` (rec: :zeek:type:`NetControl::Info`)

   Event that can be handled to access the :zeek:type:`NetControl::Info`
   record as it is sent on to the logging framework.

.. zeek:id:: NetControl::rule_added
   :source-code: base/frameworks/netcontrol/main.zeek 191 191

   :Type: :zeek:type:`event` (r: :zeek:type:`NetControl::Rule`, p: :zeek:type:`NetControl::PluginState`, msg: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)

   Confirms that a rule was put in place by a plugin.


   :param r: The rule now in place.


   :param p: The state for the plugin that put it into place.


   :param msg: An optional informational message by the plugin.

.. zeek:id:: NetControl::rule_destroyed
   :source-code: base/frameworks/netcontrol/main.zeek 256 256

   :Type: :zeek:type:`event` (r: :zeek:type:`NetControl::Rule`)

   This event is raised when a rule is deleted from the NetControl framework,
   because it is no longer in use. This can be caused by the fact that a rule
   was removed by all plugins to which it was added, by the fact that it timed out
   or due to rule errors.

   To get the cause of a rule remove, catch the rule_removed, rule_timeout and
   rule_error events.

.. zeek:id:: NetControl::rule_error
   :source-code: base/frameworks/netcontrol/main.zeek 236 236

   :Type: :zeek:type:`event` (r: :zeek:type:`NetControl::Rule`, p: :zeek:type:`NetControl::PluginState`, msg: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)

   Reports an error when operating on a rule.


   :param r: The rule that encountered an error.


   :param p: The state for the plugin that reported the error.


   :param msg: An optional informational message by the plugin.

.. zeek:id:: NetControl::rule_exists
   :source-code: base/frameworks/netcontrol/main.zeek 204 204

   :Type: :zeek:type:`event` (r: :zeek:type:`NetControl::Rule`, p: :zeek:type:`NetControl::PluginState`, msg: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)

   Signals that a rule that was supposed to be put in place was already
   existing at the specified plugin. Rules that already have been existing
   continue to be tracked like normal, but no timeout calls will be sent
   to the specified plugins. Removal of the rule from the hardware can
   still be forced by manually issuing a remove_rule call.


   :param r: The rule that was already in place.


   :param p: The plugin that reported that the rule already was in place.


   :param msg: An optional informational message by the plugin.

.. zeek:id:: NetControl::rule_new
   :source-code: base/frameworks/netcontrol/main.zeek 247 247

   :Type: :zeek:type:`event` (r: :zeek:type:`NetControl::Rule`)

   This event is raised when a new rule is created by the NetControl framework
   due to a call to add_rule. From this moment, until the rule_destroyed event
   is raised, the rule is tracked internally by the NetControl framework.

   Note that this event does not mean that a rule was successfully added by
   any backend; it just means that the rule has been accepted and addition
   to the specified backend is queued. To get information when rules are actually
   installed by the hardware, use the rule_added, rule_exists, rule_removed, rule_timeout
   and rule_error events.

.. zeek:id:: NetControl::rule_removed
   :source-code: base/frameworks/netcontrol/non-cluster.zeek 47 50

   :Type: :zeek:type:`event` (r: :zeek:type:`NetControl::Rule`, p: :zeek:type:`NetControl::PluginState`, msg: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)

   Reports that a plugin reports a rule was removed due to a
   remove_rule function call.


   :param r: The rule now removed.


   :param p: The state for the plugin that had the rule in place and now
      removed it.


   :param msg: An optional informational message by the plugin.

.. zeek:id:: NetControl::rule_timeout
   :source-code: base/frameworks/netcontrol/main.zeek 227 227

   :Type: :zeek:type:`event` (r: :zeek:type:`NetControl::Rule`, i: :zeek:type:`NetControl::FlowInfo`, p: :zeek:type:`NetControl::PluginState`)

   Reports that a rule was removed from a plugin due to a timeout.


   :param r: The rule now removed.


   :param i: Additional flow information, if supported by the protocol.


   :param p: The state for the plugin that had the rule in place and now
      removed it.


   :param msg: An optional informational message by the plugin.

Hooks
#####
.. zeek:id:: NetControl::log_policy
   :source-code: base/frameworks/netcontrol/main.zeek 23 23

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

.. zeek:id:: NetControl::rule_added_policy
   :source-code: base/frameworks/netcontrol/main.zeek 277 277

   :Type: :zeek:type:`hook` (r: :zeek:type:`NetControl::Rule`, p: :zeek:type:`NetControl::PluginState`, exists: :zeek:type:`bool`, msg: :zeek:type:`string`) : :zeek:type:`bool`

   Hook that allows the modification of rule states after they are returned from
   the plugins and have been added to the rules database. This allows low-level
   modification of the handling of rules like, e.g., changing rule expiration depending
   on context.


   :param r: The rule now in place.


   :param p: The state for the plugin that put it into place.


   :param exists: If the adding plugin flagged the rule as already existing.


   :param msg: An optional informational message by the plugin.

.. zeek:id:: NetControl::rule_policy
   :source-code: base/frameworks/netcontrol/main.zeek 263 263

   :Type: :zeek:type:`hook` (r: :zeek:type:`NetControl::Rule`) : :zeek:type:`bool`

   Hook that allows the modification of rules passed to add_rule before they
   are passed on to the plugins. If one of the hooks uses break, the rule is
   ignored and not passed on to any plugin.


   :param r: The rule to be added.

Functions
#########
.. zeek:id:: NetControl::activate
   :source-code: base/frameworks/netcontrol/non-cluster.zeek 6 9

   :Type: :zeek:type:`function` (p: :zeek:type:`NetControl::PluginState`, priority: :zeek:type:`int`) : :zeek:type:`void`

   Activates a plugin.


   :param p: The plugin to activate.


   :param priority: The higher the priority, the earlier this plugin will be checked
             whether it supports an operation, relative to other plugins.

.. zeek:id:: NetControl::add_rule
   :source-code: base/frameworks/netcontrol/non-cluster.zeek 11 14

   :Type: :zeek:type:`function` (r: :zeek:type:`NetControl::Rule`) : :zeek:type:`string`

   Installs a rule.


   :param r: The rule to install.


   :returns: If successful, returns an ID string unique to the rule that can
            later be used to refer to it. If unsuccessful, returns an empty
            string. The ID is also assigned to ``r$id``. Note that
            "successful" means "a plugin knew how to handle the rule", it
            doesn't necessarily mean that it was indeed successfully put in
            place, because that might happen asynchronously and thus fail
            only later.

.. zeek:id:: NetControl::clear
   :source-code: base/frameworks/netcontrol/main.zeek 1075 1079

   :Type: :zeek:type:`function` () : :zeek:type:`void`

   Flushes all state by calling :zeek:see:`NetControl::remove_rule` on all currently active rules.

.. zeek:id:: NetControl::delete_rule
   :source-code: base/frameworks/netcontrol/non-cluster.zeek 16 19

   :Type: :zeek:type:`function` (id: :zeek:type:`string`, reason: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Deletes a rule without removing it from the backends to which it has been
   added before. This means that no messages will be sent to the switches to which
   the rule has been added; if it is not removed from them by a separate mechanism,
   it will stay installed and not be removed later.


   :param id: The rule to delete, specified as the ID returned by :zeek:see:`NetControl::add_rule`.


   :param reason: Optional string argument giving information on why the rule was deleted.


   :returns: True if removal is successful, or sent to manager.
            False if the rule could not be found.

.. zeek:id:: NetControl::find_rules_addr
   :source-code: base/frameworks/netcontrol/main.zeek 763 766

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`) : :zeek:type:`vector` of :zeek:type:`NetControl::Rule`

   Searches all rules affecting a certain IP address.

   This function works on both the manager and workers of a cluster. Note that on
   the worker, the internal rule variables (starting with _) will not reflect the
   current state.


   :param ip: The ip address to search for.


   :returns: vector of all rules affecting the IP address.

.. zeek:id:: NetControl::find_rules_subnet
   :source-code: base/frameworks/netcontrol/main.zeek 741 761

   :Type: :zeek:type:`function` (sn: :zeek:type:`subnet`) : :zeek:type:`vector` of :zeek:type:`NetControl::Rule`

   Searches all rules affecting a certain subnet.

   A rule affects a subnet, if it covers the whole subnet. Note especially that
   this function will not reveal all rules that are covered by a subnet.

   For example, a search for 192.168.17.0/8 will reveal a rule that exists for
   192.168.0.0/16, since this rule affects the subnet. However, it will not reveal
   a more specific rule for 192.168.17.1/32, which does not directly affect the whole
   subnet.

   This function works on both the manager and workers of a cluster. Note that on
   the worker, the internal rule variables (starting with _) will not reflect the
   current state.


   :param sn: The subnet to search for.


   :returns: vector of all rules affecting the subnet.

.. zeek:id:: NetControl::plugin_activated
   :source-code: base/frameworks/netcontrol/main.zeek 617 635

   :Type: :zeek:type:`function` (p: :zeek:type:`NetControl::PluginState`) : :zeek:type:`void`

   Function called by plugins once they finished their activation. After all
   plugins defined in zeek_init finished to activate, rules will start to be sent
   to the plugins. Rules that scripts try to set before the backends are ready
   will be discarded.

.. zeek:id:: NetControl::quarantine_host
   :source-code: base/frameworks/netcontrol/main.zeek 570 590

   :Type: :zeek:type:`function` (infected: :zeek:type:`addr`, dns: :zeek:type:`addr`, quarantine: :zeek:type:`addr`, t: :zeek:type:`interval`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`vector` of :zeek:type:`string`

   Quarantines a host. This requires a special quarantine server, which runs a HTTP server explaining
   the quarantine and a DNS server which resolves all requests to the quarantine server. DNS queries
   from the host to the network DNS server will be rewritten and will be sent to the quarantine server
   instead. Only http communication infected to quarantinehost is allowed. All other network communication
   is blocked.


   :param infected: the host to quarantine.


   :param dns: the network dns server.


   :param quarantine: the quarantine server running a dns and a web server.


   :param t: how long to leave the quarantine in place.


   :returns: Vector of inserted rules on success, empty list on failure.

.. zeek:id:: NetControl::redirect_flow
   :source-code: base/frameworks/netcontrol/main.zeek 556 568

   :Type: :zeek:type:`function` (f: :zeek:type:`flow_id`, out_port: :zeek:type:`count`, t: :zeek:type:`interval`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Redirects a uni-directional flow to another port.


   :param f: The flow to redirect.


   :param out_port: Port to redirect the flow to.


   :param t: How long to leave the redirect in place, with 0 being indefinitely.


   :param location: An optional string describing where the redirect was triggered.


   :returns: The id of the inserted rule on success and zero on failure.

.. zeek:id:: NetControl::remove_rule
   :source-code: base/frameworks/netcontrol/non-cluster.zeek 21 24

   :Type: :zeek:type:`function` (id: :zeek:type:`string`, reason: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Removes a rule.


   :param id: The rule to remove, specified as the ID returned by :zeek:see:`NetControl::add_rule`.


   :param reason: Optional string argument giving information on why the rule was removed.


   :returns: True if successful, the relevant plugin indicated that it knew
            how to handle the removal. Note that again "success" means the
            plugin accepted the removal. It might still fail to put it
            into effect, as that might happen asynchronously and thus go
            wrong at that point.

.. zeek:id:: NetControl::whitelist_address
   :source-code: base/frameworks/netcontrol/main.zeek 539 545

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, t: :zeek:type:`interval`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Allows all traffic involving a specific IP address to be forwarded.


   :param a: The address to be whitelisted.


   :param t: How long to whitelist it, with 0 being indefinitely.


   :param location: An optional string describing whitelist was triggered.


   :returns: The id of the inserted rule on success and zero on failure.

.. zeek:id:: NetControl::whitelist_subnet
   :source-code: base/frameworks/netcontrol/main.zeek 547 553

   :Type: :zeek:type:`function` (s: :zeek:type:`subnet`, t: :zeek:type:`interval`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Allows all traffic involving a specific IP subnet to be forwarded.


   :param s: The subnet to be whitelisted.


   :param t: How long to whitelist it, with 0 being indefinitely.


   :param location: An optional string describing whitelist was triggered.


   :returns: The id of the inserted rule on success and zero on failure.


