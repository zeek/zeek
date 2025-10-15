:tocdepth: 3

base/frameworks/openflow/main.zeek
==================================
.. zeek:namespace:: OpenFlow

Zeek's OpenFlow control framework.

This plugin-based framework allows to control OpenFlow capable
switches by implementing communication to an OpenFlow controller
via plugins. The framework has to be instantiated via the new function
in one of the plugins. This framework only offers very low-level
functionality; if you want to use OpenFlow capable switches, e.g.,
for shunting, please look at the NetControl framework, which provides higher
level functions and can use the OpenFlow framework as a backend.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/openflow/consts.zeek </scripts/base/frameworks/openflow/consts.zeek>`, :doc:`base/frameworks/openflow/types.zeek </scripts/base/frameworks/openflow/types.zeek>`

Summary
~~~~~~~
Events
######
============================================================= =============================================================================================
:zeek:id:`OpenFlow::controller_activated`: :zeek:type:`event` Event that is raised once a controller finishes initialization
                                                              and is completely activated.
:zeek:id:`OpenFlow::flow_mod_failure`: :zeek:type:`event`     Reports an error while installing a flow Rule.
:zeek:id:`OpenFlow::flow_mod_success`: :zeek:type:`event`     Event confirming successful modification of a flow rule.
:zeek:id:`OpenFlow::flow_removed`: :zeek:type:`event`         Reports that a flow was removed by the switch because of either the hard or the idle timeout.
============================================================= =============================================================================================

Functions
#########
================================================================= =====================================================================
:zeek:id:`OpenFlow::controller_init_done`: :zeek:type:`function`  Function to signal that a controller finished activation and is
                                                                  ready to use.
:zeek:id:`OpenFlow::flow_clear`: :zeek:type:`function`            Clear the current flow table of the controller.
:zeek:id:`OpenFlow::flow_mod`: :zeek:type:`function`              Global flow_mod function.
:zeek:id:`OpenFlow::generate_cookie`: :zeek:type:`function`       Function to generate a new cookie using our group id.
:zeek:id:`OpenFlow::get_cookie_gid`: :zeek:type:`function`        Function to get the group id out of a given cookie.
:zeek:id:`OpenFlow::get_cookie_uid`: :zeek:type:`function`        Function to get the unique id out of a given cookie.
:zeek:id:`OpenFlow::lookup_controller`: :zeek:type:`function`     Function to lookup a controller instance by name.
:zeek:id:`OpenFlow::match_conn`: :zeek:type:`function`            Convert a conn_id record into an ofp_match record that can be used to
                                                                  create match objects for OpenFlow.
:zeek:id:`OpenFlow::register_controller`: :zeek:type:`function`   Function to register a controller instance.
:zeek:id:`OpenFlow::unregister_controller`: :zeek:type:`function` Function to unregister a controller instance.
================================================================= =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: OpenFlow::controller_activated
   :source-code: base/frameworks/netcontrol/plugins/openflow.zeek 433 437

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, controller: :zeek:type:`OpenFlow::Controller`)

   Event that is raised once a controller finishes initialization
   and is completely activated.

   :param name: Unique name of this controller instance.
   

   :param controller: The controller that finished activation.

.. zeek:id:: OpenFlow::flow_mod_failure
   :source-code: base/frameworks/netcontrol/plugins/openflow.zeek 383 394

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, match: :zeek:type:`OpenFlow::ofp_match`, flow_mod: :zeek:type:`OpenFlow::ofp_flow_mod`, msg: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)

   Reports an error while installing a flow Rule.
   

   :param name: The unique name of the OpenFlow controller from which this event originated.
   

   :param match: The ofp_match record which describes the flow to match.
   

   :param flow_mod: The openflow flow_mod record which describes the action to take.
   

   :param msg: Message to describe the event.

.. zeek:id:: OpenFlow::flow_mod_success
   :source-code: base/frameworks/netcontrol/plugins/openflow.zeek 356 381

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, match: :zeek:type:`OpenFlow::ofp_match`, flow_mod: :zeek:type:`OpenFlow::ofp_flow_mod`, msg: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)

   Event confirming successful modification of a flow rule.
   

   :param name: The unique name of the OpenFlow controller from which this event originated.
   

   :param match: The ofp_match record which describes the flow to match.
   

   :param flow_mod: The openflow flow_mod record which describes the action to take.
   

   :param msg: An optional informational message by the plugin.

.. zeek:id:: OpenFlow::flow_removed
   :source-code: base/frameworks/netcontrol/plugins/openflow.zeek 396 418

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, match: :zeek:type:`OpenFlow::ofp_match`, cookie: :zeek:type:`count`, priority: :zeek:type:`count`, reason: :zeek:type:`count`, duration_sec: :zeek:type:`count`, idle_timeout: :zeek:type:`count`, packet_count: :zeek:type:`count`, byte_count: :zeek:type:`count`)

   Reports that a flow was removed by the switch because of either the hard or the idle timeout.
   This message is only generated by controllers that indicate that they support flow removal
   in supports_flow_removed.
   

   :param name: The unique name of the OpenFlow controller from which this event originated.
   

   :param match: The ofp_match record which was used to create the flow.
   

   :param cookie: The cookie that was specified when creating the flow.
   

   :param priority: The priority that was specified when creating the flow.
   

   :param reason: The reason for flow removal (OFPRR_*).
   

   :param duration_sec: Duration of the flow in seconds.
   

   :param packet_count: Packet count of the flow.
   

   :param byte_count: Byte count of the flow.

Functions
#########
.. zeek:id:: OpenFlow::controller_init_done
   :source-code: base/frameworks/openflow/main.zeek 242 252

   :Type: :zeek:type:`function` (controller: :zeek:type:`OpenFlow::Controller`) : :zeek:type:`void`

   Function to signal that a controller finished activation and is
   ready to use. Will throw the ``OpenFlow::controller_activated``
   event.

.. zeek:id:: OpenFlow::flow_clear
   :source-code: base/frameworks/openflow/non-cluster.zeek 17 26

   :Type: :zeek:type:`function` (controller: :zeek:type:`OpenFlow::Controller`) : :zeek:type:`bool`

   Clear the current flow table of the controller.
   

   :param controller: The controller which should execute the flow modification.
   

   :returns: F on error or if the plugin does not support the operation, T when the operation was queued.

.. zeek:id:: OpenFlow::flow_mod
   :source-code: base/frameworks/openflow/non-cluster.zeek 6 15

   :Type: :zeek:type:`function` (controller: :zeek:type:`OpenFlow::Controller`, match: :zeek:type:`OpenFlow::ofp_match`, flow_mod: :zeek:type:`OpenFlow::ofp_flow_mod`) : :zeek:type:`bool`

   Global flow_mod function.
   

   :param controller: The controller which should execute the flow modification.
   

   :param match: The ofp_match record which describes the flow to match.
   

   :param flow_mod: The openflow flow_mod record which describes the action to take.
   

   :returns: F on error or if the plugin does not support the operation, T when the operation was queued.

.. zeek:id:: OpenFlow::generate_cookie
   :source-code: base/frameworks/openflow/main.zeek 199 209

   :Type: :zeek:type:`function` (cookie: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`) : :zeek:type:`count`

   Function to generate a new cookie using our group id.
   

   :param cookie: The openflow match cookie.
   

   :returns: The cookie group id.

.. zeek:id:: OpenFlow::get_cookie_gid
   :source-code: base/frameworks/openflow/main.zeek 230 240

   :Type: :zeek:type:`function` (cookie: :zeek:type:`count`) : :zeek:type:`count`

   Function to get the group id out of a given cookie.
   

   :param cookie: The openflow match cookie.
   

   :returns: The cookie group id.

.. zeek:id:: OpenFlow::get_cookie_uid
   :source-code: base/frameworks/openflow/main.zeek 222 228

   :Type: :zeek:type:`function` (cookie: :zeek:type:`count`) : :zeek:type:`count`

   Function to get the unique id out of a given cookie.
   

   :param cookie: The openflow match cookie.
   

   :returns: The cookie unique id.

.. zeek:id:: OpenFlow::lookup_controller
   :source-code: base/frameworks/openflow/non-cluster.zeek 41 44

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`vector` of :zeek:type:`OpenFlow::Controller`

   Function to lookup a controller instance by name.
   

   :param name: Unique name of the controller to look up.
   

   :returns: One element vector with controller, if found. Empty vector otherwise.

.. zeek:id:: OpenFlow::match_conn
   :source-code: base/frameworks/openflow/main.zeek 153 194

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`, reverse: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`OpenFlow::ofp_match`

   Convert a conn_id record into an ofp_match record that can be used to
   create match objects for OpenFlow.
   

   :param id: The conn_id record that describes the record.
   

   :param reverse: Reverse the sources and destinations when creating the match record (default F).
   

   :returns: ofp_match object for the conn_id record.

.. zeek:id:: OpenFlow::register_controller
   :source-code: base/frameworks/openflow/non-cluster.zeek 28 34

   :Type: :zeek:type:`function` (tpe: :zeek:type:`OpenFlow::Plugin`, name: :zeek:type:`string`, controller: :zeek:type:`OpenFlow::Controller`) : :zeek:type:`void`

   Function to register a controller instance. This function
   is called automatically by the plugin _new functions.
   

   :param tpe: Type of this plugin.
   

   :param name: Unique name of this controller instance.
   

   :param controller: The controller to register.

.. zeek:id:: OpenFlow::unregister_controller
   :source-code: base/frameworks/openflow/non-cluster.zeek 36 39

   :Type: :zeek:type:`function` (controller: :zeek:type:`OpenFlow::Controller`) : :zeek:type:`void`

   Function to unregister a controller instance. This function
   should be called when a specific controller should no longer
   be used.
   

   :param controller: The controller to unregister.


