:tocdepth: 3

base/frameworks/openflow/main.zeek
==================================
.. bro:namespace:: OpenFlow

Bro's OpenFlow control framework.

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
=========================================================== =============================================================================================
:bro:id:`OpenFlow::controller_activated`: :bro:type:`event` Event that is raised once a controller finishes initialization
                                                            and is completely activated.
:bro:id:`OpenFlow::flow_mod_failure`: :bro:type:`event`     Reports an error while installing a flow Rule.
:bro:id:`OpenFlow::flow_mod_success`: :bro:type:`event`     Event confirming successful modification of a flow rule.
:bro:id:`OpenFlow::flow_removed`: :bro:type:`event`         Reports that a flow was removed by the switch because of either the hard or the idle timeout.
=========================================================== =============================================================================================

Functions
#########
=============================================================== =====================================================================
:bro:id:`OpenFlow::controller_init_done`: :bro:type:`function`  Function to signal that a controller finished activation and is
                                                                ready to use.
:bro:id:`OpenFlow::flow_clear`: :bro:type:`function`            Clear the current flow table of the controller.
:bro:id:`OpenFlow::flow_mod`: :bro:type:`function`              Global flow_mod function.
:bro:id:`OpenFlow::generate_cookie`: :bro:type:`function`       Function to generate a new cookie using our group id.
:bro:id:`OpenFlow::get_cookie_gid`: :bro:type:`function`        Function to get the group id out of a given cookie.
:bro:id:`OpenFlow::get_cookie_uid`: :bro:type:`function`        Function to get the unique id out of a given cookie.
:bro:id:`OpenFlow::lookup_controller`: :bro:type:`function`     Function to lookup a controller instance by name.
:bro:id:`OpenFlow::match_conn`: :bro:type:`function`            Convert a conn_id record into an ofp_match record that can be used to
                                                                create match objects for OpenFlow.
:bro:id:`OpenFlow::register_controller`: :bro:type:`function`   Function to register a controller instance.
:bro:id:`OpenFlow::unregister_controller`: :bro:type:`function` Function to unregister a controller instance.
=============================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: OpenFlow::controller_activated

   :Type: :bro:type:`event` (name: :bro:type:`string`, controller: :bro:type:`OpenFlow::Controller`)

   Event that is raised once a controller finishes initialization
   and is completely activated.

   :name: Unique name of this controller instance.
   

   :controller: The controller that finished activation.

.. bro:id:: OpenFlow::flow_mod_failure

   :Type: :bro:type:`event` (name: :bro:type:`string`, match: :bro:type:`OpenFlow::ofp_match`, flow_mod: :bro:type:`OpenFlow::ofp_flow_mod`, msg: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`)

   Reports an error while installing a flow Rule.
   

   :name: The unique name of the OpenFlow controller from which this event originated.
   

   :match: The ofp_match record which describes the flow to match.
   

   :flow_mod: The openflow flow_mod record which describes the action to take.
   

   :msg: Message to describe the event.

.. bro:id:: OpenFlow::flow_mod_success

   :Type: :bro:type:`event` (name: :bro:type:`string`, match: :bro:type:`OpenFlow::ofp_match`, flow_mod: :bro:type:`OpenFlow::ofp_flow_mod`, msg: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`)

   Event confirming successful modification of a flow rule.
   

   :name: The unique name of the OpenFlow controller from which this event originated.
   

   :match: The ofp_match record which describes the flow to match.
   

   :flow_mod: The openflow flow_mod record which describes the action to take.
   

   :msg: An optional informational message by the plugin.

.. bro:id:: OpenFlow::flow_removed

   :Type: :bro:type:`event` (name: :bro:type:`string`, match: :bro:type:`OpenFlow::ofp_match`, cookie: :bro:type:`count`, priority: :bro:type:`count`, reason: :bro:type:`count`, duration_sec: :bro:type:`count`, idle_timeout: :bro:type:`count`, packet_count: :bro:type:`count`, byte_count: :bro:type:`count`)

   Reports that a flow was removed by the switch because of either the hard or the idle timeout.
   This message is only generated by controllers that indicate that they support flow removal
   in supports_flow_removed.
   

   :name: The unique name of the OpenFlow controller from which this event originated.
   

   :match: The ofp_match record which was used to create the flow.
   

   :cookie: The cookie that was specified when creating the flow.
   

   :priority: The priority that was specified when creating the flow.
   

   :reason: The reason for flow removal (OFPRR_*).
   

   :duration_sec: Duration of the flow in seconds.
   

   :packet_count: Packet count of the flow.
   

   :byte_count: Byte count of the flow.

Functions
#########
.. bro:id:: OpenFlow::controller_init_done

   :Type: :bro:type:`function` (controller: :bro:type:`OpenFlow::Controller`) : :bro:type:`void`

   Function to signal that a controller finished activation and is
   ready to use. Will throw the ``OpenFlow::controller_activated``
   event.

.. bro:id:: OpenFlow::flow_clear

   :Type: :bro:type:`function` (controller: :bro:type:`OpenFlow::Controller`) : :bro:type:`bool`

   Clear the current flow table of the controller.
   

   :controller: The controller which should execute the flow modification.
   

   :returns: F on error or if the plugin does not support the operation, T when the operation was queued.

.. bro:id:: OpenFlow::flow_mod

   :Type: :bro:type:`function` (controller: :bro:type:`OpenFlow::Controller`, match: :bro:type:`OpenFlow::ofp_match`, flow_mod: :bro:type:`OpenFlow::ofp_flow_mod`) : :bro:type:`bool`

   Global flow_mod function.
   

   :controller: The controller which should execute the flow modification.
   

   :match: The ofp_match record which describes the flow to match.
   

   :flow_mod: The openflow flow_mod record which describes the action to take.
   

   :returns: F on error or if the plugin does not support the operation, T when the operation was queued.

.. bro:id:: OpenFlow::generate_cookie

   :Type: :bro:type:`function` (cookie: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`) : :bro:type:`count`

   Function to generate a new cookie using our group id.
   

   :cookie: The openflow match cookie.
   

   :returns: The cookie group id.

.. bro:id:: OpenFlow::get_cookie_gid

   :Type: :bro:type:`function` (cookie: :bro:type:`count`) : :bro:type:`count`

   Function to get the group id out of a given cookie.
   

   :cookie: The openflow match cookie.
   

   :returns: The cookie group id.

.. bro:id:: OpenFlow::get_cookie_uid

   :Type: :bro:type:`function` (cookie: :bro:type:`count`) : :bro:type:`count`

   Function to get the unique id out of a given cookie.
   

   :cookie: The openflow match cookie.
   

   :returns: The cookie unique id.

.. bro:id:: OpenFlow::lookup_controller

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`vector` of :bro:type:`OpenFlow::Controller`

   Function to lookup a controller instance by name.
   

   :name: Unique name of the controller to look up.
   

   :returns: One element vector with controller, if found. Empty vector otherwise.

.. bro:id:: OpenFlow::match_conn

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`, reverse: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`) : :bro:type:`OpenFlow::ofp_match`

   Convert a conn_id record into an ofp_match record that can be used to
   create match objects for OpenFlow.
   

   :id: The conn_id record that describes the record.
   

   :reverse: Reverse the sources and destinations when creating the match record (default F).
   

   :returns: ofp_match object for the conn_id record.

.. bro:id:: OpenFlow::register_controller

   :Type: :bro:type:`function` (tpe: :bro:type:`OpenFlow::Plugin`, name: :bro:type:`string`, controller: :bro:type:`OpenFlow::Controller`) : :bro:type:`void`

   Function to register a controller instance. This function
   is called automatically by the plugin _new functions.
   

   :tpe: Type of this plugin.
   

   :name: Unique name of this controller instance.
   

   :controller: The controller to register.

.. bro:id:: OpenFlow::unregister_controller

   :Type: :bro:type:`function` (controller: :bro:type:`OpenFlow::Controller`) : :bro:type:`void`

   Function to unregister a controller instance. This function
   should be called when a specific controller should no longer
   be used.
   

   :controller: The controller to unregister.


