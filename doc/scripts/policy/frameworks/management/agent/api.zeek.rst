:tocdepth: 3

policy/frameworks/management/agent/api.zeek
===========================================
.. zeek:namespace:: Management::Agent::API

The event API of cluster agents. Most endpoints consist of event pairs,
where the agent answers a request event with a corresponding response
event. Such event pairs share the same name prefix and end in "_request" and
"_response", respectively.

:Namespace: Management::Agent::API
:Imports: :doc:`base/frameworks/supervisor/control.zeek </scripts/base/frameworks/supervisor/control.zeek>`, :doc:`policy/frameworks/management/types.zeek </scripts/policy/frameworks/management/types.zeek>`

Summary
~~~~~~~
Constants
#########
============================================================== ================================================================
:zeek:id:`Management::Agent::API::version`: :zeek:type:`count` A simple versioning scheme, used to track basic compatibility of
                                                               controller and agent.
============================================================== ================================================================

Events
######
============================================================================= =====================================================================
:zeek:id:`Management::Agent::API::agent_standby_request`: :zeek:type:`event`  The controller sends this event to convey that the agent is not
                                                                              currently required.
:zeek:id:`Management::Agent::API::agent_standby_response`: :zeek:type:`event` Response to a
                                                                              :zeek:see:`Management::Agent::API::agent_standby_request` event.
:zeek:id:`Management::Agent::API::agent_welcome_request`: :zeek:type:`event`  The controller sends this event to confirm to the agent that it is
                                                                              part of the current cluster topology.
:zeek:id:`Management::Agent::API::agent_welcome_response`: :zeek:type:`event` Response to a
                                                                              :zeek:see:`Management::Agent::API::agent_welcome_request` event.
:zeek:id:`Management::Agent::API::deploy_request`: :zeek:type:`event`         The controller sends this event to deploy a cluster configuration to
                                                                              this instance.
:zeek:id:`Management::Agent::API::deploy_response`: :zeek:type:`event`        Response to a :zeek:see:`Management::Agent::API::deploy_request`
                                                                              event.
:zeek:id:`Management::Agent::API::get_nodes_request`: :zeek:type:`event`      The controller sends this event to request a list of
                                                                              :zeek:see:`Management::NodeStatus` records that capture
                                                                              the status of Supervisor-managed nodes running on this instance.
:zeek:id:`Management::Agent::API::get_nodes_response`: :zeek:type:`event`     Response to a :zeek:see:`Management::Agent::API::get_nodes_request`
                                                                              event.
:zeek:id:`Management::Agent::API::node_dispatch_request`: :zeek:type:`event`  The controller sends this to every agent to request a dispatch (the
                                                                              execution of a pre-implemented activity) to all cluster nodes.
:zeek:id:`Management::Agent::API::node_dispatch_response`: :zeek:type:`event` Response to a
                                                                              :zeek:see:`Management::Agent::API::node_dispatch_request` event.
:zeek:id:`Management::Agent::API::notify_agent_hello`: :zeek:type:`event`     The agent sends this event upon peering as a "check-in", informing
                                                                              the controller that an agent of the given name is now available to
                                                                              communicate with.
:zeek:id:`Management::Agent::API::notify_change`: :zeek:type:`event`
:zeek:id:`Management::Agent::API::notify_error`: :zeek:type:`event`
:zeek:id:`Management::Agent::API::notify_log`: :zeek:type:`event`
:zeek:id:`Management::Agent::API::restart_request`: :zeek:type:`event`        The controller sends this event to ask the agent to restart currently
                                                                              running Zeek cluster nodes.
:zeek:id:`Management::Agent::API::restart_response`: :zeek:type:`event`       Response to a :zeek:see:`Management::Agent::API::restart_request`
                                                                              event.
============================================================================= =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: Management::Agent::API::version
   :source-code: policy/frameworks/management/agent/api.zeek 14 14

   :Type: :zeek:type:`count`
   :Default: ``1``

   A simple versioning scheme, used to track basic compatibility of
   controller and agent.

Events
######
.. zeek:id:: Management::Agent::API::agent_standby_request
   :source-code: policy/frameworks/management/agent/main.zeek 871 890

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   The controller sends this event to convey that the agent is not
   currently required. This status may later change, depending on
   updates from the client, so the Broker-level peering can remain
   active. The agent releases any cluster-related resources (including
   shutdown of existing Zeek cluster nodes) when processing the request,
   and confirms via the response event. Shutting down an agent at this
   point has no operational impact on the running cluster.


   :param reqid: a request identifier string, echoed in the response event.


.. zeek:id:: Management::Agent::API::agent_standby_response
   :source-code: policy/frameworks/management/agent/api.zeek 150 150

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`Management::Result`)

   Response to a
   :zeek:see:`Management::Agent::API::agent_standby_request` event. The
   agent sends this back to the controller.


   :param reqid: the request identifier used in the request event.


   :param result: the result record.


.. zeek:id:: Management::Agent::API::agent_welcome_request
   :source-code: policy/frameworks/management/agent/main.zeek 857 869

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   The controller sends this event to confirm to the agent that it is
   part of the current cluster topology. The agent acknowledges with a
   :zeek:see:`Management::Agent::API::agent_welcome_response` event,
   upon which the controller may proceed with a cluster deployment to
   this agent.


   :param reqid: a request identifier string, echoed in the response event.


.. zeek:id:: Management::Agent::API::agent_welcome_response
   :source-code: policy/frameworks/management/controller/main.zeek 900 926

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`Management::Result`)

   Response to a
   :zeek:see:`Management::Agent::API::agent_welcome_request` event. The
   agent sends this back to the controller.


   :param reqid: the request identifier used in the request event.


   :param result: the result record.


.. zeek:id:: Management::Agent::API::deploy_request
   :source-code: policy/frameworks/management/agent/main.zeek 411 451

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, config: :zeek:type:`Management::Configuration`, force: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`)

   The controller sends this event to deploy a cluster configuration to
   this instance. Once processed, the agent responds with a
   :zeek:see:`Management::Agent::API::deploy_response` event.  event.


   :param reqid: a request identifier string, echoed in the response event.


   :param config: a :zeek:see:`Management::Configuration` record describing the
       cluster topology. This contains the full topology, not just the
       part pertaining to this instance: the cluster framework requires
       full cluster visibility to establish needed peerings.


   :param force: whether to re-deploy (i.e., restart its Zeek cluster nodes)
       when the agent already runs this configuration. This relies on
       the config ID to determine config equality.


.. zeek:id:: Management::Agent::API::deploy_response
   :source-code: policy/frameworks/management/controller/main.zeek 944 1000

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, results: :zeek:type:`Management::ResultVec`)

   Response to a :zeek:see:`Management::Agent::API::deploy_request`
   event. The agent sends this back to the controller.


   :param reqid: the request identifier used in the request event.


   :param results: A vector of :zeek:see:`Management::Result` records, each
       capturing the outcome of a single launched node. For failing
       nodes, the result's data field is a
       :zeek:see:`Management::NodeOutputs` record.


.. zeek:id:: Management::Agent::API::get_nodes_request
   :source-code: policy/frameworks/management/agent/main.zeek 588 597

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   The controller sends this event to request a list of
   :zeek:see:`Management::NodeStatus` records that capture
   the status of Supervisor-managed nodes running on this instance.
   instances.


   :param reqid: a request identifier string, echoed in the response event.


.. zeek:id:: Management::Agent::API::get_nodes_response
   :source-code: policy/frameworks/management/controller/main.zeek 1153 1197

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`Management::Result`)

   Response to a :zeek:see:`Management::Agent::API::get_nodes_request`
   event. The agent sends this back to the controller.


   :param reqid: the request identifier used in the request event.


   :param result: a :zeek:see:`Management::Result` record. Its data
       member is a vector of :zeek:see:`Management::NodeStatus`
       records, covering the nodes at this instance. The result may also
       indicate failure, with error messages indicating what went wrong.


.. zeek:id:: Management::Agent::API::node_dispatch_request
   :source-code: policy/frameworks/management/agent/main.zeek 761 855

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, action: :zeek:type:`vector` of :zeek:type:`string`, nodes: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`)

   The controller sends this to every agent to request a dispatch (the
   execution of a pre-implemented activity) to all cluster nodes.  This
   is the generic controller-agent "back-end" implementation of explicit
   client-controller "front-end" interactions, including:

   - :zeek:see:`Management::Controller::API::get_id_value_request`: two
     arguments, the first being "get_id_value" and the second the name
     of the ID to look up.


   :param reqid: a request identifier string, echoed in the response event.


   :param action: the requested dispatch command, with any arguments.


   :param nodes: a set of cluster node names (e.g. "worker-01") to retrieve
      the values from. An empty set, supplied by default, means
      retrieval from all nodes managed by the agent.


.. zeek:id:: Management::Agent::API::node_dispatch_response
   :source-code: policy/frameworks/management/controller/main.zeek 1230 1295

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, results: :zeek:type:`Management::ResultVec`)

   Response to a
   :zeek:see:`Management::Agent::API::node_dispatch_request` event. Each
   agent sends this back to the controller to report the dispatch
   outcomes on all nodes managed by that agent.


   :param reqid: the request identifier used in the request event.


   :param results: a :zeek:type:`vector` of :zeek:see:`Management::Result`
       records. Each record covers one Zeek cluster node managed by this
       agent. Upon success, each :zeek:see:`Management::Result` record's
       data member contains the dispatches' response in a data type
       appropriate for the respective dispatch.


.. zeek:id:: Management::Agent::API::notify_agent_hello
   :source-code: policy/frameworks/management/controller/main.zeek 835 898

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, id: :zeek:type:`string`, connecting: :zeek:type:`bool`, api_version: :zeek:type:`count`)

   The agent sends this event upon peering as a "check-in", informing
   the controller that an agent of the given name is now available to
   communicate with. It is a controller-level equivalent of
   :zeek:see:`Broker::peer_added` and triggered by it.


   :param instance: an instance name, really the agent's name as per
      :zeek:see:`Management::Agent::get_name`.


   :param id: the Broker ID of the agent.


   :param connecting: true if this agent connected to the controller,
      false if the controller connected to the agent.


   :param api_version: the API version of this agent.


.. zeek:id:: Management::Agent::API::notify_change
   :source-code: policy/frameworks/management/controller/main.zeek 929 930

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, n: :zeek:type:`Management::Node`, old: :zeek:type:`Management::State`, new: :zeek:type:`Management::State`)


.. zeek:id:: Management::Agent::API::notify_error
   :source-code: policy/frameworks/management/controller/main.zeek 934 935

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, msg: :zeek:type:`string`, node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)


.. zeek:id:: Management::Agent::API::notify_log
   :source-code: policy/frameworks/management/controller/main.zeek 939 940

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, msg: :zeek:type:`string`, node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)


.. zeek:id:: Management::Agent::API::restart_request
   :source-code: policy/frameworks/management/agent/main.zeek 934 1008

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, nodes: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`)

   The controller sends this event to ask the agent to restart currently
   running Zeek cluster nodes. For nodes currently running, the agent
   places these nodes into PENDING state and sends restart events to the
   Supervisor, rendering its responses into a list of
   :zeek:see:`Management::Result` records summarizing each node restart.
   When restarted nodes check in with the agent, they switch back to
   RUNNING state. The agent ignores nodes not currently running.


   :param reqid: a request identifier string, echoed in the response event.


   :param nodes: a set of cluster node names (e.g. "worker-01") to restart. An
      empty set, supplied by default, means restart of all of the
      agent's current cluster nodes.


.. zeek:id:: Management::Agent::API::restart_response
   :source-code: policy/frameworks/management/controller/main.zeek 1376 1414

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, results: :zeek:type:`Management::ResultVec`)

   Response to a :zeek:see:`Management::Agent::API::restart_request`
   event. The agent sends this back to the controller when the
   Supervisor has restarted all nodes affected, or a timeout occurs.


   :param reqid: the request identifier used in the request event.


   :param results: a :zeek:type:`vector` of :zeek:see:`Management::Result`, one
       for each Supervisor transaction. Each such result identifies both
       the instance and node.



