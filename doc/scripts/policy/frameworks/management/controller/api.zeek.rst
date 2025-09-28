:tocdepth: 3

policy/frameworks/management/controller/api.zeek
================================================
.. zeek:namespace:: Management::Controller::API

The event API of cluster controllers. Most endpoints consist of event pairs,
where the controller answers the client's request event with a corresponding
response event. Such event pairs share the same name prefix and end in
"_request" and "_response", respectively.

:Namespace: Management::Controller::API
:Imports: :doc:`policy/frameworks/management/types.zeek </scripts/policy/frameworks/management/types.zeek>`

Summary
~~~~~~~
Constants
#########
=================================================================== ================================================================
:zeek:id:`Management::Controller::API::version`: :zeek:type:`count` A simple versioning scheme, used to track basic compatibility of
                                                                    controller, agents, and the client.
=================================================================== ================================================================

Events
######
======================================================================================== ======================================================================
:zeek:id:`Management::Controller::API::deploy_request`: :zeek:type:`event`               Trigger deployment of a previously staged configuration.
:zeek:id:`Management::Controller::API::deploy_response`: :zeek:type:`event`              Response to a :zeek:see:`Management::Controller::API::deploy_request`
                                                                                         event.
:zeek:id:`Management::Controller::API::get_configuration_request`: :zeek:type:`event`    The client sends this event to retrieve the controller's current
                                                                                         cluster configuration(s).
:zeek:id:`Management::Controller::API::get_configuration_response`: :zeek:type:`event`   Response to a
                                                                                         :zeek:see:`Management::Controller::API::get_configuration_request`
                                                                                         event.
:zeek:id:`Management::Controller::API::get_id_value_request`: :zeek:type:`event`         The client sends this event to retrieve the current value of a
                                                                                         variable in Zeek's global namespace, referenced by the given
                                                                                         identifier (i.e., variable name).
:zeek:id:`Management::Controller::API::get_id_value_response`: :zeek:type:`event`        Response to a
                                                                                         :zeek:see:`Management::Controller::API::get_id_value_request`
                                                                                         event.
:zeek:id:`Management::Controller::API::get_instances_request`: :zeek:type:`event`        The client sends this event to request a list of the currently
                                                                                         peered agents/instances.
:zeek:id:`Management::Controller::API::get_instances_response`: :zeek:type:`event`       Response to a
                                                                                         :zeek:see:`Management::Controller::API::get_instances_request`
                                                                                         event.
:zeek:id:`Management::Controller::API::get_nodes_request`: :zeek:type:`event`            The client sends this event to request a list of
                                                                                         :zeek:see:`Management::NodeStatus` records that capture
                                                                                         the status of Supervisor-managed nodes running on the cluster's
                                                                                         instances.
:zeek:id:`Management::Controller::API::get_nodes_response`: :zeek:type:`event`           Response to a
                                                                                         :zeek:see:`Management::Controller::API::get_nodes_request` event.
:zeek:id:`Management::Controller::API::notify_agents_ready`: :zeek:type:`event`          The controller triggers this event when the operational cluster
                                                                                         instances align with the ones desired by the cluster
                                                                                         configuration.
:zeek:id:`Management::Controller::API::restart_request`: :zeek:type:`event`              The client sends this event to restart currently running Zeek cluster
                                                                                         nodes.
:zeek:id:`Management::Controller::API::restart_response`: :zeek:type:`event`             Response to a :zeek:see:`Management::Controller::API::restart_request`
                                                                                         event.
:zeek:id:`Management::Controller::API::stage_configuration_request`: :zeek:type:`event`  Upload a configuration to the controller for later deployment.
:zeek:id:`Management::Controller::API::stage_configuration_response`: :zeek:type:`event` Response to a
                                                                                         :zeek:see:`Management::Controller::API::stage_configuration_request`
                                                                                         event.
:zeek:id:`Management::Controller::API::test_timeout_request`: :zeek:type:`event`         This event causes no further action (other than getting logged) if
                                                                                         with_state is F.
:zeek:id:`Management::Controller::API::test_timeout_response`: :zeek:type:`event`        Response to a
                                                                                         :zeek:see:`Management::Controller::API::test_timeout_request`
                                                                                         event.
======================================================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: Management::Controller::API::version
   :source-code: policy/frameworks/management/controller/api.zeek 13 13

   :Type: :zeek:type:`count`
   :Default: ``1``

   A simple versioning scheme, used to track basic compatibility of
   controller, agents, and the client.

Events
######
.. zeek:id:: Management::Controller::API::deploy_request
   :source-code: policy/frameworks/management/controller/main.zeek 1088 1128

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   Trigger deployment of a previously staged configuration.  The client
   sends this event to the controller, which deploys the configuration
   to the agents. Agents then terminate any previously running cluster
   nodes and (re-)launch those defined in the new configuration. Once
   each agent has responded (or a timeout occurs), the controller sends
   a response event back to the client, aggregating the results from the
   agents. The controller keeps the staged configuration available for
   download, or re-deployment.  In addition, the deployed configuration
   becomes available for download as well, with any augmentations
   (e.g. node ports filled in by auto-assignment) reflected.
   

   :param reqid: a request identifier string, echoed in the response event.
   

.. zeek:id:: Management::Controller::API::deploy_response
   :source-code: policy/frameworks/management/controller/api.zeek 119 119

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, results: :zeek:type:`Management::ResultVec`)

   Response to a :zeek:see:`Management::Controller::API::deploy_request`
   event. The controller sends this back to the client, conveying the
   outcome of the deployment.
   

   :param reqid: the request identifier used in the request event.
   

   :param results: a vector of :zeek:see:`Management::Result` records.
       Each member captures the result of launching one cluster
       node captured in the configuration, or an agent-wide error
       when the result does not indicate a particular node.
   

.. zeek:id:: Management::Controller::API::get_configuration_request
   :source-code: policy/frameworks/management/controller/main.zeek 1063 1086

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, deployed: :zeek:type:`bool`)

   The client sends this event to retrieve the controller's current
   cluster configuration(s).
   

   :param reqid: a request identifier string, echoed in the response event.
   

   :param deployed: when true, returns the deployed configuration (if any),
       otherwise the staged one (if any).
   

.. zeek:id:: Management::Controller::API::get_configuration_response
   :source-code: policy/frameworks/management/controller/api.zeek 89 89

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`Management::Result`)

   Response to a
   :zeek:see:`Management::Controller::API::get_configuration_request`
   event. The controller sends this back to the client, with the
   requested configuration.
   

   :param reqid: the request identifier used in the request event.
   

   :param result: a :zeek:see:`Management::Result` record with a successful
       :zeek:see:`Management::Configuration` in the data member, if
       a configuration is currently deployed. Otherwise, a Result
       record in error state, with no data value assigned.
   

.. zeek:id:: Management::Controller::API::get_id_value_request
   :source-code: policy/frameworks/management/controller/main.zeek 1297 1374

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, id: :zeek:type:`string`, nodes: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`)

   The client sends this event to retrieve the current value of a
   variable in Zeek's global namespace, referenced by the given
   identifier (i.e., variable name). The controller asks all agents
   to retrieve this value from each cluster node, accumulates the
   returned responses, and responds with a get_id_value_response
   event back to the client.
   

   :param reqid: a request identifier string, echoed in the response event.
   

   :param id: the name of the variable whose value to retrieve.
   

   :param nodes: a set of cluster node names (e.g. "worker-01") to retrieve
      the values from. An empty set, supplied by default, means
      retrieval from all current cluster nodes.
   

.. zeek:id:: Management::Controller::API::get_id_value_response
   :source-code: policy/frameworks/management/controller/api.zeek 182 182

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, results: :zeek:type:`Management::ResultVec`)

   Response to a
   :zeek:see:`Management::Controller::API::get_id_value_request`
   event. The controller sends this back to the client, with a JSON
   representation of the requested global ID on all relevant instances.
   

   :param reqid: the request identifier used in the request event.
   

   :param results: a :zeek:type:`vector` of :zeek:see:`Management::Result`
       records. Each record covers one Zeek cluster node. Each record's
       data field contains a string with the JSON rendering (as produced
       by :zeek:id:`to_json`, including the error strings it potentially
       returns).
   

.. zeek:id:: Management::Controller::API::get_instances_request
   :source-code: policy/frameworks/management/controller/main.zeek 1130 1151

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   The client sends this event to request a list of the currently
   peered agents/instances.
   

   :param reqid: a request identifier string, echoed in the response event.
   

.. zeek:id:: Management::Controller::API::get_instances_response
   :source-code: policy/frameworks/management/controller/api.zeek 32 32

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`Management::Result`)

   Response to a
   :zeek:see:`Management::Controller::API::get_instances_request`
   event. The controller sends this back to the client.
   

   :param reqid: the request identifier used in the request event.
   

   :param result: a :zeek:see:`Management::Result`. Its data member is a vector
       of :zeek:see:`Management::Instance` records.
   

.. zeek:id:: Management::Controller::API::get_nodes_request
   :source-code: policy/frameworks/management/controller/main.zeek 1199 1228

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   The client sends this event to request a list of
   :zeek:see:`Management::NodeStatus` records that capture
   the status of Supervisor-managed nodes running on the cluster's
   instances.
   

   :param reqid: a request identifier string, echoed in the response event.
   

.. zeek:id:: Management::Controller::API::get_nodes_response
   :source-code: policy/frameworks/management/controller/api.zeek 147 147

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, results: :zeek:type:`Management::ResultVec`)

   Response to a
   :zeek:see:`Management::Controller::API::get_nodes_request` event. The
   controller sends this back to the client, with a description of the
   nodes currently managed by the Supervisors on all connected
   instances. This includes agents and possibly the controller, if it
   runs jointly with an agent.
   

   :param reqid: the request identifier used in the request event.
   

   :param results: a :zeek:type:`vector` of :zeek:see:`Management::Result`
       records. Each record covers one cluster instance. Each record's
       data member is a vector of :zeek:see:`Management::NodeStatus`
       records, covering the nodes at that instance. Results may also
       indicate failure, with error messages indicating what went wrong.
   

.. zeek:id:: Management::Controller::API::notify_agents_ready
   :source-code: policy/frameworks/management/controller/main.zeek 801 833

   :Type: :zeek:type:`event` (instances: :zeek:type:`set` [:zeek:type:`string`])

   The controller triggers this event when the operational cluster
   instances align with the ones desired by the cluster
   configuration. It's essentially a cluster management readiness
   event. This event is currently only used internally by the controller,
   and not published to topics.
   

   :param instances: the set of instance names now ready.
   

.. zeek:id:: Management::Controller::API::restart_request
   :source-code: policy/frameworks/management/controller/main.zeek 1416 1509

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, nodes: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`)

   The client sends this event to restart currently running Zeek cluster
   nodes. The controller relays the request to its agents, which respond
   with a list of :zeek:see:`Management::Result` records summarizing
   each node restart. The controller combines these lists, and sends a
   :zeek:see:`Management::Controller::API::restart_response` event with
   the result.
   

   :param reqid: a request identifier string, echoed in the response event.
   

   :param nodes: a set of cluster node names (e.g. "worker-01") to restart.  An
      empty set, supplied by default, means restart of all current
      cluster nodes.
   

.. zeek:id:: Management::Controller::API::restart_response
   :source-code: policy/frameworks/management/controller/api.zeek 213 213

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, results: :zeek:type:`Management::ResultVec`)

   Response to a :zeek:see:`Management::Controller::API::restart_request`
   event. The controller sends this back to the client when it has received
   responses from all agents involved, or a timeout occurs.
   

   :param reqid: the request identifier used in the request event.
   

   :param results: a :zeek:type:`vector` of :zeek:see:`Management::Result`,
       combining the restart results from all agents. Each such result
       identifies both the instance and node in question. Results that
       do not identify an instance are generated by the controller,
       flagging corner cases, including absence of a deployed cluster
       or unknown nodes.
   

.. zeek:id:: Management::Controller::API::stage_configuration_request
   :source-code: policy/frameworks/management/controller/main.zeek 1002 1061

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, config: :zeek:type:`Management::Configuration`)

   Upload a configuration to the controller for later deployment.
   The client sends this event to the controller, which validates the
   configuration and indicates the outcome in its response event. No
   deployment takes place yet, and existing deployed configurations and
   the running Zeek cluster remain intact. To trigger deployment of an uploaded
   configuration, use :zeek:see:`Management::Controller::API::deploy_request`.
   

   :param reqid: a request identifier string, echoed in the response event.
   

   :param config: a :zeek:see:`Management::Configuration` record
       specifying the cluster configuration.
   

.. zeek:id:: Management::Controller::API::stage_configuration_response
   :source-code: policy/frameworks/management/controller/api.zeek 63 63

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, results: :zeek:type:`Management::ResultVec`)

   Response to a
   :zeek:see:`Management::Controller::API::stage_configuration_request`
   event. The controller sends this back to the client, conveying
   validation results.
   

   :param reqid: the request identifier used in the request event.
   

   :param results: a :zeek:see:`Management::Result` vector, indicating whether
       the controller accepts the configuration. In case of a success,
       a single result record indicates so. Otherwise, the sequence is
       all errors, each indicating a configuration validation error.
   

.. zeek:id:: Management::Controller::API::test_timeout_request
   :source-code: policy/frameworks/management/controller/main.zeek 1588 1599

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, with_state: :zeek:type:`bool`)

   This event causes no further action (other than getting logged) if
   with_state is F. When T, the controller establishes request state, and
   the controller only ever sends the response event when this state times
   out.
   

   :param reqid: a request identifier string, echoed in the response event when
       with_state is T.
   

   :param with_state: flag indicating whether the controller should keep (and
       time out) request state for this request.
   

.. zeek:id:: Management::Controller::API::test_timeout_response
   :source-code: policy/frameworks/management/controller/api.zeek 238 238

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`Management::Result`)

   Response to a
   :zeek:see:`Management::Controller::API::test_timeout_request`
   event. The controller sends this back to the client if the original
   request had the with_state flag.
   

   :param reqid: the request identifier used in the request event.
   


