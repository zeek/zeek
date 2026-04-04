:tocdepth: 3

policy/frameworks/management/types.zeek
=======================================
.. zeek:namespace:: Management

This module holds the basic types needed for the Management framework. These
are used by both cluster agent and controller, and several have corresponding
implementations in zeek-client.

:Namespace: Management

Summary
~~~~~~~
Types
#####
=========================================================== =====================================================================
:zeek:type:`Management::Configuration`: :zeek:type:`record` Data structure capturing a cluster's complete configuration.
:zeek:type:`Management::Instance`: :zeek:type:`record`      Configuration describing a Zeek instance running a Cluster
                                                            Agent.
:zeek:type:`Management::InstanceVec`: :zeek:type:`vector`
:zeek:type:`Management::Node`: :zeek:type:`record`          Configuration describing a Cluster Node process.
:zeek:type:`Management::NodeOutputs`: :zeek:type:`record`   In :zeek:see:`Management::Controller::API::deploy_response` events,
                                                            each :zeek:see:`Management::Result` indicates the outcome of a
                                                            launched cluster node.
:zeek:type:`Management::NodeStatus`: :zeek:type:`record`    The status of a Supervisor-managed node, as reported to the client in
                                                            a get_nodes_request/get_nodes_response transaction.
:zeek:type:`Management::NodeStatusVec`: :zeek:type:`vector`
:zeek:type:`Management::Option`: :zeek:type:`record`        A Zeek-side option with value.
:zeek:type:`Management::Result`: :zeek:type:`record`        Return value for request-response API event pairs.
:zeek:type:`Management::ResultVec`: :zeek:type:`vector`
:zeek:type:`Management::Role`: :zeek:type:`enum`            Management infrastructure node type.
:zeek:type:`Management::State`: :zeek:type:`enum`           State that a Cluster Node can be in.
=========================================================== =====================================================================

Functions
#########
================================================================== =========================================================
:zeek:id:`Management::result_to_string`: :zeek:type:`function`     Given a :zeek:see:`Management::Result` record,
                                                                   this function returns a string summarizing it.
:zeek:id:`Management::result_vec_to_string`: :zeek:type:`function` Given a vector of :zeek:see:`Management::Result` records,
                                                                   this function returns a string summarizing them.
================================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Management::Configuration
   :source-code: policy/frameworks/management/types.zeek 67 74

   :Type: :zeek:type:`record`


   .. zeek:field:: id :zeek:type:`string` :zeek:attr:`&default` = ``Fm22x30CduPMuXAq1`` :zeek:attr:`&optional`

      Unique identifier for a particular configuration


   .. zeek:field:: instances :zeek:type:`set` [:zeek:type:`Management::Instance`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`

      The instances in the cluster.


   .. zeek:field:: nodes :zeek:type:`set` [:zeek:type:`Management::Node`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`

      The set of nodes in the cluster, as distributed over the instances.


   Data structure capturing a cluster's complete configuration.

.. zeek:type:: Management::Instance
   :source-code: policy/frameworks/management/types.zeek 27 34

   :Type: :zeek:type:`record`


   .. zeek:field:: name :zeek:type:`string`

      Unique, human-readable instance name


   .. zeek:field:: host :zeek:type:`addr`

      IP address of system


   .. zeek:field:: listen_port :zeek:type:`port` :zeek:attr:`&optional`

      Agent listening port. Not needed if agents connect to controller.


   Configuration describing a Zeek instance running a Cluster
   Agent. Normally, there'll be one instance per cluster
   system: a single physical system.

.. zeek:type:: Management::InstanceVec
   :source-code: policy/frameworks/management/types.zeek 36 36

   :Type: :zeek:type:`vector` of :zeek:type:`Management::Instance`


.. zeek:type:: Management::Node
   :source-code: policy/frameworks/management/types.zeek 52 64

   :Type: :zeek:type:`record`


   .. zeek:field:: name :zeek:type:`string`

      Cluster-unique, human-readable node name


   .. zeek:field:: instance :zeek:type:`string`

      Name of instance where node is to run


   .. zeek:field:: role :zeek:type:`Supervisor::ClusterRole`

      Role of the node.


   .. zeek:field:: state :zeek:type:`Management::State`

      Desired, or current, run state.


   .. zeek:field:: p :zeek:type:`port` :zeek:attr:`&optional`

      Port on which this node will listen


   .. zeek:field:: scripts :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`

      Additional Zeek scripts for node


   .. zeek:field:: options :zeek:type:`set` [:zeek:type:`Management::Option`] :zeek:attr:`&optional`

      Zeek options for node


   .. zeek:field:: interface :zeek:type:`string` :zeek:attr:`&optional`

      Interface to sniff


   .. zeek:field:: cpu_affinity :zeek:type:`int` :zeek:attr:`&optional`

      CPU/core number to pin to


   .. zeek:field:: env :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`

      Custom environment vars


   .. zeek:field:: metrics_port :zeek:type:`port` :zeek:attr:`&optional`

      Metrics exposure port, for Prometheus


   Configuration describing a Cluster Node process.

.. zeek:type:: Management::NodeOutputs
   :source-code: policy/frameworks/management/types.zeek 122 125

   :Type: :zeek:type:`record`


   .. zeek:field:: stdout :zeek:type:`string`

      The stdout stream of a Zeek process


   .. zeek:field:: stderr :zeek:type:`string`

      The stderr stream of a Zeek process


   In :zeek:see:`Management::Controller::API::deploy_response` events,
   each :zeek:see:`Management::Result` indicates the outcome of a
   launched cluster node. If a node does not launch properly (meaning
   it doesn't check in with the agent on the machine it's running on),
   the result will indicate failure, and its data field will be an
   instance of this record, capturing the stdout and stderr output of
   the failing node.

.. zeek:type:: Management::NodeStatus
   :source-code: policy/frameworks/management/types.zeek 78 94

   :Type: :zeek:type:`record`


   .. zeek:field:: node :zeek:type:`string`

      Cluster-unique, human-readable node name


   .. zeek:field:: state :zeek:type:`Management::State`

      Current run state of the node.


   .. zeek:field:: mgmt_role :zeek:type:`Management::Role` :zeek:attr:`&default` = ``Management::NONE`` :zeek:attr:`&optional`

      Role the node plays in cluster management.


   .. zeek:field:: cluster_role :zeek:type:`Supervisor::ClusterRole` :zeek:attr:`&default` = ``Supervisor::NONE`` :zeek:attr:`&optional`

      Role the node plays in the Zeek cluster.


   .. zeek:field:: pid :zeek:type:`int` :zeek:attr:`&optional`

      Process ID of the node. This is optional because the Supervisor may not have
      a PID when a node is still bootstrapping.


   .. zeek:field:: p :zeek:type:`port` :zeek:attr:`&optional`

      The node's Broker peering listening port, if any.


   .. zeek:field:: metrics_port :zeek:type:`port` :zeek:attr:`&optional`

      The node's metrics port for Prometheus, if any.


   The status of a Supervisor-managed node, as reported to the client in
   a get_nodes_request/get_nodes_response transaction.

.. zeek:type:: Management::NodeStatusVec
   :source-code: policy/frameworks/management/types.zeek 96 96

   :Type: :zeek:type:`vector` of :zeek:type:`Management::NodeStatus`


.. zeek:type:: Management::Option
   :source-code: policy/frameworks/management/types.zeek 19 22

   :Type: :zeek:type:`record`


   .. zeek:field:: name :zeek:type:`string`

      Name of option


   .. zeek:field:: value :zeek:type:`string`

      Value of option


   A Zeek-side option with value.

.. zeek:type:: Management::Result
   :source-code: policy/frameworks/management/types.zeek 104 111

   :Type: :zeek:type:`record`


   .. zeek:field:: reqid :zeek:type:`string`

      Request ID of operation this result refers to


   .. zeek:field:: success :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`

      True if successful


   .. zeek:field:: instance :zeek:type:`string` :zeek:attr:`&optional`

      Name of associated instance (for context)


   .. zeek:field:: data :zeek:type:`any` :zeek:attr:`&optional`

      Addl data returned for successful operation


   .. zeek:field:: error :zeek:type:`string` :zeek:attr:`&optional`

      Descriptive error on failure


   .. zeek:field:: node :zeek:type:`string` :zeek:attr:`&optional`

      Name of associated node (for context)


   Return value for request-response API event pairs. Some responses
   contain one, others multiple of these. The request ID allows clients
   to string requests and responses together. Agents and the controller
   fill in the instance and node fields whenever there's sufficient
   context to define them. Any result produced by an agent will carry an
   instance value, for example.

.. zeek:type:: Management::ResultVec
   :source-code: policy/frameworks/management/types.zeek 113 113

   :Type: :zeek:type:`vector` of :zeek:type:`Management::Result`


.. zeek:type:: Management::Role
   :source-code: policy/frameworks/management/types.zeek 11 17

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Management::NONE Management::Role

         No active role in cluster management

      .. zeek:enum:: Management::AGENT Management::Role

         A cluster management agent.

      .. zeek:enum:: Management::CONTROLLER Management::Role

         The cluster's controller.

      .. zeek:enum:: Management::NODE Management::Role

         A managed cluster node (worker, manager, etc).

   Management infrastructure node type. This intentionally does not
   include the managed cluster node types (worker, logger, etc) -- those
   continue to be managed by the cluster framework.

.. zeek:type:: Management::State
   :source-code: policy/frameworks/management/types.zeek 42 50

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Management::PENDING Management::State

         Not yet running

      .. zeek:enum:: Management::RUNNING Management::State

         Running and operating normally

      .. zeek:enum:: Management::STOPPED Management::State

         Explicitly stopped

      .. zeek:enum:: Management::FAILED Management::State

         Failed to start; and permanently halted

      .. zeek:enum:: Management::CRASHED Management::State

         Crashed, will be restarted,

      .. zeek:enum:: Management::UNKNOWN Management::State

         State not known currently (e.g., because of lost connectivity)

   State that a Cluster Node can be in. State changes trigger an
   API notification (see notify_change()). The Pending state corresponds
   to the Supervisor not yet reporting a PID for a node when it has not
   yet fully launched.

Functions
#########
.. zeek:id:: Management::result_to_string
   :source-code: policy/frameworks/management/types.zeek 136 160

   :Type: :zeek:type:`function` (res: :zeek:type:`Management::Result`) : :zeek:type:`string`

   Given a :zeek:see:`Management::Result` record,
   this function returns a string summarizing it.

.. zeek:id:: Management::result_vec_to_string
   :source-code: policy/frameworks/management/types.zeek 162 170

   :Type: :zeek:type:`function` (res: :zeek:type:`Management::ResultVec`) : :zeek:type:`string`

   Given a vector of :zeek:see:`Management::Result` records,
   this function returns a string summarizing them.


