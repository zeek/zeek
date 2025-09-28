:tocdepth: 3

policy/frameworks/management/node/api.zeek
==========================================
.. zeek:namespace:: Management::Node::API

The Management event API of cluster nodes. The API consists of request/
response event pairs, like elsewhere in the Management, Supervisor, and
Control frameworks.

:Namespace: Management::Node::API
:Imports: :doc:`policy/frameworks/management/types.zeek </scripts/policy/frameworks/management/types.zeek>`

Summary
~~~~~~~
Events
######
============================================================================ =====================================================================
:zeek:id:`Management::Node::API::node_dispatch_request`: :zeek:type:`event`  Management agents send this event to every Zeek cluster node to run a
                                                                             "dispatch" -- a particular, pre-implemented action.
:zeek:id:`Management::Node::API::node_dispatch_response`: :zeek:type:`event` Response to a node_dispatch_request event.
:zeek:id:`Management::Node::API::notify_node_hello`: :zeek:type:`event`      The cluster nodes send this event upon peering as a "check-in" to
                                                                             the agent, to indicate the node is now available to communicate
                                                                             with.
============================================================================ =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Management::Node::API::node_dispatch_request
   :source-code: policy/frameworks/management/node/main.zeek 58 97

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, action: :zeek:type:`vector` of :zeek:type:`string`, nodes: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`)

   Management agents send this event to every Zeek cluster node to run a
   "dispatch" -- a particular, pre-implemented action. This is the agent-node
   complement to :zeek:see:`Management::Agent::API::node_dispatch_request`.
   

   :param reqid: a request identifier string, echoed in the response event.
   

   :param action: the requested dispatch command, with any arguments.
   

   :param nodes: the cluster node names this dispatch targets. An empty set,
       supplied by default, means it applies to all nodes. Since nodes
       receive all dispatch requests, they can use any node names provided
       here to filter themselves out of responding.

.. zeek:id:: Management::Node::API::node_dispatch_response
   :source-code: policy/frameworks/management/agent/main.zeek 690 759

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`Management::Result`)

   Response to a node_dispatch_request event. The nodes send this back
   to the agent. This is the agent-node equivalent of
   :zeek:see:`Management::Agent::API::node_dispatch_response`.
   

   :param reqid: the request identifier used in the request event.
   

   :param result: a :zeek:see:`Management::Result` record covering one Zeek
       cluster node managed by the agent. Upon success, the data field
       contains a value appropriate for the requested dispatch.

.. zeek:id:: Management::Node::API::notify_node_hello
   :source-code: policy/frameworks/management/agent/main.zeek 1010 1033

   :Type: :zeek:type:`event` (node: :zeek:type:`string`)

   The cluster nodes send this event upon peering as a "check-in" to
   the agent, to indicate the node is now available to communicate
   with. It is an agent-level equivalent of :zeek:see:`Broker::peer_added`,
   and similar to :zeek:see:`Management::Agent::API::notify_agent_hello`
   for agents.
   

   :param node: the name of the node, as given in :zeek:see:`Cluster::node`.
   


