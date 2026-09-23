:tocdepth: 3

base/frameworks/cluster/main.zeek
=================================
.. zeek:namespace:: Cluster

A framework for establishing and controlling a cluster of Zeek instances.
In order to use the cluster framework, a script named
``cluster-layout.zeek`` must exist somewhere in Zeek's script search path
which has a cluster definition of the :zeek:id:`Cluster::nodes` variable.
The ``CLUSTER_NODE`` environment variable or :zeek:id:`Cluster::node`
must also be sent and the cluster framework loaded as a package like
``@load base/frameworks/cluster``.

.. warning::

    The file ``cluster-layout.zeek`` should only contain the definition
    of :zeek:id:`Cluster::nodes`. Specifically, avoid loading other Zeek
    scripts or using :zeek:see:`redef` for anything but :zeek:id:`Cluster::nodes`.

    Due to ``cluster-layout.zeek`` being loaded very early, it is easy to
    introduce circular loading issues.

:Namespace: Cluster
:Imports: :doc:`base/bif/cluster.bif.zeek </scripts/base/bif/cluster.bif.zeek>`, :doc:`base/bif/plugins/Zeek_Cluster_WebSocket.events.bif.zeek </scripts/base/bif/plugins/Zeek_Cluster_WebSocket.events.bif.zeek>`, :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/cluster/types.zeek </scripts/base/frameworks/cluster/types.zeek>`, :doc:`base/frameworks/control </scripts/base/frameworks/control/index>`

Summary
~~~~~~~
Redefinable Options
###################
===================================================================================== ===============================================================================
:zeek:id:`Cluster::default_store_dir`: :zeek:type:`string` :zeek:attr:`&redef`        Setting a default dir will, for persistent backends that have not been given an
                                                                                      explicit file path, automatically create a path within this dir that is based
                                                                                      on the name of the data store.
:zeek:id:`Cluster::enable_round_robin_logging`: :zeek:type:`bool` :zeek:attr:`&redef` Whether to distribute log messages among available logging nodes.
:zeek:id:`Cluster::logger_topic`: :zeek:type:`string` :zeek:attr:`&redef`             The topic name used for exchanging messages that are relevant to
                                                                                      logger nodes in a cluster.
:zeek:id:`Cluster::manager_is_logger`: :zeek:type:`bool` :zeek:attr:`&redef`          Indicates whether or not the manager will act as the logger and receive
                                                                                      logs.
:zeek:id:`Cluster::manager_topic`: :zeek:type:`string` :zeek:attr:`&redef`            The topic name used for exchanging messages that are relevant to
                                                                                      manager nodes in a cluster.
:zeek:id:`Cluster::node`: :zeek:type:`string` :zeek:attr:`&redef`                     This is usually supplied on the command line for each instance
                                                                                      of the cluster that is started up.
:zeek:id:`Cluster::node_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`        The topic prefix used for exchanging messages that are relevant to
                                                                                      a named node in a cluster.
:zeek:id:`Cluster::nodeid_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`      The topic prefix used for exchanging messages that are relevant to
                                                                                      a unique node in a cluster.
:zeek:id:`Cluster::nodes`: :zeek:type:`table` :zeek:attr:`&redef`                     The cluster layout definition.
:zeek:id:`Cluster::proxy_topic`: :zeek:type:`string` :zeek:attr:`&redef`              The topic name used for exchanging messages that are relevant to
                                                                                      proxy nodes in a cluster.
:zeek:id:`Cluster::retry_interval`: :zeek:type:`interval` :zeek:attr:`&redef`         Interval for retrying failed connections between cluster nodes.
:zeek:id:`Cluster::worker_topic`: :zeek:type:`string` :zeek:attr:`&redef`             The topic name used for exchanging messages that are relevant to
                                                                                      worker nodes in a cluster.
===================================================================================== ===============================================================================

Constants
#########
====================================================== ==================================================================
:zeek:id:`Cluster::broadcast_topics`: :zeek:type:`set` A set of topic names to be used for broadcasting messages that are
                                                       relevant to all nodes in a cluster.
====================================================== ==================================================================

Types
#####
================================================================= ====================================================================
:zeek:type:`Cluster::Info`: :zeek:type:`record` :zeek:attr:`&log` The record type which contains the column fields of the cluster log.
:zeek:type:`Cluster::BackendTag`: :zeek:type:`enum`
:zeek:type:`Cluster::EventSerializerTag`: :zeek:type:`enum`
:zeek:type:`Cluster::LogSerializerTag`: :zeek:type:`enum`
================================================================= ====================================================================

Redefinitions
#############
======================================= ======================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The cluster logging stream identifier.

                                        * :zeek:enum:`Cluster::LOG`
======================================= ======================================

Events
######
================================================= =======================================================================
:zeek:id:`Cluster::hello`: :zeek:type:`event`     When using broker-enabled cluster framework, nodes broadcast this event
                                                  to exchange their user-defined name along with a string that uniquely
                                                  identifies it for the duration of its lifetime.
:zeek:id:`Cluster::node_down`: :zeek:type:`event` When using broker-enabled cluster framework, this event will be emitted
                                                  locally whenever a connected cluster node becomes disconnected.
:zeek:id:`Cluster::node_up`: :zeek:type:`event`   When using broker-enabled cluster framework, this event will be emitted
                                                  locally whenever a cluster node connects or reconnects.
================================================= =======================================================================

Hooks
#####
============================================================ ========================================================================
:zeek:id:`Cluster::connect_node_hook`: :zeek:type:`hook`     This hook is called when the local node connects to other nodes based on
                                                             the given cluster layout.
:zeek:id:`Cluster::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
============================================================ ========================================================================

Functions
#########
=========================================================================== =====================================================================
:zeek:id:`Cluster::get_active_node_count`: :zeek:type:`function`            Returns the number of nodes per type, the calling node is currently
                                                                            connected to.
:zeek:id:`Cluster::get_node_count`: :zeek:type:`function`                   Returns the number of nodes defined in the cluster layout for a given
                                                                            node type.
:zeek:id:`Cluster::init`: :zeek:type:`function`                             Initialize the cluster backend.
:zeek:id:`Cluster::is_enabled`: :zeek:type:`function`                       This function can be called at any time to determine if the cluster
                                                                            framework is being enabled for this run.
:zeek:id:`Cluster::listen_websocket`: :zeek:type:`function`                 Start listening on a WebSocket address.
:zeek:id:`Cluster::local_node_metrics_port`: :zeek:type:`function`          This function can be called at any time to determine the configured
                                                                            metrics port for Prometheus being used by current Zeek instance.
:zeek:id:`Cluster::local_node_type`: :zeek:type:`function`                  This function can be called at any time to determine what type of
                                                                            cluster node the current Zeek instance is going to be acting as.
:zeek:id:`Cluster::log`: :zeek:type:`function`                              Write a message to the cluster logging stream.
:zeek:id:`Cluster::node_id`: :zeek:type:`function` :zeek:attr:`&redef`      Function returning this node's identifier.
:zeek:id:`Cluster::node_topic`: :zeek:type:`function` :zeek:attr:`&redef`   Retrieve the topic associated with a specific node in the cluster.
:zeek:id:`Cluster::nodeid_to_node`: :zeek:type:`function`                   Retrieve the cluster-level naming of a node based on its node ID,
                                                                            a backend-specific identifier.
:zeek:id:`Cluster::nodeid_topic`: :zeek:type:`function` :zeek:attr:`&redef` Retrieve the topic associated with a specific node in the cluster.
=========================================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Cluster::default_store_dir
   :source-code: base/frameworks/cluster/main.zeek 67 67

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Setting a default dir will, for persistent backends that have not been given an
   explicit file path, automatically create a path within this dir that is based
   on the name of the data store.

.. zeek:id:: Cluster::enable_round_robin_logging
   :source-code: base/frameworks/cluster/main.zeek 27 27

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether to distribute log messages among available logging nodes.

.. zeek:id:: Cluster::logger_topic
   :source-code: base/frameworks/cluster/main.zeek 31 31

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/logger"``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/options.zeek`

      ``=``::

         "zeek.cluster.logger"


   The topic name used for exchanging messages that are relevant to
   logger nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::manager_is_logger
   :source-code: base/frameworks/cluster/main.zeek 128 128

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Indicates whether or not the manager will act as the logger and receive
   logs.  This value should be set in the cluster-layout.zeek script (the
   value should be true only if no logger is specified in Cluster::nodes).
   Note that ZeekControl handles this automatically.

.. zeek:id:: Cluster::manager_topic
   :source-code: base/frameworks/cluster/main.zeek 35 35

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/manager"``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/options.zeek`

      ``=``::

         "zeek.cluster.manager"


   The topic name used for exchanging messages that are relevant to
   manager nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::node
   :source-code: base/frameworks/cluster/main.zeek 132 132

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   This is usually supplied on the command line for each instance
   of the cluster that is started up.

.. zeek:id:: Cluster::node_topic_prefix
   :source-code: base/frameworks/cluster/main.zeek 58 58

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/node/"``

   The topic prefix used for exchanging messages that are relevant to
   a named node in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::nodeid_topic_prefix
   :source-code: base/frameworks/cluster/main.zeek 62 62

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/nodeid/"``

   The topic prefix used for exchanging messages that are relevant to
   a unique node in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::nodes
   :source-code: base/frameworks/cluster/main.zeek 113 113

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Cluster::Node`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   The cluster layout definition.  This should be placed into a filter
   named cluster-layout.zeek somewhere in the ZEEKPATH.  It will be
   automatically loaded if the CLUSTER_NODE environment variable is set.
   Note that ZeekControl handles all of this automatically.
   The table is typically indexed by node names/labels (e.g. "manager"
   or "worker-1").

.. zeek:id:: Cluster::proxy_topic
   :source-code: base/frameworks/cluster/main.zeek 39 39

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/proxy"``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/options.zeek`

      ``=``::

         "zeek.cluster.proxy"


   The topic name used for exchanging messages that are relevant to
   proxy nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::retry_interval
   :source-code: base/frameworks/cluster/main.zeek 144 144

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   Interval for retrying failed connections between cluster nodes.
   If set, the ZEEK_DEFAULT_CONNECT_RETRY (given in number of seconds)
   environment variable overrides this option.

.. zeek:id:: Cluster::worker_topic
   :source-code: base/frameworks/cluster/main.zeek 43 43

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/worker"``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/options.zeek`

      ``=``::

         "zeek.cluster.worker"


   The topic name used for exchanging messages that are relevant to
   worker nodes in a cluster.  Used with broker-enabled cluster communication.

Constants
#########
.. zeek:id:: Cluster::broadcast_topics
   :source-code: base/frameworks/cluster/main.zeek 49 49

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Default:

      ::

         {
            "zeek/cluster/manager",
            "zeek/cluster/logger",
            "zeek/cluster/proxy",
            "zeek/cluster/worker"
         }


   A set of topic names to be used for broadcasting messages that are
   relevant to all nodes in a cluster. Currently, there is not a common
   topic to broadcast to, because enabling implicit Broker forwarding would
   cause a routing loop for this topic.

Types
#####
.. zeek:type:: Cluster::Info
   :source-code: base/frameworks/cluster/main.zeek 76 83

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The time at which a cluster message was generated.


   .. zeek:field:: node :zeek:type:`string` :zeek:attr:`&log`

      The name of the node that is creating the log record.


   .. zeek:field:: message :zeek:type:`string` :zeek:attr:`&log`

      A message indicating information about the cluster's operation.

   :Attributes: :zeek:attr:`&log`

   The record type which contains the column fields of the cluster log.

.. zeek:type:: Cluster::BackendTag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Cluster::CLUSTER_BACKEND_BROKER Cluster::BackendTag

      .. zeek:enum:: Cluster::CLUSTER_BACKEND_BROKER_WEBSOCKET_SHIM Cluster::BackendTag

      .. zeek:enum:: Cluster::CLUSTER_BACKEND_NONE Cluster::BackendTag

      .. zeek:enum:: Cluster::CLUSTER_BACKEND_ZEROMQ Cluster::BackendTag


.. zeek:type:: Cluster::EventSerializerTag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Cluster::EVENT_SERIALIZER_BROKER_BIN_V1 Cluster::EventSerializerTag

      .. zeek:enum:: Cluster::EVENT_SERIALIZER_BROKER_JSON_V1 Cluster::EventSerializerTag


.. zeek:type:: Cluster::LogSerializerTag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Cluster::LOG_SERIALIZER_ZEEK_BIN_V1 Cluster::LogSerializerTag


Events
######
.. zeek:id:: Cluster::hello
   :source-code: base/frameworks/cluster/main.zeek 304 329

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, nodes broadcast this event
   to exchange their user-defined name along with a string that uniquely
   identifies it for the duration of its lifetime.  This string may change
   if the node dies and has to reconnect later.

.. zeek:id:: Cluster::node_down
   :source-code: base/frameworks/cluster/main.zeek 158 158

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a connected cluster node becomes disconnected.

.. zeek:id:: Cluster::node_up
   :source-code: base/frameworks/cluster/main.zeek 154 154

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a cluster node connects or reconnects.

Hooks
#####
.. zeek:id:: Cluster::connect_node_hook
   :source-code: base/frameworks/cluster/main.zeek 210 210

   :Type: :zeek:type:`hook` (connectee: :zeek:type:`Cluster::NamedNode`) : :zeek:type:`bool`

   This hook is called when the local node connects to other nodes based on
   the given cluster layout. Breaking from the hook will prevent connection
   establishment.

   This hook only applies to the Broker cluster backend.


   :param connectee: The node to connect to.

.. zeek:id:: Cluster::log_policy
   :source-code: base/frameworks/cluster/main.zeek 73 73

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: Cluster::get_active_node_count
   :source-code: base/frameworks/cluster/main.zeek 248 251

   :Type: :zeek:type:`function` (node_type: :zeek:type:`Cluster::NodeType`) : :zeek:type:`count`

   Returns the number of nodes per type, the calling node is currently
   connected to. This is primarily intended for use by the manager to find
   out how many nodes should be responding to requests.

.. zeek:id:: Cluster::get_node_count
   :source-code: base/frameworks/cluster/main.zeek 235 246

   :Type: :zeek:type:`function` (node_type: :zeek:type:`Cluster::NodeType`) : :zeek:type:`count`

   Returns the number of nodes defined in the cluster layout for a given
   node type.

.. zeek:id:: Cluster::init
   :source-code: base/frameworks/cluster/main.zeek 371 374

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Initialize the cluster backend.

   Cluster backends usually invoke this from a :zeek:see:`zeek_init` handler.


   :returns: T on success, else F.

.. zeek:id:: Cluster::is_enabled
   :source-code: base/frameworks/cluster/main.zeek 253 256

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   This function can be called at any time to determine if the cluster
   framework is being enabled for this run.


   :returns: True if :zeek:id:`Cluster::node` has been set.

.. zeek:id:: Cluster::listen_websocket
   :source-code: base/frameworks/cluster/main.zeek 376 379

   :Type: :zeek:type:`function` (options: :zeek:type:`Cluster::WebSocketServerOptions`) : :zeek:type:`bool`

   Start listening on a WebSocket address.


   :param options: The server :zeek:see:`Cluster::WebSocketServerOptions` to use.


   :returns: T on success, else F.

.. zeek:id:: Cluster::local_node_metrics_port
   :source-code: base/frameworks/cluster/main.zeek 269 281

   :Type: :zeek:type:`function` () : :zeek:type:`port`

   This function can be called at any time to determine the configured
   metrics port for Prometheus being used by current Zeek instance. If
   :zeek:id:`Cluster::is_enabled` returns false or the node isn't found,
   ``0/unknown`` is returned.


   :returns: The metrics port used by the calling node.

.. zeek:id:: Cluster::local_node_type
   :source-code: base/frameworks/cluster/main.zeek 258 267

   :Type: :zeek:type:`function` () : :zeek:type:`Cluster::NodeType`

   This function can be called at any time to determine what type of
   cluster node the current Zeek instance is going to be acting as.
   If :zeek:id:`Cluster::is_enabled` returns false, then
   :zeek:enum:`Cluster::NONE` is returned.


   :returns: The :zeek:type:`Cluster::NodeType` the calling node acts as.

.. zeek:id:: Cluster::log
   :source-code: base/frameworks/cluster/main.zeek 366 369

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`void`

   Write a message to the cluster logging stream.

.. zeek:id:: Cluster::node_id
   :source-code: policy/frameworks/cluster/backend/zeromq/options.zeek 452 454

   :Type: :zeek:type:`function` () : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   Function returning this node's identifier.

   By default this is :zeek:see:`Broker::node_id`, but can be
   redefined by other cluster backends. This identifier should be
   a short lived identifier that resets when a node is restarted.

.. zeek:id:: Cluster::node_topic
   :source-code: policy/frameworks/cluster/backend/zeromq/options.zeek 437 439

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   Retrieve the topic associated with a specific node in the cluster.


   :param name: the name of the cluster node (e.g. "manager").


   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.

.. zeek:id:: Cluster::nodeid_to_node
   :source-code: base/frameworks/cluster/main.zeek 293 302

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`Cluster::NamedNode`

   Retrieve the cluster-level naming of a node based on its node ID,
   a backend-specific identifier.


   :param id: the node ID of a peer.


   :returns: the :zeek:see:`Cluster::NamedNode` for the requested node, if
            known, otherwise a "null" instance with an empty name field.

.. zeek:id:: Cluster::nodeid_topic
   :source-code: policy/frameworks/cluster/backend/zeromq/options.zeek 441 443

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   Retrieve the topic associated with a specific node in the cluster.


   :param id: the id of the cluster node (from :zeek:see:`Broker::EndpointInfo`
       or :zeek:see:`Broker::node_id`.


   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.


