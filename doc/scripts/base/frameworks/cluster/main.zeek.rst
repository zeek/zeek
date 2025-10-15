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
:Imports: :doc:`base/bif/cluster.bif.zeek </scripts/base/bif/cluster.bif.zeek>`, :doc:`base/bif/plugins/Zeek_Cluster_WebSocket.events.bif.zeek </scripts/base/bif/plugins/Zeek_Cluster_WebSocket.events.bif.zeek>`, :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/control </scripts/base/frameworks/control/index>`

Summary
~~~~~~~
Redefinable Options
###################
==================================================================================================== ===============================================================================
:zeek:id:`Cluster::default_backend`: :zeek:type:`Broker::BackendType` :zeek:attr:`&redef`            The type of data store backend that will be used for all data stores if
                                                                                                     no other has already been specified by the user in :zeek:see:`Cluster::stores`.
:zeek:id:`Cluster::default_master_node`: :zeek:type:`string` :zeek:attr:`&redef`                     Name of the node on which master data stores will be created if no other
                                                                                                     has already been specified by the user in :zeek:see:`Cluster::stores`.
:zeek:id:`Cluster::default_persistent_backend`: :zeek:type:`Broker::BackendType` :zeek:attr:`&redef` The type of persistent data store backend that will be used for all data
                                                                                                     stores if no other has already been specified by the user in
                                                                                                     :zeek:see:`Cluster::stores`.
:zeek:id:`Cluster::default_store_dir`: :zeek:type:`string` :zeek:attr:`&redef`                       Setting a default dir will, for persistent backends that have not
                                                                                                     been given an explicit file path via :zeek:see:`Cluster::stores`,
                                                                                                     automatically create a path within this dir that is based on the name of
                                                                                                     the data store.
:zeek:id:`Cluster::default_websocket_max_event_queue_size`: :zeek:type:`count` :zeek:attr:`&redef`   The default maximum queue size for WebSocket event dispatcher instances.
:zeek:id:`Cluster::default_websocket_ping_interval`: :zeek:type:`interval` :zeek:attr:`&redef`       The default ping interval for WebSocket clients.
:zeek:id:`Cluster::enable_round_robin_logging`: :zeek:type:`bool` :zeek:attr:`&redef`                Whether to distribute log messages among available logging nodes.
:zeek:id:`Cluster::logger_topic`: :zeek:type:`string` :zeek:attr:`&redef`                            The topic name used for exchanging messages that are relevant to
                                                                                                     logger nodes in a cluster.
:zeek:id:`Cluster::manager_is_logger`: :zeek:type:`bool` :zeek:attr:`&redef`                         Indicates whether or not the manager will act as the logger and receive
                                                                                                     logs.
:zeek:id:`Cluster::manager_topic`: :zeek:type:`string` :zeek:attr:`&redef`                           The topic name used for exchanging messages that are relevant to
                                                                                                     manager nodes in a cluster.
:zeek:id:`Cluster::node`: :zeek:type:`string` :zeek:attr:`&redef`                                    This is usually supplied on the command line for each instance
                                                                                                     of the cluster that is started up.
:zeek:id:`Cluster::node_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                       The topic prefix used for exchanging messages that are relevant to
                                                                                                     a named node in a cluster.
:zeek:id:`Cluster::nodeid_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                     The topic prefix used for exchanging messages that are relevant to
                                                                                                     a unique node in a cluster.
:zeek:id:`Cluster::nodes`: :zeek:type:`table` :zeek:attr:`&redef`                                    The cluster layout definition.
:zeek:id:`Cluster::proxy_topic`: :zeek:type:`string` :zeek:attr:`&redef`                             The topic name used for exchanging messages that are relevant to
                                                                                                     proxy nodes in a cluster.
:zeek:id:`Cluster::retry_interval`: :zeek:type:`interval` :zeek:attr:`&redef`                        Interval for retrying failed connections between cluster nodes.
:zeek:id:`Cluster::worker_topic`: :zeek:type:`string` :zeek:attr:`&redef`                            The topic name used for exchanging messages that are relevant to
                                                                                                     worker nodes in a cluster.
==================================================================================================== ===============================================================================

Constants
#########
====================================================== ==================================================================
:zeek:id:`Cluster::broadcast_topics`: :zeek:type:`set` A set of topic names to be used for broadcasting messages that are
                                                       relevant to all nodes in a cluster.
====================================================== ==================================================================

State Variables
###############
================================================================================================ ======================================================================
:zeek:id:`Cluster::stores`: :zeek:type:`table` :zeek:attr:`&default` = *...* :zeek:attr:`&redef` A table of cluster-enabled data stores that have been created, indexed
                                                                                                 by their name.
================================================================================================ ======================================================================

Types
#####
================================================================= ==========================================================================
:zeek:type:`Cluster::EndpointInfo`: :zeek:type:`record`           Information about a WebSocket endpoint.
:zeek:type:`Cluster::Event`: :zeek:type:`record`                  An event instance for cluster pub/sub.
:zeek:type:`Cluster::Info`: :zeek:type:`record` :zeek:attr:`&log` The record type which contains the column fields of the cluster log.
:zeek:type:`Cluster::NamedNode`: :zeek:type:`record`              Record to represent a cluster node including its name.
:zeek:type:`Cluster::NetworkInfo`: :zeek:type:`record`            Network information of an endpoint.
:zeek:type:`Cluster::Node`: :zeek:type:`record`                   Record type to indicate a node in a cluster.
:zeek:type:`Cluster::NodeType`: :zeek:type:`enum`                 Types of nodes that are allowed to participate in the cluster
                                                                  configuration.
:zeek:type:`Cluster::StoreInfo`: :zeek:type:`record`              Information regarding a cluster-enabled data store.
:zeek:type:`Cluster::WebSocketServerOptions`: :zeek:type:`record` WebSocket server options to pass to :zeek:see:`Cluster::listen_websocket`.
:zeek:type:`Cluster::WebSocketTLSOptions`: :zeek:type:`record`    The TLS options for a WebSocket server.
:zeek:type:`Cluster::BackendTag`: :zeek:type:`enum`               
:zeek:type:`Cluster::EventSerializerTag`: :zeek:type:`enum`       
:zeek:type:`Cluster::LogSerializerTag`: :zeek:type:`enum`         
================================================================= ==========================================================================

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
============================================================ =============================================================
:zeek:id:`Cluster::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
:zeek:id:`Cluster::on_subscribe`: :zeek:type:`hook`          A hook invoked for every :zeek:see:`Cluster::subscribe` call.
:zeek:id:`Cluster::on_unsubscribe`: :zeek:type:`hook`        A hook invoked for every :zeek:see:`Cluster::subscribe` call.
============================================================ =============================================================

Functions
#########
=========================================================================== =====================================================================
:zeek:id:`Cluster::create_store`: :zeek:type:`function`                     Sets up a cluster-enabled data store.
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
:zeek:id:`Cluster::subscribe`: :zeek:type:`function`                        Subscribe to the given topic.
:zeek:id:`Cluster::unsubscribe`: :zeek:type:`function`                      Unsubscribe from the given topic.
=========================================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Cluster::default_backend
   :source-code: base/frameworks/cluster/main.zeek 70 70

   :Type: :zeek:type:`Broker::BackendType`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Broker::MEMORY``

   The type of data store backend that will be used for all data stores if
   no other has already been specified by the user in :zeek:see:`Cluster::stores`.

.. zeek:id:: Cluster::default_master_node
   :source-code: base/frameworks/cluster/main.zeek 66 66

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Name of the node on which master data stores will be created if no other
   has already been specified by the user in :zeek:see:`Cluster::stores`.
   An empty value means "use whatever name corresponds to the manager
   node".

.. zeek:id:: Cluster::default_persistent_backend
   :source-code: base/frameworks/cluster/main.zeek 76 76

   :Type: :zeek:type:`Broker::BackendType`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Broker::SQLITE``

   The type of persistent data store backend that will be used for all data
   stores if no other has already been specified by the user in
   :zeek:see:`Cluster::stores`.  This will be used when script authors call
   :zeek:see:`Cluster::create_store` with the *persistent* argument set true.

.. zeek:id:: Cluster::default_store_dir
   :source-code: base/frameworks/cluster/main.zeek 95 95

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Setting a default dir will, for persistent backends that have not
   been given an explicit file path via :zeek:see:`Cluster::stores`,
   automatically create a path within this dir that is based on the name of
   the data store.

.. zeek:id:: Cluster::default_websocket_max_event_queue_size
   :source-code: base/frameworks/cluster/main.zeek 86 86

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``32``

   The default maximum queue size for WebSocket event dispatcher instances.
   
   If the maximum queue size is reached, events from external WebSocket
   clients will be stalled and processed once the queue has been drained.
   
   An internal metric named ``cluster_onloop_queue_stalls`` and
   labeled with a ``WebSocketEventDispatcher:<host>:<port>`` tag
   is incremented when the maximum queue size is reached.

.. zeek:id:: Cluster::default_websocket_ping_interval
   :source-code: base/frameworks/cluster/main.zeek 89 89

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 secs``

   The default ping interval for WebSocket clients.

.. zeek:id:: Cluster::enable_round_robin_logging
   :source-code: base/frameworks/cluster/main.zeek 25 25

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether to distribute log messages among available logging nodes.

.. zeek:id:: Cluster::logger_topic
   :source-code: base/frameworks/cluster/main.zeek 29 29

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/logger"``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/main.zeek`

      ``=``::

         zeek.cluster.logger


   The topic name used for exchanging messages that are relevant to
   logger nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::manager_is_logger
   :source-code: base/frameworks/cluster/main.zeek 252 252

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Indicates whether or not the manager will act as the logger and receive
   logs.  This value should be set in the cluster-layout.zeek script (the
   value should be true only if no logger is specified in Cluster::nodes).
   Note that ZeekControl handles this automatically.

.. zeek:id:: Cluster::manager_topic
   :source-code: base/frameworks/cluster/main.zeek 33 33

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/manager"``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/main.zeek`

      ``=``::

         zeek.cluster.manager


   The topic name used for exchanging messages that are relevant to
   manager nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::node
   :source-code: base/frameworks/cluster/main.zeek 256 256

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   This is usually supplied on the command line for each instance
   of the cluster that is started up.

.. zeek:id:: Cluster::node_topic_prefix
   :source-code: base/frameworks/cluster/main.zeek 56 56

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/node/"``

   The topic prefix used for exchanging messages that are relevant to
   a named node in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::nodeid_topic_prefix
   :source-code: base/frameworks/cluster/main.zeek 60 60

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/nodeid/"``

   The topic prefix used for exchanging messages that are relevant to
   a unique node in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::nodes
   :source-code: base/frameworks/cluster/main.zeek 237 237

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
   :source-code: base/frameworks/cluster/main.zeek 37 37

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/proxy"``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/main.zeek`

      ``=``::

         zeek.cluster.proxy


   The topic name used for exchanging messages that are relevant to
   proxy nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::retry_interval
   :source-code: base/frameworks/cluster/main.zeek 268 268

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   Interval for retrying failed connections between cluster nodes.
   If set, the ZEEK_DEFAULT_CONNECT_RETRY (given in number of seconds)
   environment variable overrides this option.

.. zeek:id:: Cluster::worker_topic
   :source-code: base/frameworks/cluster/main.zeek 41 41

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/worker"``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/main.zeek`

      ``=``::

         zeek.cluster.worker


   The topic name used for exchanging messages that are relevant to
   worker nodes in a cluster.  Used with broker-enabled cluster communication.

Constants
#########
.. zeek:id:: Cluster::broadcast_topics
   :source-code: base/frameworks/cluster/main.zeek 47 47

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

State Variables
###############
.. zeek:id:: Cluster::stores
   :source-code: base/frameworks/cluster/main.zeek 130 130

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Cluster::StoreInfo`
   :Attributes: :zeek:attr:`&default` = *[name=<uninitialized>, store=<uninitialized>, master_node=, master=F, backend=Broker::MEMORY, options=[sqlite=[path=, synchronous=<uninitialized>, journal_mode=<uninitialized>, failure_mode=Broker::SQLITE_FAILURE_MODE_FAIL, integrity_check=F]], clone_resync_interval=10.0 secs, clone_stale_interval=5.0 mins, clone_mutation_buffer_interval=2.0 mins]* :zeek:attr:`&redef`
   :Default: ``{}``

   A table of cluster-enabled data stores that have been created, indexed
   by their name.  This table will be populated automatically by
   :zeek:see:`Cluster::create_store`, but if you need to customize
   the options related to a particular data store, you may redef this
   table.  Calls to :zeek:see:`Cluster::create_store` will first check
   the table for an entry of the same name and, if found, will use the
   predefined options there when setting up the store.

Types
#####
.. zeek:type:: Cluster::EndpointInfo
   :source-code: base/frameworks/cluster/main.zeek 398 403

   :Type: :zeek:type:`record`


   .. zeek:field:: id :zeek:type:`string`


   .. zeek:field:: network :zeek:type:`Cluster::NetworkInfo`


   .. zeek:field:: application_name :zeek:type:`string` :zeek:attr:`&optional`

      The value of the X-Application-Name HTTP header, if any.


   Information about a WebSocket endpoint.

.. zeek:type:: Cluster::Event
   :source-code: base/frameworks/cluster/main.zeek 337 342

   :Type: :zeek:type:`record`


   .. zeek:field:: ev :zeek:type:`any`

      The event handler to be invoked on the remote node.


   .. zeek:field:: args :zeek:type:`vector` of :zeek:type:`any`

      The arguments for the event.


   An event instance for cluster pub/sub.
   
   See :zeek:see:`Cluster::publish` and :zeek:see:`Cluster::make_event`.

.. zeek:type:: Cluster::Info
   :source-code: base/frameworks/cluster/main.zeek 151 158

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The time at which a cluster message was generated.


   .. zeek:field:: node :zeek:type:`string` :zeek:attr:`&log`

      The name of the node that is creating the log record.


   .. zeek:field:: message :zeek:type:`string` :zeek:attr:`&log`

      A message indicating information about the cluster's operation.

   :Attributes: :zeek:attr:`&log`

   The record type which contains the column fields of the cluster log.

.. zeek:type:: Cluster::NamedNode
   :source-code: base/frameworks/cluster/main.zeek 204 207

   :Type: :zeek:type:`record`


   .. zeek:field:: name :zeek:type:`string`


   .. zeek:field:: node :zeek:type:`Cluster::Node`


   Record to represent a cluster node including its name.

.. zeek:type:: Cluster::NetworkInfo
   :source-code: base/frameworks/cluster/main.zeek 390 395

   :Type: :zeek:type:`record`


   .. zeek:field:: address :zeek:type:`string`

      The IP address or hostname where the endpoint listens.


   .. zeek:field:: bound_port :zeek:type:`port`

      The port where the endpoint is bound to.


   Network information of an endpoint.

.. zeek:type:: Cluster::Node
   :source-code: base/frameworks/cluster/main.zeek 181 201

   :Type: :zeek:type:`record`


   .. zeek:field:: node_type :zeek:type:`Cluster::NodeType`

      Identifies the type of cluster node in this node's configuration.


   .. zeek:field:: ip :zeek:type:`addr`

      The IP address of the cluster node.


   .. zeek:field:: zone_id :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      If the *ip* field is a non-global IPv6 address, this field
      can specify a particular :rfc:`4007` ``zone_id``.


   .. zeek:field:: p :zeek:type:`port` :zeek:attr:`&default` = ``0/unknown`` :zeek:attr:`&optional`

      The port that this node will listen on for peer connections.
      A value of ``0/unknown`` means the node is not pre-configured to listen.


   .. zeek:field:: manager :zeek:type:`string` :zeek:attr:`&optional`

      Name of the manager node this node uses.  For workers and proxies.


   .. zeek:field:: id :zeek:type:`string` :zeek:attr:`&optional`

      A unique identifier assigned to the node by the broker framework.
      This field is only set while a node is connected.


   .. zeek:field:: metrics_port :zeek:type:`port` :zeek:attr:`&optional`

      The port used to expose metrics to Prometheus. Setting this in a cluster
      configuration will override the setting for Telemetry::metrics_port for
      the node.


   Record type to indicate a node in a cluster.

.. zeek:type:: Cluster::NodeType
   :source-code: base/frameworks/cluster/main.zeek 162 179

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Cluster::NONE Cluster::NodeType

         A dummy node type indicating the local node is not operating
         within a cluster.

      .. zeek:enum:: Cluster::CONTROL Cluster::NodeType

         A node type which is allowed to view/manipulate the configuration
         of other nodes in the cluster.

      .. zeek:enum:: Cluster::LOGGER Cluster::NodeType

         A node type responsible for log management.

      .. zeek:enum:: Cluster::MANAGER Cluster::NodeType

         A node type responsible for policy management.

      .. zeek:enum:: Cluster::PROXY Cluster::NodeType

         A node type for relaying worker node communication and synchronizing
         worker node state.

      .. zeek:enum:: Cluster::WORKER Cluster::NodeType

         The node type doing all the actual traffic analysis.

   Types of nodes that are allowed to participate in the cluster
   configuration.

.. zeek:type:: Cluster::StoreInfo
   :source-code: base/frameworks/cluster/main.zeek 98 121

   :Type: :zeek:type:`record`


   .. zeek:field:: name :zeek:type:`string` :zeek:attr:`&optional`

      The name of the data store.


   .. zeek:field:: store :zeek:type:`opaque` of Broker::Store :zeek:attr:`&optional`

      The store handle.


   .. zeek:field:: master_node :zeek:type:`string` :zeek:attr:`&default` = :zeek:see:`Cluster::default_master_node` :zeek:attr:`&optional`

      The name of the cluster node on which the master version of the data
      store resides.


   .. zeek:field:: master :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Whether the data store is the master version or a clone.


   .. zeek:field:: backend :zeek:type:`Broker::BackendType` :zeek:attr:`&default` = :zeek:see:`Cluster::default_backend` :zeek:attr:`&optional`

      The type of backend used for storing data.


   .. zeek:field:: options :zeek:type:`Broker::BackendOptions` :zeek:attr:`&default` = *...* :zeek:attr:`&optional`

      Parameters used for configuring the backend.


   .. zeek:field:: clone_resync_interval :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_resync_interval` :zeek:attr:`&optional`

      A resync/reconnect interval to pass through to
      :zeek:see:`Broker::create_clone`.


   .. zeek:field:: clone_stale_interval :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_stale_interval` :zeek:attr:`&optional`

      A staleness duration to pass through to
      :zeek:see:`Broker::create_clone`.


   .. zeek:field:: clone_mutation_buffer_interval :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_mutation_buffer_interval` :zeek:attr:`&optional`

      A mutation buffer interval to pass through to
      :zeek:see:`Broker::create_clone`.


   Information regarding a cluster-enabled data store.

.. zeek:type:: Cluster::WebSocketServerOptions
   :source-code: base/frameworks/cluster/main.zeek 364 380

   :Type: :zeek:type:`record`


   .. zeek:field:: listen_host :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&deprecated` = *...*

      The host address to listen on.


   .. zeek:field:: listen_addr :zeek:type:`addr` :zeek:attr:`&optional`

      The address to listen on, cannot be used together with ``listen_host``.


   .. zeek:field:: listen_port :zeek:type:`port`

      The port the WebSocket server is supposed to listen on.


   .. zeek:field:: max_event_queue_size :zeek:type:`count` :zeek:attr:`&default` = :zeek:see:`Cluster::default_websocket_max_event_queue_size` :zeek:attr:`&optional`

      The maximum event queue size for this server.


   .. zeek:field:: ping_interval :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Cluster::default_websocket_ping_interval` :zeek:attr:`&optional`

      Ping interval to use. A WebSocket client not responding to
      the pings will be disconnected. Set to a negative value to
      disable pings. Subsecond intervals are currently not supported.


   .. zeek:field:: tls_options :zeek:type:`Cluster::WebSocketTLSOptions` :zeek:attr:`&default` = *...* :zeek:attr:`&optional`

      The TLS options used for this WebSocket server. By default,
      TLS is disabled. See also :zeek:see:`Cluster::WebSocketTLSOptions`.


   WebSocket server options to pass to :zeek:see:`Cluster::listen_websocket`.

.. zeek:type:: Cluster::WebSocketTLSOptions
   :source-code: base/frameworks/cluster/main.zeek 348 361

   :Type: :zeek:type:`record`


   .. zeek:field:: cert_file :zeek:type:`string` :zeek:attr:`&optional`

      The cert file to use.


   .. zeek:field:: key_file :zeek:type:`string` :zeek:attr:`&optional`

      The key file to use.


   .. zeek:field:: enable_peer_verification :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Expect peers to send client certificates.


   .. zeek:field:: ca_file :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      The CA certificate or CA bundle used for peer verification.
      Empty will use the implementations's default when
      ``enable_peer_verification`` is T.


   .. zeek:field:: ciphers :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      The ciphers to use. Empty will use the implementation's defaults.


   The TLS options for a WebSocket server.
   
   If cert_file and key_file are set, TLS is enabled. If both
   are unset, TLS is disabled. Any other combination is an error.

.. zeek:type:: Cluster::BackendTag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Cluster::CLUSTER_BACKEND_BROKER Cluster::BackendTag

      .. zeek:enum:: Cluster::CLUSTER_BACKEND_BROKER_WEBSOCKET_SHIM Cluster::BackendTag

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
   :source-code: base/frameworks/cluster/main.zeek 512 537

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, nodes broadcast this event
   to exchange their user-defined name along with a string that uniquely
   identifies it for the duration of its lifetime.  This string may change
   if the node dies and has to reconnect later.

.. zeek:id:: Cluster::node_down
   :source-code: base/frameworks/cluster/main.zeek 282 282

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a connected cluster node becomes disconnected.

.. zeek:id:: Cluster::node_up
   :source-code: base/frameworks/cluster/main.zeek 278 278

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a cluster node connects or reconnects.

Hooks
#####
.. zeek:id:: Cluster::log_policy
   :source-code: base/frameworks/cluster/main.zeek 148 148

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

.. zeek:id:: Cluster::on_subscribe
   :source-code: base/frameworks/cluster/main.zeek 410 410

   :Type: :zeek:type:`hook` (topic: :zeek:type:`string`) : :zeek:type:`bool`

   A hook invoked for every :zeek:see:`Cluster::subscribe` call.
   
   Breaking from this hook has no effect.
   

   :param topic: The topic string as given to :zeek:see:`Cluster::subscribe`.

.. zeek:id:: Cluster::on_unsubscribe
   :source-code: base/frameworks/cluster/main.zeek 417 417

   :Type: :zeek:type:`hook` (topic: :zeek:type:`string`) : :zeek:type:`bool`

   A hook invoked for every :zeek:see:`Cluster::subscribe` call.
   
   Breaking from this hook has no effect.
   

   :param topic: The topic string as given to :zeek:see:`Cluster::subscribe`.

Functions
#########
.. zeek:id:: Cluster::create_store
   :source-code: base/frameworks/cluster/main.zeek 592 667

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, persistent: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`Cluster::StoreInfo`

   Sets up a cluster-enabled data store.  They will also still properly
   function for uses that are not operating a cluster.
   

   :param name: the name of the data store to create.
   

   :param persistent: whether the data store must be persistent.
   

   :returns: the store's information.  For master stores, the store will be
            ready to use immediately.  For clones, the store field will not
            be set until the node containing the master store has connected.

.. zeek:id:: Cluster::get_active_node_count
   :source-code: base/frameworks/cluster/main.zeek 456 459

   :Type: :zeek:type:`function` (node_type: :zeek:type:`Cluster::NodeType`) : :zeek:type:`count`

   Returns the number of nodes per type, the calling node is currently
   connected to. This is primarily intended for use by the manager to find
   out how many nodes should be responding to requests.

.. zeek:id:: Cluster::get_node_count
   :source-code: base/frameworks/cluster/main.zeek 443 454

   :Type: :zeek:type:`function` (node_type: :zeek:type:`Cluster::NodeType`) : :zeek:type:`count`

   Returns the number of nodes defined in the cluster layout for a given
   node type.

.. zeek:id:: Cluster::init
   :source-code: base/frameworks/cluster/main.zeek 674 677

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Initialize the cluster backend.
   
   Cluster backends usually invoke this from a :zeek:see:`zeek_init` handler.
   

   :returns: T on success, else F.

.. zeek:id:: Cluster::is_enabled
   :source-code: base/frameworks/cluster/main.zeek 461 464

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   This function can be called at any time to determine if the cluster
   framework is being enabled for this run.
   

   :returns: True if :zeek:id:`Cluster::node` has been set.

.. zeek:id:: Cluster::listen_websocket
   :source-code: base/frameworks/cluster/main.zeek 689 692

   :Type: :zeek:type:`function` (options: :zeek:type:`Cluster::WebSocketServerOptions`) : :zeek:type:`bool`

   Start listening on a WebSocket address.
   

   :param options: The server :zeek:see:`Cluster::WebSocketServerOptions` to use.
   

   :returns: T on success, else F.

.. zeek:id:: Cluster::local_node_metrics_port
   :source-code: base/frameworks/cluster/main.zeek 477 489

   :Type: :zeek:type:`function` () : :zeek:type:`port`

   This function can be called at any time to determine the configured
   metrics port for Prometheus being used by current Zeek instance. If
   :zeek:id:`Cluster::is_enabled` returns false or the node isn't found,
   ``0/unknown`` is returned.
   

   :returns: The metrics port used by the calling node.

.. zeek:id:: Cluster::local_node_type
   :source-code: base/frameworks/cluster/main.zeek 466 475

   :Type: :zeek:type:`function` () : :zeek:type:`Cluster::NodeType`

   This function can be called at any time to determine what type of
   cluster node the current Zeek instance is going to be acting as.
   If :zeek:id:`Cluster::is_enabled` returns false, then
   :zeek:enum:`Cluster::NONE` is returned.
   

   :returns: The :zeek:type:`Cluster::NodeType` the calling node acts as.

.. zeek:id:: Cluster::log
   :source-code: base/frameworks/cluster/main.zeek 669 672

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`void`

   Write a message to the cluster logging stream.

.. zeek:id:: Cluster::node_id
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 355 357

   :Type: :zeek:type:`function` () : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   Function returning this node's identifier.
   
   By default this is :zeek:see:`Broker::node_id`, but can be
   redefined by other cluster backends. This identifier should be
   a short lived identifier that resets when a node is restarted.

.. zeek:id:: Cluster::node_topic
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 340 342

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   Retrieve the topic associated with a specific node in the cluster.
   

   :param name: the name of the cluster node (e.g. "manager").
   

   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.

.. zeek:id:: Cluster::nodeid_to_node
   :source-code: base/frameworks/cluster/main.zeek 501 510

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`Cluster::NamedNode`

   Retrieve the cluster-level naming of a node based on its node ID,
   a backend-specific identifier.
   

   :param id: the node ID of a peer.
   

   :returns: the :zeek:see:`Cluster::NamedNode` for the requested node, if
            known, otherwise a "null" instance with an empty name field.

.. zeek:id:: Cluster::nodeid_topic
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 344 346

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   Retrieve the topic associated with a specific node in the cluster.
   

   :param id: the id of the cluster node (from :zeek:see:`Broker::EndpointInfo`
       or :zeek:see:`Broker::node_id`.
   

   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.

.. zeek:id:: Cluster::subscribe
   :source-code: base/frameworks/cluster/main.zeek 679 682

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`) : :zeek:type:`bool`

   Subscribe to the given topic.
   

   :param topic: The topic to subscribe to.
   

   :returns: T on success, else F.

.. zeek:id:: Cluster::unsubscribe
   :source-code: base/frameworks/cluster/main.zeek 684 687

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`) : :zeek:type:`bool`

   Unsubscribe from the given topic.
   

   :param topic: The topic to unsubscribe from.
   

   :returns: T on success, else F.


