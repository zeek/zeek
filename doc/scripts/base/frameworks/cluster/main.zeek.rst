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
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/control </scripts/base/frameworks/control/index>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================================================== ===============================================================================
:zeek:id:`Cluster::default_backend`: :zeek:type:`Broker::BackendType` :zeek:attr:`&redef`                                                The type of data store backend that will be used for all data stores if
                                                                                                                                         no other has already been specified by the user in :zeek:see:`Cluster::stores`.
:zeek:id:`Cluster::default_master_node`: :zeek:type:`string` :zeek:attr:`&redef`                                                         Name of the node on which master data stores will be created if no other
                                                                                                                                         has already been specified by the user in :zeek:see:`Cluster::stores`.
:zeek:id:`Cluster::default_persistent_backend`: :zeek:type:`Broker::BackendType` :zeek:attr:`&redef`                                     The type of persistent data store backend that will be used for all data
                                                                                                                                         stores if no other has already been specified by the user in
                                                                                                                                         :zeek:see:`Cluster::stores`.
:zeek:id:`Cluster::default_store_dir`: :zeek:type:`string` :zeek:attr:`&redef`                                                           Setting a default dir will, for persistent backends that have not
                                                                                                                                         been given an explicit file path via :zeek:see:`Cluster::stores`,
                                                                                                                                         automatically create a path within this dir that is based on the name of
                                                                                                                                         the data store.
:zeek:id:`Cluster::enable_round_robin_logging`: :zeek:type:`bool` :zeek:attr:`&redef`                                                    Whether to distribute log messages among available logging nodes.
:zeek:id:`Cluster::logger_topic`: :zeek:type:`string` :zeek:attr:`&redef`                                                                The topic name used for exchanging messages that are relevant to
                                                                                                                                         logger nodes in a cluster.
:zeek:id:`Cluster::manager_is_logger`: :zeek:type:`bool` :zeek:attr:`&redef`                                                             Indicates whether or not the manager will act as the logger and receive
                                                                                                                                         logs.
:zeek:id:`Cluster::manager_topic`: :zeek:type:`string` :zeek:attr:`&redef`                                                               The topic name used for exchanging messages that are relevant to
                                                                                                                                         manager nodes in a cluster.
:zeek:id:`Cluster::node`: :zeek:type:`string` :zeek:attr:`&redef`                                                                        This is usually supplied on the command line for each instance
                                                                                                                                         of the cluster that is started up.
:zeek:id:`Cluster::node_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                                                           The topic prefix used for exchanging messages that are relevant to
                                                                                                                                         a named node in a cluster.
:zeek:id:`Cluster::nodeid_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                                                         The topic prefix used for exchanging messages that are relevant to
                                                                                                                                         a unique node in a cluster.
:zeek:id:`Cluster::nodes`: :zeek:type:`table` :zeek:attr:`&redef`                                                                        The cluster layout definition.
:zeek:id:`Cluster::proxy_topic`: :zeek:type:`string` :zeek:attr:`&redef`                                                                 The topic name used for exchanging messages that are relevant to
                                                                                                                                         proxy nodes in a cluster.
:zeek:id:`Cluster::retry_interval`: :zeek:type:`interval` :zeek:attr:`&redef`                                                            Interval for retrying failed connections between cluster nodes.
:zeek:id:`Cluster::time_machine_topic`: :zeek:type:`string` :zeek:attr:`&redef` :zeek:attr:`&deprecated` = ``"Remove in v7.1: Unused."`` The topic name used for exchanging messages that are relevant to
                                                                                                                                         time machine nodes in a cluster.
:zeek:id:`Cluster::worker_topic`: :zeek:type:`string` :zeek:attr:`&redef`                                                                The topic name used for exchanging messages that are relevant to
                                                                                                                                         worker nodes in a cluster.
======================================================================================================================================== ===============================================================================

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
================================================================= ====================================================================
:zeek:type:`Cluster::Info`: :zeek:type:`record` :zeek:attr:`&log` The record type which contains the column fields of the cluster log.
:zeek:type:`Cluster::NamedNode`: :zeek:type:`record`              Record to represent a cluster node including its name.
:zeek:type:`Cluster::Node`: :zeek:type:`record`                   Record type to indicate a node in a cluster.
:zeek:type:`Cluster::NodeType`: :zeek:type:`enum`                 Types of nodes that are allowed to participate in the cluster
                                                                  configuration.
:zeek:type:`Cluster::StoreInfo`: :zeek:type:`record`              Information regarding a cluster-enabled data store.
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
============================================================ =============================================
:zeek:id:`Cluster::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
============================================================ =============================================

Functions
#########
================================================================== =====================================================================
:zeek:id:`Cluster::create_store`: :zeek:type:`function`            Sets up a cluster-enabled data store.
:zeek:id:`Cluster::get_active_node_count`: :zeek:type:`function`   Returns the number of nodes per type, the calling node is currently
                                                                   connected to.
:zeek:id:`Cluster::get_node_count`: :zeek:type:`function`          Returns the number of nodes defined in the cluster layout for a given
                                                                   node type.
:zeek:id:`Cluster::is_enabled`: :zeek:type:`function`              This function can be called at any time to determine if the cluster
                                                                   framework is being enabled for this run.
:zeek:id:`Cluster::local_node_metrics_port`: :zeek:type:`function` This function can be called at any time to determine the configured
                                                                   metrics port for Prometheus being used by current Zeek instance.
:zeek:id:`Cluster::local_node_type`: :zeek:type:`function`         This function can be called at any time to determine what type of
                                                                   cluster node the current Zeek instance is going to be acting as.
:zeek:id:`Cluster::log`: :zeek:type:`function`                     Write a message to the cluster logging stream.
:zeek:id:`Cluster::node_topic`: :zeek:type:`function`              Retrieve the topic associated with a specific node in the cluster.
:zeek:id:`Cluster::nodeid_topic`: :zeek:type:`function`            Retrieve the topic associated with a specific node in the cluster.
================================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Cluster::default_backend
   :source-code: base/frameworks/cluster/main.zeek 77 77

   :Type: :zeek:type:`Broker::BackendType`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Broker::MEMORY``

   The type of data store backend that will be used for all data stores if
   no other has already been specified by the user in :zeek:see:`Cluster::stores`.

.. zeek:id:: Cluster::default_master_node
   :source-code: base/frameworks/cluster/main.zeek 73 73

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Name of the node on which master data stores will be created if no other
   has already been specified by the user in :zeek:see:`Cluster::stores`.
   An empty value means "use whatever name corresponds to the manager
   node".

.. zeek:id:: Cluster::default_persistent_backend
   :source-code: base/frameworks/cluster/main.zeek 83 83

   :Type: :zeek:type:`Broker::BackendType`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Broker::SQLITE``

   The type of persistent data store backend that will be used for all data
   stores if no other has already been specified by the user in
   :zeek:see:`Cluster::stores`.  This will be used when script authors call
   :zeek:see:`Cluster::create_store` with the *persistent* argument set true.

.. zeek:id:: Cluster::default_store_dir
   :source-code: base/frameworks/cluster/main.zeek 89 89

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Setting a default dir will, for persistent backends that have not
   been given an explicit file path via :zeek:see:`Cluster::stores`,
   automatically create a path within this dir that is based on the name of
   the data store.

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

   The topic name used for exchanging messages that are relevant to
   logger nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::manager_is_logger
   :source-code: base/frameworks/cluster/main.zeek 254 254

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

   The topic name used for exchanging messages that are relevant to
   manager nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::node
   :source-code: base/frameworks/cluster/main.zeek 258 258

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   This is usually supplied on the command line for each instance
   of the cluster that is started up.

.. zeek:id:: Cluster::node_topic_prefix
   :source-code: base/frameworks/cluster/main.zeek 63 63

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/node/"``

   The topic prefix used for exchanging messages that are relevant to
   a named node in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::nodeid_topic_prefix
   :source-code: base/frameworks/cluster/main.zeek 67 67

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/nodeid/"``

   The topic prefix used for exchanging messages that are relevant to
   a unique node in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::nodes
   :source-code: base/frameworks/cluster/main.zeek 239 239

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

   The topic name used for exchanging messages that are relevant to
   proxy nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::retry_interval
   :source-code: base/frameworks/cluster/main.zeek 263 263

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min``

   Interval for retrying failed connections between cluster nodes.
   If set, the ZEEK_DEFAULT_CONNECT_RETRY (given in number of seconds)
   environment variable overrides this option.

.. zeek:id:: Cluster::time_machine_topic
   :source-code: base/frameworks/cluster/main.zeek 45 45

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef` :zeek:attr:`&deprecated` = ``"Remove in v7.1: Unused."``
   :Default: ``"zeek/cluster/time_machine"``

   The topic name used for exchanging messages that are relevant to
   time machine nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::worker_topic
   :source-code: base/frameworks/cluster/main.zeek 41 41

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster/worker"``

   The topic name used for exchanging messages that are relevant to
   worker nodes in a cluster.  Used with broker-enabled cluster communication.

Constants
#########
.. zeek:id:: Cluster::broadcast_topics
   :source-code: base/frameworks/cluster/main.zeek 51 51

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Default:

      ::

         {
            "zeek/cluster/manager",
            "zeek/cluster/logger",
            "zeek/cluster/proxy",
            "zeek/cluster/worker",
            "zeek/cluster/time_machine"
         }


   A set of topic names to be used for broadcasting messages that are
   relevant to all nodes in a cluster. Currently, there is not a common
   topic to broadcast to, because enabling implicit Broker forwarding would
   cause a routing loop for this topic.

State Variables
###############
.. zeek:id:: Cluster::stores
   :source-code: base/frameworks/cluster/main.zeek 124 124

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
.. zeek:type:: Cluster::Info
   :source-code: base/frameworks/cluster/main.zeek 145 152

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The time at which a cluster message was generated.

      node: :zeek:type:`string` :zeek:attr:`&log`
         The name of the node that is creating the log record.

      message: :zeek:type:`string` :zeek:attr:`&log`
         A message indicating information about the cluster's operation.
   :Attributes: :zeek:attr:`&log`

   The record type which contains the column fields of the cluster log.

.. zeek:type:: Cluster::NamedNode
   :source-code: base/frameworks/cluster/main.zeek 206 209

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`

      node: :zeek:type:`Cluster::Node`

   Record to represent a cluster node including its name.

.. zeek:type:: Cluster::Node
   :source-code: base/frameworks/cluster/main.zeek 179 203

   :Type: :zeek:type:`record`

      node_type: :zeek:type:`Cluster::NodeType`
         Identifies the type of cluster node in this node's configuration.

      ip: :zeek:type:`addr`
         The IP address of the cluster node.

      zone_id: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         If the *ip* field is a non-global IPv6 address, this field
         can specify a particular :rfc:`4007` ``zone_id``.

      p: :zeek:type:`port` :zeek:attr:`&default` = ``0/unknown`` :zeek:attr:`&optional`
         The port that this node will listen on for peer connections.
         A value of ``0/unknown`` means the node is not pre-configured to listen.

      interface: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&deprecated` = *"Remove in v7.1: interface is not required and not set consistently on workers. Replace usages with packet_source() or keep a separate worker-to-interface mapping in a global table."*
         Identifier for the interface a worker is sniffing.

      manager: :zeek:type:`string` :zeek:attr:`&optional`
         Name of the manager node this node uses.  For workers and proxies.

      time_machine: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&deprecated` = ``"Remove in v7.1: Unused."``
         Name of a time machine node with which this node connects.

      id: :zeek:type:`string` :zeek:attr:`&optional`
         A unique identifier assigned to the node by the broker framework.
         This field is only set while a node is connected.

      metrics_port: :zeek:type:`port` :zeek:attr:`&optional`
         The port used to expose metrics to Prometheus. Setting this in a cluster
         configuration will override the setting for Telemetry::metrics_port for
         the node.

      lb_filter: :zeek:type:`string` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/misc/load-balancing.zeek` is loaded)

         A BPF filter for load balancing traffic sniffed on a single
         interface across a number of processes.  In normal uses, this
         will be assigned dynamically by the manager and installed by
         the workers.

   Record type to indicate a node in a cluster.

.. zeek:type:: Cluster::NodeType
   :source-code: base/frameworks/cluster/main.zeek 156 177

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

      .. zeek:enum:: Cluster::TIME_MACHINE Cluster::NodeType

         A node acting as a traffic recorder using the
         `Time Machine <https://github.com/zeek/time-machine>`_
         software.

   Types of nodes that are allowed to participate in the cluster
   configuration.

.. zeek:type:: Cluster::StoreInfo
   :source-code: base/frameworks/cluster/main.zeek 92 115

   :Type: :zeek:type:`record`

      name: :zeek:type:`string` :zeek:attr:`&optional`
         The name of the data store.

      store: :zeek:type:`opaque` of Broker::Store :zeek:attr:`&optional`
         The store handle.

      master_node: :zeek:type:`string` :zeek:attr:`&default` = :zeek:see:`Cluster::default_master_node` :zeek:attr:`&optional`
         The name of the cluster node on which the master version of the data
         store resides.

      master: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Whether the data store is the master version or a clone.

      backend: :zeek:type:`Broker::BackendType` :zeek:attr:`&default` = :zeek:see:`Cluster::default_backend` :zeek:attr:`&optional`
         The type of backend used for storing data.

      options: :zeek:type:`Broker::BackendOptions` :zeek:attr:`&default` = *[sqlite=[path=, synchronous=<uninitialized>, journal_mode=<uninitialized>, failure_mode=Broker::SQLITE_FAILURE_MODE_FAIL, integrity_check=F]]* :zeek:attr:`&optional`
         Parameters used for configuring the backend.

      clone_resync_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_resync_interval` :zeek:attr:`&optional`
         A resync/reconnect interval to pass through to
         :zeek:see:`Broker::create_clone`.

      clone_stale_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_stale_interval` :zeek:attr:`&optional`
         A staleness duration to pass through to
         :zeek:see:`Broker::create_clone`.

      clone_mutation_buffer_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_mutation_buffer_interval` :zeek:attr:`&optional`
         A mutation buffer interval to pass through to
         :zeek:see:`Broker::create_clone`.

   Information regarding a cluster-enabled data store.

Events
######
.. zeek:id:: Cluster::hello
   :source-code: base/frameworks/cluster/main.zeek 377 402

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, nodes broadcast this event
   to exchange their user-defined name along with a string that uniquely
   identifies it for the duration of its lifetime.  This string may change
   if the node dies and has to reconnect later.

.. zeek:id:: Cluster::node_down
   :source-code: base/frameworks/cluster/main.zeek 277 277

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a connected cluster node becomes disconnected.

.. zeek:id:: Cluster::node_up
   :source-code: base/frameworks/cluster/main.zeek 273 273

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a cluster node connects or reconnects.

Hooks
#####
.. zeek:id:: Cluster::log_policy
   :source-code: base/frameworks/cluster/main.zeek 142 142

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: Cluster::create_store
   :source-code: base/frameworks/cluster/main.zeek 441 516

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, persistent: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`Cluster::StoreInfo`

   Sets up a cluster-enabled data store.  They will also still properly
   function for uses that are not operating a cluster.
   

   :param name: the name of the data store to create.
   

   :param persistent: whether the data store must be persistent.
   

   :returns: the store's information.  For master stores, the store will be
            ready to use immediately.  For clones, the store field will not
            be set until the node containing the master store has connected.

.. zeek:id:: Cluster::get_active_node_count
   :source-code: base/frameworks/cluster/main.zeek 332 335

   :Type: :zeek:type:`function` (node_type: :zeek:type:`Cluster::NodeType`) : :zeek:type:`count`

   Returns the number of nodes per type, the calling node is currently
   connected to. This is primarily intended for use by the manager to find
   out how many nodes should be responding to requests.

.. zeek:id:: Cluster::get_node_count
   :source-code: base/frameworks/cluster/main.zeek 319 330

   :Type: :zeek:type:`function` (node_type: :zeek:type:`Cluster::NodeType`) : :zeek:type:`count`

   Returns the number of nodes defined in the cluster layout for a given
   node type.

.. zeek:id:: Cluster::is_enabled
   :source-code: base/frameworks/cluster/main.zeek 337 340

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   This function can be called at any time to determine if the cluster
   framework is being enabled for this run.
   

   :returns: True if :zeek:id:`Cluster::node` has been set.

.. zeek:id:: Cluster::local_node_metrics_port
   :source-code: base/frameworks/cluster/main.zeek 353 365

   :Type: :zeek:type:`function` () : :zeek:type:`port`

   This function can be called at any time to determine the configured
   metrics port for Prometheus being used by current Zeek instance. If
   :zeek:id:`Cluster::is_enabled` returns false or the node isn't found,
   ``0/unknown`` is returned.
   

   :returns: The metrics port used by the calling node.

.. zeek:id:: Cluster::local_node_type
   :source-code: base/frameworks/cluster/main.zeek 342 351

   :Type: :zeek:type:`function` () : :zeek:type:`Cluster::NodeType`

   This function can be called at any time to determine what type of
   cluster node the current Zeek instance is going to be acting as.
   If :zeek:id:`Cluster::is_enabled` returns false, then
   :zeek:enum:`Cluster::NONE` is returned.
   

   :returns: The :zeek:type:`Cluster::NodeType` the calling node acts as.

.. zeek:id:: Cluster::log
   :source-code: base/frameworks/cluster/main.zeek 518 521

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`void`

   Write a message to the cluster logging stream.

.. zeek:id:: Cluster::node_topic
   :source-code: base/frameworks/cluster/main.zeek 367 370

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the topic associated with a specific node in the cluster.
   

   :param name: the name of the cluster node (e.g. "manager").
   

   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.

.. zeek:id:: Cluster::nodeid_topic
   :source-code: base/frameworks/cluster/main.zeek 372 375

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the topic associated with a specific node in the cluster.
   

   :param id: the id of the cluster node (from :zeek:see:`Broker::EndpointInfo`
       or :zeek:see:`Broker::node_id`.
   

   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.


