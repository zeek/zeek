:tocdepth: 3

base/frameworks/cluster/main.bro
================================
.. bro:namespace:: Cluster

A framework for establishing and controlling a cluster of Bro instances.
In order to use the cluster framework, a script named
``cluster-layout.bro`` must exist somewhere in Bro's script search path
which has a cluster definition of the :bro:id:`Cluster::nodes` variable.
The ``CLUSTER_NODE`` environment variable or :bro:id:`Cluster::node`
must also be sent and the cluster framework loaded as a package like
``@load base/frameworks/cluster``.

:Namespace: Cluster
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/control </scripts/base/frameworks/control/index>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================= ==============================================================================
:bro:id:`Cluster::default_backend`: :bro:type:`Broker::BackendType` :bro:attr:`&redef`            The type of data store backend that will be used for all data stores if
                                                                                                  no other has already been specified by the user in :bro:see:`Cluster::stores`.
:bro:id:`Cluster::default_master_node`: :bro:type:`string` :bro:attr:`&redef`                     Name of the node on which master data stores will be created if no other
                                                                                                  has already been specified by the user in :bro:see:`Cluster::stores`.
:bro:id:`Cluster::default_persistent_backend`: :bro:type:`Broker::BackendType` :bro:attr:`&redef` The type of persistent data store backend that will be used for all data
                                                                                                  stores if no other has already been specified by the user in
                                                                                                  :bro:see:`Cluster::stores`.
:bro:id:`Cluster::default_store_dir`: :bro:type:`string` :bro:attr:`&redef`                       Setting a default dir will, for persistent backends that have not
                                                                                                  been given an explicit file path via :bro:see:`Cluster::stores`,
                                                                                                  automatically create a path within this dir that is based on the name of
                                                                                                  the data store.
:bro:id:`Cluster::enable_round_robin_logging`: :bro:type:`bool` :bro:attr:`&redef`                Whether to distribute log messages among available logging nodes.
:bro:id:`Cluster::logger_topic`: :bro:type:`string` :bro:attr:`&redef`                            The topic name used for exchanging messages that are relevant to
                                                                                                  logger nodes in a cluster.
:bro:id:`Cluster::manager_is_logger`: :bro:type:`bool` :bro:attr:`&redef`                         Indicates whether or not the manager will act as the logger and receive
                                                                                                  logs.
:bro:id:`Cluster::manager_topic`: :bro:type:`string` :bro:attr:`&redef`                           The topic name used for exchanging messages that are relevant to
                                                                                                  manager nodes in a cluster.
:bro:id:`Cluster::node`: :bro:type:`string` :bro:attr:`&redef`                                    This is usually supplied on the command line for each instance
                                                                                                  of the cluster that is started up.
:bro:id:`Cluster::node_topic_prefix`: :bro:type:`string` :bro:attr:`&redef`                       The topic prefix used for exchanging messages that are relevant to
                                                                                                  a named node in a cluster.
:bro:id:`Cluster::nodeid_topic_prefix`: :bro:type:`string` :bro:attr:`&redef`                     The topic prefix used for exchanging messages that are relevant to
                                                                                                  a unique node in a cluster.
:bro:id:`Cluster::nodes`: :bro:type:`table` :bro:attr:`&redef`                                    The cluster layout definition.
:bro:id:`Cluster::proxy_topic`: :bro:type:`string` :bro:attr:`&redef`                             The topic name used for exchanging messages that are relevant to
                                                                                                  proxy nodes in a cluster.
:bro:id:`Cluster::retry_interval`: :bro:type:`interval` :bro:attr:`&redef`                        Interval for retrying failed connections between cluster nodes.
:bro:id:`Cluster::time_machine_topic`: :bro:type:`string` :bro:attr:`&redef`                      The topic name used for exchanging messages that are relevant to
                                                                                                  time machine nodes in a cluster.
:bro:id:`Cluster::worker_topic`: :bro:type:`string` :bro:attr:`&redef`                            The topic name used for exchanging messages that are relevant to
                                                                                                  worker nodes in a cluster.
================================================================================================= ==============================================================================

State Variables
###############
================================================================================================================================================================================================================================================================================================================================================================== ======================================================================
:bro:id:`Cluster::stores`: :bro:type:`table` :bro:attr:`&default` = ``[name=<uninitialized>, store=<uninitialized>, master_node=, master=F, backend=Broker::MEMORY, options=[sqlite=[path=], rocksdb=[path=]], clone_resync_interval=10.0 secs, clone_stale_interval=5.0 mins, clone_mutation_buffer_interval=2.0 mins]`` :bro:attr:`&optional` :bro:attr:`&redef` A table of cluster-enabled data stores that have been created, indexed
                                                                                                                                                                                                                                                                                                                                                                   by their name.
:bro:id:`Cluster::worker_count`: :bro:type:`count`                                                                                                                                                                                                                                                                                                                 This gives the value for the number of workers currently connected to,
                                                                                                                                                                                                                                                                                                                                                                   and it's maintained internally by the cluster framework.
================================================================================================================================================================================================================================================================================================================================================================== ======================================================================

Types
#####
============================================================== ====================================================================
:bro:type:`Cluster::Info`: :bro:type:`record` :bro:attr:`&log` The record type which contains the column fields of the cluster log.
:bro:type:`Cluster::Node`: :bro:type:`record`                  Record type to indicate a node in a cluster.
:bro:type:`Cluster::NodeType`: :bro:type:`enum`                Types of nodes that are allowed to participate in the cluster
                                                               configuration.
:bro:type:`Cluster::StoreInfo`: :bro:type:`record`             Information regarding a cluster-enabled data store.
============================================================== ====================================================================

Redefinitions
#############
===================================== ======================================
:bro:type:`Log::ID`: :bro:type:`enum` The cluster logging stream identifier.
===================================== ======================================

Events
######
=============================================== =======================================================================
:bro:id:`Cluster::hello`: :bro:type:`event`     When using broker-enabled cluster framework, nodes broadcast this event
                                                to exchange their user-defined name along with a string that uniquely
                                                identifies it for the duration of its lifetime.
:bro:id:`Cluster::node_down`: :bro:type:`event` When using broker-enabled cluster framework, this event will be emitted
                                                locally whenever a connected cluster node becomes disconnected.
:bro:id:`Cluster::node_up`: :bro:type:`event`   When using broker-enabled cluster framework, this event will be emitted
                                                locally whenever a cluster node connects or reconnects.
=============================================== =======================================================================

Functions
#########
======================================================== ===================================================================
:bro:id:`Cluster::create_store`: :bro:type:`function`    Sets up a cluster-enabled data store.
:bro:id:`Cluster::is_enabled`: :bro:type:`function`      This function can be called at any time to determine if the cluster
                                                         framework is being enabled for this run.
:bro:id:`Cluster::local_node_type`: :bro:type:`function` This function can be called at any time to determine what type of
                                                         cluster node the current Bro instance is going to be acting as.
:bro:id:`Cluster::log`: :bro:type:`function`             Write a message to the cluster logging stream.
:bro:id:`Cluster::node_topic`: :bro:type:`function`      Retrieve the topic associated with a specific node in the cluster.
:bro:id:`Cluster::nodeid_topic`: :bro:type:`function`    Retrieve the topic associated with a specific node in the cluster.
======================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Cluster::default_backend

   :Type: :bro:type:`Broker::BackendType`
   :Attributes: :bro:attr:`&redef`
   :Default: ``Broker::MEMORY``

   The type of data store backend that will be used for all data stores if
   no other has already been specified by the user in :bro:see:`Cluster::stores`.

.. bro:id:: Cluster::default_master_node

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Name of the node on which master data stores will be created if no other
   has already been specified by the user in :bro:see:`Cluster::stores`.
   An empty value means "use whatever name corresponds to the manager
   node".

.. bro:id:: Cluster::default_persistent_backend

   :Type: :bro:type:`Broker::BackendType`
   :Attributes: :bro:attr:`&redef`
   :Default: ``Broker::SQLITE``

   The type of persistent data store backend that will be used for all data
   stores if no other has already been specified by the user in
   :bro:see:`Cluster::stores`.  This will be used when script authors call
   :bro:see:`Cluster::create_store` with the *persistent* argument set true.

.. bro:id:: Cluster::default_store_dir

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Setting a default dir will, for persistent backends that have not
   been given an explicit file path via :bro:see:`Cluster::stores`,
   automatically create a path within this dir that is based on the name of
   the data store.

.. bro:id:: Cluster::enable_round_robin_logging

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Whether to distribute log messages among available logging nodes.

.. bro:id:: Cluster::logger_topic

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/cluster/logger"``

   The topic name used for exchanging messages that are relevant to
   logger nodes in a cluster.  Used with broker-enabled cluster communication.

.. bro:id:: Cluster::manager_is_logger

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Indicates whether or not the manager will act as the logger and receive
   logs.  This value should be set in the cluster-layout.bro script (the
   value should be true only if no logger is specified in Cluster::nodes).
   Note that BroControl handles this automatically.

.. bro:id:: Cluster::manager_topic

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/cluster/manager"``

   The topic name used for exchanging messages that are relevant to
   manager nodes in a cluster.  Used with broker-enabled cluster communication.

.. bro:id:: Cluster::node

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   This is usually supplied on the command line for each instance
   of the cluster that is started up.

.. bro:id:: Cluster::node_topic_prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/cluster/node/"``

   The topic prefix used for exchanging messages that are relevant to
   a named node in a cluster.  Used with broker-enabled cluster communication.

.. bro:id:: Cluster::nodeid_topic_prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/cluster/nodeid/"``

   The topic prefix used for exchanging messages that are relevant to
   a unique node in a cluster.  Used with broker-enabled cluster communication.

.. bro:id:: Cluster::nodes

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`Cluster::Node`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   The cluster layout definition.  This should be placed into a filter
   named cluster-layout.bro somewhere in the BROPATH.  It will be
   automatically loaded if the CLUSTER_NODE environment variable is set.
   Note that BroControl handles all of this automatically.
   The table is typically indexed by node names/labels (e.g. "manager"
   or "worker-1").

.. bro:id:: Cluster::proxy_topic

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/cluster/proxy"``

   The topic name used for exchanging messages that are relevant to
   proxy nodes in a cluster.  Used with broker-enabled cluster communication.

.. bro:id:: Cluster::retry_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 min``

   Interval for retrying failed connections between cluster nodes.
   If set, the BRO_DEFAULT_CONNECT_RETRY (given in number of seconds)
   overrides this option.

.. bro:id:: Cluster::time_machine_topic

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/cluster/time_machine"``

   The topic name used for exchanging messages that are relevant to
   time machine nodes in a cluster.  Used with broker-enabled cluster communication.

.. bro:id:: Cluster::worker_topic

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/cluster/worker"``

   The topic name used for exchanging messages that are relevant to
   worker nodes in a cluster.  Used with broker-enabled cluster communication.

State Variables
###############
.. bro:id:: Cluster::stores

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`Cluster::StoreInfo`
   :Attributes: :bro:attr:`&default` = ``[name=<uninitialized>, store=<uninitialized>, master_node=, master=F, backend=Broker::MEMORY, options=[sqlite=[path=], rocksdb=[path=]], clone_resync_interval=10.0 secs, clone_stale_interval=5.0 mins, clone_mutation_buffer_interval=2.0 mins]`` :bro:attr:`&optional` :bro:attr:`&redef`
   :Default: ``{}``

   A table of cluster-enabled data stores that have been created, indexed
   by their name.  This table will be populated automatically by
   :bro:see:`Cluster::create_store`, but if you need to customize
   the options related to a particular data store, you may redef this
   table.  Calls to :bro:see:`Cluster::create_store` will first check
   the table for an entry of the same name and, if found, will use the
   predefined options there when setting up the store.

.. bro:id:: Cluster::worker_count

   :Type: :bro:type:`count`
   :Default: ``0``

   This gives the value for the number of workers currently connected to,
   and it's maintained internally by the cluster framework.  It's
   primarily intended for use by managers to find out how many workers
   should be responding to requests.

Types
#####
.. bro:type:: Cluster::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The time at which a cluster message was generated.

      node: :bro:type:`string` :bro:attr:`&log`
         The name of the node that is creating the log record.

      message: :bro:type:`string` :bro:attr:`&log`
         A message indicating information about the cluster's operation.
   :Attributes: :bro:attr:`&log`

   The record type which contains the column fields of the cluster log.

.. bro:type:: Cluster::Node

   :Type: :bro:type:`record`

      node_type: :bro:type:`Cluster::NodeType`
         Identifies the type of cluster node in this node's configuration.

      ip: :bro:type:`addr`
         The IP address of the cluster node.

      zone_id: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         If the *ip* field is a non-global IPv6 address, this field
         can specify a particular :rfc:`4007` ``zone_id``.

      p: :bro:type:`port`
         The port that this node will listen on for peer connections.

      interface: :bro:type:`string` :bro:attr:`&optional`
         Identifier for the interface a worker is sniffing.

      manager: :bro:type:`string` :bro:attr:`&optional`
         Name of the manager node this node uses.  For workers and proxies.

      time_machine: :bro:type:`string` :bro:attr:`&optional`
         Name of a time machine node with which this node connects.

      id: :bro:type:`string` :bro:attr:`&optional`
         A unique identifier assigned to the node by the broker framework.
         This field is only set while a node is connected.

      lb_filter: :bro:type:`string` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/misc/load-balancing.bro` is loaded)

         A BPF filter for load balancing traffic sniffed on a single
         interface across a number of processes.  In normal uses, this
         will be assigned dynamically by the manager and installed by
         the workers.

   Record type to indicate a node in a cluster.

.. bro:type:: Cluster::NodeType

   :Type: :bro:type:`enum`

      .. bro:enum:: Cluster::NONE Cluster::NodeType

         A dummy node type indicating the local node is not operating
         within a cluster.

      .. bro:enum:: Cluster::CONTROL Cluster::NodeType

         A node type which is allowed to view/manipulate the configuration
         of other nodes in the cluster.

      .. bro:enum:: Cluster::LOGGER Cluster::NodeType

         A node type responsible for log management.

      .. bro:enum:: Cluster::MANAGER Cluster::NodeType

         A node type responsible for policy management.

      .. bro:enum:: Cluster::PROXY Cluster::NodeType

         A node type for relaying worker node communication and synchronizing
         worker node state.

      .. bro:enum:: Cluster::WORKER Cluster::NodeType

         The node type doing all the actual traffic analysis.

      .. bro:enum:: Cluster::TIME_MACHINE Cluster::NodeType

         A node acting as a traffic recorder using the
         `Time Machine <https://www.zeek.org/community/time-machine.html>`_
         software.

   Types of nodes that are allowed to participate in the cluster
   configuration.

.. bro:type:: Cluster::StoreInfo

   :Type: :bro:type:`record`

      name: :bro:type:`string` :bro:attr:`&optional`
         The name of the data store.

      store: :bro:type:`opaque` of Broker::Store :bro:attr:`&optional`
         The store handle.

      master_node: :bro:type:`string` :bro:attr:`&default` = :bro:see:`Cluster::default_master_node` :bro:attr:`&optional`
         The name of the cluster node on which the master version of the data
         store resides.

      master: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Whether the data store is the master version or a clone.

      backend: :bro:type:`Broker::BackendType` :bro:attr:`&default` = :bro:see:`Cluster::default_backend` :bro:attr:`&optional`
         The type of backend used for storing data.

      options: :bro:type:`Broker::BackendOptions` :bro:attr:`&default` = ``[sqlite=[path=], rocksdb=[path=]]`` :bro:attr:`&optional`
         Parameters used for configuring the backend.

      clone_resync_interval: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Broker::default_clone_resync_interval` :bro:attr:`&optional`
         A resync/reconnect interval to pass through to
         :bro:see:`Broker::create_clone`.

      clone_stale_interval: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Broker::default_clone_stale_interval` :bro:attr:`&optional`
         A staleness duration to pass through to
         :bro:see:`Broker::create_clone`.

      clone_mutation_buffer_interval: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Broker::default_clone_mutation_buffer_interval` :bro:attr:`&optional`
         A mutation buffer interval to pass through to
         :bro:see:`Broker::create_clone`.

   Information regarding a cluster-enabled data store.

Events
######
.. bro:id:: Cluster::hello

   :Type: :bro:type:`event` (name: :bro:type:`string`, id: :bro:type:`string`)

   When using broker-enabled cluster framework, nodes broadcast this event
   to exchange their user-defined name along with a string that uniquely
   identifies it for the duration of its lifetime.  This string may change
   if the node dies and has to reconnect later.

.. bro:id:: Cluster::node_down

   :Type: :bro:type:`event` (name: :bro:type:`string`, id: :bro:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a connected cluster node becomes disconnected.

.. bro:id:: Cluster::node_up

   :Type: :bro:type:`event` (name: :bro:type:`string`, id: :bro:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a cluster node connects or reconnects.

Functions
#########
.. bro:id:: Cluster::create_store

   :Type: :bro:type:`function` (name: :bro:type:`string`, persistent: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`) : :bro:type:`Cluster::StoreInfo`

   Sets up a cluster-enabled data store.  They will also still properly
   function for uses that are not operating a cluster.
   

   :name: the name of the data store to create.
   

   :persistent: whether the data store must be persistent.
   

   :returns: the store's information.  For master stores, the store will be
            ready to use immediately.  For clones, the store field will not
            be set until the node containing the master store has connected.

.. bro:id:: Cluster::is_enabled

   :Type: :bro:type:`function` () : :bro:type:`bool`

   This function can be called at any time to determine if the cluster
   framework is being enabled for this run.
   

   :returns: True if :bro:id:`Cluster::node` has been set.

.. bro:id:: Cluster::local_node_type

   :Type: :bro:type:`function` () : :bro:type:`Cluster::NodeType`

   This function can be called at any time to determine what type of
   cluster node the current Bro instance is going to be acting as.
   If :bro:id:`Cluster::is_enabled` returns false, then
   :bro:enum:`Cluster::NONE` is returned.
   

   :returns: The :bro:type:`Cluster::NodeType` the calling node acts as.

.. bro:id:: Cluster::log

   :Type: :bro:type:`function` (msg: :bro:type:`string`) : :bro:type:`void`

   Write a message to the cluster logging stream.

.. bro:id:: Cluster::node_topic

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`string`

   Retrieve the topic associated with a specific node in the cluster.
   

   :name: the name of the cluster node (e.g. "manager").
   

   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.

.. bro:id:: Cluster::nodeid_topic

   :Type: :bro:type:`function` (id: :bro:type:`string`) : :bro:type:`string`

   Retrieve the topic associated with a specific node in the cluster.
   

   :id: the id of the cluster node (from :bro:see:`Broker::EndpointInfo`
       or :bro:see:`Broker::node_id`.
   

   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.


