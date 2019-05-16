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

:Namespace: Cluster
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/control </scripts/base/frameworks/control/index>`

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
:zeek:id:`Cluster::time_machine_topic`: :zeek:type:`string` :zeek:attr:`&redef`                      The topic name used for exchanging messages that are relevant to
                                                                                                     time machine nodes in a cluster.
:zeek:id:`Cluster::worker_topic`: :zeek:type:`string` :zeek:attr:`&redef`                            The topic name used for exchanging messages that are relevant to
                                                                                                     worker nodes in a cluster.
==================================================================================================== ===============================================================================

State Variables
###############
======================================================================================================================================================================================================================================================================================================================================================================= ======================================================================
:zeek:id:`Cluster::stores`: :zeek:type:`table` :zeek:attr:`&default` = ``[name=<uninitialized>, store=<uninitialized>, master_node=, master=F, backend=Broker::MEMORY, options=[sqlite=[path=], rocksdb=[path=]], clone_resync_interval=10.0 secs, clone_stale_interval=5.0 mins, clone_mutation_buffer_interval=2.0 mins]`` :zeek:attr:`&optional` :zeek:attr:`&redef` A table of cluster-enabled data stores that have been created, indexed
                                                                                                                                                                                                                                                                                                                                                                        by their name.
:zeek:id:`Cluster::worker_count`: :zeek:type:`count`                                                                                                                                                                                                                                                                                                                    This gives the value for the number of workers currently connected to,
                                                                                                                                                                                                                                                                                                                                                                        and it's maintained internally by the cluster framework.
======================================================================================================================================================================================================================================================================================================================================================================= ======================================================================

Types
#####
================================================================= ====================================================================
:zeek:type:`Cluster::Info`: :zeek:type:`record` :zeek:attr:`&log` The record type which contains the column fields of the cluster log.
:zeek:type:`Cluster::Node`: :zeek:type:`record`                   Record type to indicate a node in a cluster.
:zeek:type:`Cluster::NodeType`: :zeek:type:`enum`                 Types of nodes that are allowed to participate in the cluster
                                                                  configuration.
:zeek:type:`Cluster::StoreInfo`: :zeek:type:`record`              Information regarding a cluster-enabled data store.
================================================================= ====================================================================

Redefinitions
#############
======================================= ======================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The cluster logging stream identifier.
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

Functions
#########
========================================================== ===================================================================
:zeek:id:`Cluster::create_store`: :zeek:type:`function`    Sets up a cluster-enabled data store.
:zeek:id:`Cluster::is_enabled`: :zeek:type:`function`      This function can be called at any time to determine if the cluster
                                                           framework is being enabled for this run.
:zeek:id:`Cluster::local_node_type`: :zeek:type:`function` This function can be called at any time to determine what type of
                                                           cluster node the current Zeek instance is going to be acting as.
:zeek:id:`Cluster::log`: :zeek:type:`function`             Write a message to the cluster logging stream.
:zeek:id:`Cluster::node_topic`: :zeek:type:`function`      Retrieve the topic associated with a specific node in the cluster.
:zeek:id:`Cluster::nodeid_topic`: :zeek:type:`function`    Retrieve the topic associated with a specific node in the cluster.
========================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Cluster::default_backend

   :Type: :zeek:type:`Broker::BackendType`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Broker::MEMORY``

   The type of data store backend that will be used for all data stores if
   no other has already been specified by the user in :zeek:see:`Cluster::stores`.

.. zeek:id:: Cluster::default_master_node

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Name of the node on which master data stores will be created if no other
   has already been specified by the user in :zeek:see:`Cluster::stores`.
   An empty value means "use whatever name corresponds to the manager
   node".

.. zeek:id:: Cluster::default_persistent_backend

   :Type: :zeek:type:`Broker::BackendType`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Broker::SQLITE``

   The type of persistent data store backend that will be used for all data
   stores if no other has already been specified by the user in
   :zeek:see:`Cluster::stores`.  This will be used when script authors call
   :zeek:see:`Cluster::create_store` with the *persistent* argument set true.

.. zeek:id:: Cluster::default_store_dir

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Setting a default dir will, for persistent backends that have not
   been given an explicit file path via :zeek:see:`Cluster::stores`,
   automatically create a path within this dir that is based on the name of
   the data store.

.. zeek:id:: Cluster::enable_round_robin_logging

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether to distribute log messages among available logging nodes.

.. zeek:id:: Cluster::logger_topic

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"bro/cluster/logger"``

   The topic name used for exchanging messages that are relevant to
   logger nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::manager_is_logger

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Indicates whether or not the manager will act as the logger and receive
   logs.  This value should be set in the cluster-layout.zeek script (the
   value should be true only if no logger is specified in Cluster::nodes).
   Note that ZeekControl handles this automatically.

.. zeek:id:: Cluster::manager_topic

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"bro/cluster/manager"``

   The topic name used for exchanging messages that are relevant to
   manager nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::node

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   This is usually supplied on the command line for each instance
   of the cluster that is started up.

.. zeek:id:: Cluster::node_topic_prefix

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"bro/cluster/node/"``

   The topic prefix used for exchanging messages that are relevant to
   a named node in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::nodeid_topic_prefix

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"bro/cluster/nodeid/"``

   The topic prefix used for exchanging messages that are relevant to
   a unique node in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::nodes

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Cluster::Node`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   The cluster layout definition.  This should be placed into a filter
   named cluster-layout.zeek somewhere in the BROPATH.  It will be
   automatically loaded if the CLUSTER_NODE environment variable is set.
   Note that ZeekControl handles all of this automatically.
   The table is typically indexed by node names/labels (e.g. "manager"
   or "worker-1").

.. zeek:id:: Cluster::proxy_topic

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"bro/cluster/proxy"``

   The topic name used for exchanging messages that are relevant to
   proxy nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::retry_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min``

   Interval for retrying failed connections between cluster nodes.
   If set, the BRO_DEFAULT_CONNECT_RETRY (given in number of seconds)
   overrides this option.

.. zeek:id:: Cluster::time_machine_topic

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"bro/cluster/time_machine"``

   The topic name used for exchanging messages that are relevant to
   time machine nodes in a cluster.  Used with broker-enabled cluster communication.

.. zeek:id:: Cluster::worker_topic

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"bro/cluster/worker"``

   The topic name used for exchanging messages that are relevant to
   worker nodes in a cluster.  Used with broker-enabled cluster communication.

State Variables
###############
.. zeek:id:: Cluster::stores

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Cluster::StoreInfo`
   :Attributes: :zeek:attr:`&default` = ``[name=<uninitialized>, store=<uninitialized>, master_node=, master=F, backend=Broker::MEMORY, options=[sqlite=[path=], rocksdb=[path=]], clone_resync_interval=10.0 secs, clone_stale_interval=5.0 mins, clone_mutation_buffer_interval=2.0 mins]`` :zeek:attr:`&optional` :zeek:attr:`&redef`
   :Default: ``{}``

   A table of cluster-enabled data stores that have been created, indexed
   by their name.  This table will be populated automatically by
   :zeek:see:`Cluster::create_store`, but if you need to customize
   the options related to a particular data store, you may redef this
   table.  Calls to :zeek:see:`Cluster::create_store` will first check
   the table for an entry of the same name and, if found, will use the
   predefined options there when setting up the store.

.. zeek:id:: Cluster::worker_count

   :Type: :zeek:type:`count`
   :Default: ``0``

   This gives the value for the number of workers currently connected to,
   and it's maintained internally by the cluster framework.  It's
   primarily intended for use by managers to find out how many workers
   should be responding to requests.

Types
#####
.. zeek:type:: Cluster::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The time at which a cluster message was generated.

      node: :zeek:type:`string` :zeek:attr:`&log`
         The name of the node that is creating the log record.

      message: :zeek:type:`string` :zeek:attr:`&log`
         A message indicating information about the cluster's operation.
   :Attributes: :zeek:attr:`&log`

   The record type which contains the column fields of the cluster log.

.. zeek:type:: Cluster::Node

   :Type: :zeek:type:`record`

      node_type: :zeek:type:`Cluster::NodeType`
         Identifies the type of cluster node in this node's configuration.

      ip: :zeek:type:`addr`
         The IP address of the cluster node.

      zone_id: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         If the *ip* field is a non-global IPv6 address, this field
         can specify a particular :rfc:`4007` ``zone_id``.

      p: :zeek:type:`port`
         The port that this node will listen on for peer connections.

      interface: :zeek:type:`string` :zeek:attr:`&optional`
         Identifier for the interface a worker is sniffing.

      manager: :zeek:type:`string` :zeek:attr:`&optional`
         Name of the manager node this node uses.  For workers and proxies.

      time_machine: :zeek:type:`string` :zeek:attr:`&optional`
         Name of a time machine node with which this node connects.

      id: :zeek:type:`string` :zeek:attr:`&optional`
         A unique identifier assigned to the node by the broker framework.
         This field is only set while a node is connected.

      lb_filter: :zeek:type:`string` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/misc/load-balancing.zeek` is loaded)

         A BPF filter for load balancing traffic sniffed on a single
         interface across a number of processes.  In normal uses, this
         will be assigned dynamically by the manager and installed by
         the workers.

   Record type to indicate a node in a cluster.

.. zeek:type:: Cluster::NodeType

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
         `Time Machine <https://www.zeek.org/community/time-machine.html>`_
         software.

   Types of nodes that are allowed to participate in the cluster
   configuration.

.. zeek:type:: Cluster::StoreInfo

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

      options: :zeek:type:`Broker::BackendOptions` :zeek:attr:`&default` = ``[sqlite=[path=], rocksdb=[path=]]`` :zeek:attr:`&optional`
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

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, nodes broadcast this event
   to exchange their user-defined name along with a string that uniquely
   identifies it for the duration of its lifetime.  This string may change
   if the node dies and has to reconnect later.

.. zeek:id:: Cluster::node_down

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a connected cluster node becomes disconnected.

.. zeek:id:: Cluster::node_up

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   When using broker-enabled cluster framework, this event will be emitted
   locally whenever a cluster node connects or reconnects.

Functions
#########
.. zeek:id:: Cluster::create_store

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, persistent: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`Cluster::StoreInfo`

   Sets up a cluster-enabled data store.  They will also still properly
   function for uses that are not operating a cluster.
   

   :name: the name of the data store to create.
   

   :persistent: whether the data store must be persistent.
   

   :returns: the store's information.  For master stores, the store will be
            ready to use immediately.  For clones, the store field will not
            be set until the node containing the master store has connected.

.. zeek:id:: Cluster::is_enabled

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   This function can be called at any time to determine if the cluster
   framework is being enabled for this run.
   

   :returns: True if :zeek:id:`Cluster::node` has been set.

.. zeek:id:: Cluster::local_node_type

   :Type: :zeek:type:`function` () : :zeek:type:`Cluster::NodeType`

   This function can be called at any time to determine what type of
   cluster node the current Zeek instance is going to be acting as.
   If :zeek:id:`Cluster::is_enabled` returns false, then
   :zeek:enum:`Cluster::NONE` is returned.
   

   :returns: The :zeek:type:`Cluster::NodeType` the calling node acts as.

.. zeek:id:: Cluster::log

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`void`

   Write a message to the cluster logging stream.

.. zeek:id:: Cluster::node_topic

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the topic associated with a specific node in the cluster.
   

   :name: the name of the cluster node (e.g. "manager").
   

   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.

.. zeek:id:: Cluster::nodeid_topic

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the topic associated with a specific node in the cluster.
   

   :id: the id of the cluster node (from :zeek:see:`Broker::EndpointInfo`
       or :zeek:see:`Broker::node_id`.
   

   :returns: a topic string that may used to send a message exclusively to
            a given cluster node.


