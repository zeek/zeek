:tocdepth: 3

base/frameworks/cluster/pools.zeek
==================================
.. zeek:namespace:: Cluster

Defines an interface for managing pools of cluster nodes.  Pools are
a useful way to distribute work or data among nodes within a cluster.

:Namespace: Cluster
:Imports: :doc:`base/frameworks/cluster/main.zeek </scripts/base/frameworks/cluster/main.zeek>`, :doc:`base/utils/hash_hrw.zeek </scripts/base/utils/hash_hrw.zeek>`

Summary
~~~~~~~
State Variables
###############
======================================================================================== =======================================================
:zeek:id:`Cluster::logger_pool`: :zeek:type:`Cluster::Pool`                              A pool containing all the logger nodes of a cluster.
:zeek:id:`Cluster::logger_pool_spec`: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&redef` The specification for :zeek:see:`Cluster::logger_pool`.
:zeek:id:`Cluster::proxy_pool`: :zeek:type:`Cluster::Pool`                               A pool containing all the proxy nodes of a cluster.
:zeek:id:`Cluster::proxy_pool_spec`: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&redef`  The specification for :zeek:see:`Cluster::proxy_pool`.
:zeek:id:`Cluster::worker_pool`: :zeek:type:`Cluster::Pool`                              A pool containing all the worker nodes of a cluster.
:zeek:id:`Cluster::worker_pool_spec`: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&redef` The specification for :zeek:see:`Cluster::worker_pool`.
======================================================================================== =======================================================

Types
#####
========================================================= ===========================================================
:zeek:type:`Cluster::PoolNode`: :zeek:type:`record`       Store state of a cluster within the context of a work pool.
:zeek:type:`Cluster::PoolNodeTable`: :zeek:type:`table`   
:zeek:type:`Cluster::PoolSpec`: :zeek:type:`record`       A pool specification.
:zeek:type:`Cluster::RoundRobinTable`: :zeek:type:`table` 
========================================================= ===========================================================

Functions
#########
======================================================== ======================================================================
:zeek:id:`Cluster::hrw_topic`: :zeek:type:`function`     Retrieve the topic associated with the node mapped via Rendezvous hash
                                                         of an arbitrary key.
:zeek:id:`Cluster::register_pool`: :zeek:type:`function` Registers and initializes a pool.
:zeek:id:`Cluster::rr_log_topic`: :zeek:type:`function`  Distributes log message topics among logger nodes via round-robin.
:zeek:id:`Cluster::rr_topic`: :zeek:type:`function`      Retrieve the topic associated with the node in a round-robin fashion.
======================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: Cluster::logger_pool

   :Type: :zeek:type:`Cluster::Pool`
   :Default:

   ::

      {
         spec=[topic="", node_type=Cluster::PROXY, max_nodes=<uninitialized>, exclusive=F]
         nodes={

         }
         node_list=[]
         hrw_pool=[sites={

         }]
         rr_key_seq={

         }
         alive_count=0
      }

   A pool containing all the logger nodes of a cluster.
   The pool's node membership/availability is automatically
   maintained by the cluster framework.

.. zeek:id:: Cluster::logger_pool_spec

   :Type: :zeek:type:`Cluster::PoolSpec`
   :Attributes: :zeek:attr:`&redef`
   :Default:

   ::

      {
         topic="zeek/cluster/pool/logger"
         node_type=Cluster::LOGGER
         max_nodes=<uninitialized>
         exclusive=F
      }

   The specification for :zeek:see:`Cluster::logger_pool`.

.. zeek:id:: Cluster::proxy_pool

   :Type: :zeek:type:`Cluster::Pool`
   :Default:

   ::

      {
         spec=[topic="", node_type=Cluster::PROXY, max_nodes=<uninitialized>, exclusive=F]
         nodes={

         }
         node_list=[]
         hrw_pool=[sites={

         }]
         rr_key_seq={

         }
         alive_count=0
      }

   A pool containing all the proxy nodes of a cluster.
   The pool's node membership/availability is automatically
   maintained by the cluster framework.

.. zeek:id:: Cluster::proxy_pool_spec

   :Type: :zeek:type:`Cluster::PoolSpec`
   :Attributes: :zeek:attr:`&redef`
   :Default:

   ::

      {
         topic="zeek/cluster/pool/proxy"
         node_type=Cluster::PROXY
         max_nodes=<uninitialized>
         exclusive=F
      }

   The specification for :zeek:see:`Cluster::proxy_pool`.

.. zeek:id:: Cluster::worker_pool

   :Type: :zeek:type:`Cluster::Pool`
   :Default:

   ::

      {
         spec=[topic="", node_type=Cluster::PROXY, max_nodes=<uninitialized>, exclusive=F]
         nodes={

         }
         node_list=[]
         hrw_pool=[sites={

         }]
         rr_key_seq={

         }
         alive_count=0
      }

   A pool containing all the worker nodes of a cluster.
   The pool's node membership/availability is automatically
   maintained by the cluster framework.

.. zeek:id:: Cluster::worker_pool_spec

   :Type: :zeek:type:`Cluster::PoolSpec`
   :Attributes: :zeek:attr:`&redef`
   :Default:

   ::

      {
         topic="zeek/cluster/pool/worker"
         node_type=Cluster::WORKER
         max_nodes=<uninitialized>
         exclusive=F
      }

   The specification for :zeek:see:`Cluster::worker_pool`.

Types
#####
.. zeek:type:: Cluster::PoolNode

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         The node name (e.g. "manager").

      alias: :zeek:type:`string`
         An alias of *name* used to prevent hashing collisions when creating
         *site_id*.

      site_id: :zeek:type:`count`
         A 32-bit unique identifier for the pool node, derived from name/alias.

      alive: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Whether the node is currently alive and can receive work.

   Store state of a cluster within the context of a work pool.

.. zeek:type:: Cluster::PoolNodeTable

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Cluster::PoolNode`


.. zeek:type:: Cluster::PoolSpec

   :Type: :zeek:type:`record`

      topic: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         A topic string that can be used to reach all nodes within a pool.

      node_type: :zeek:type:`Cluster::NodeType` :zeek:attr:`&default` = ``Cluster::PROXY`` :zeek:attr:`&optional`
         The type of nodes that are contained within the pool.

      max_nodes: :zeek:type:`count` :zeek:attr:`&optional`
         The maximum number of nodes that may belong to the pool.
         If not set, then all available nodes will be added to the pool,
         else the cluster framework will automatically limit the pool
         membership according to the threshhold.

      exclusive: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Whether the pool requires exclusive access to nodes.  If true,
         then *max_nodes* nodes will not be assigned to any other pool.
         When using this flag, *max_nodes* must also be set.

   A pool specification.

.. zeek:type:: Cluster::RoundRobinTable

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`int`


Functions
#########
.. zeek:id:: Cluster::hrw_topic

   :Type: :zeek:type:`function` (pool: :zeek:type:`Cluster::Pool`, key: :zeek:type:`any`) : :zeek:type:`string`

   Retrieve the topic associated with the node mapped via Rendezvous hash
   of an arbitrary key.
   

   :pool: the pool of nodes to consider.
   

   :key: data used for input to the hashing function that will uniformly
        distribute keys among available nodes.
   

   :returns: a topic string associated with a cluster node that is alive
            or an empty string if nothing is alive.

.. zeek:id:: Cluster::register_pool

   :Type: :zeek:type:`function` (spec: :zeek:type:`Cluster::PoolSpec`) : :zeek:type:`Cluster::Pool`

   Registers and initializes a pool.

.. zeek:id:: Cluster::rr_log_topic

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, path: :zeek:type:`string`) : :zeek:type:`string`

   Distributes log message topics among logger nodes via round-robin.
   This will be automatically assigned to :zeek:see:`Broker::log_topic`
   if :zeek:see:`Cluster::enable_round_robin_logging` is enabled.
   If no logger nodes are active, then this will return the value
   of :zeek:see:`Broker::default_log_topic`.

.. zeek:id:: Cluster::rr_topic

   :Type: :zeek:type:`function` (pool: :zeek:type:`Cluster::Pool`, key: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Retrieve the topic associated with the node in a round-robin fashion.
   

   :pool: the pool of nodes to consider.
   

   :key: an arbitrary string to identify the purpose for which you're
        requesting the topic.  e.g. consider using a name-spaced key
        like "Intel::cluster_rr_key" if you need to guarantee that
        a group of messages get distributed in a well-defined pattern
        without other messages being interleaved within the round-robin.
        Usually sharing the default key is fine for load-balancing
        purposes.
   

   :returns: a topic string associated with a cluster node that is alive,
            or an empty string if nothing is alive.


