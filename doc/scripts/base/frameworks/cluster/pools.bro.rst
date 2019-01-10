:tocdepth: 3

base/frameworks/cluster/pools.bro
=================================
.. bro:namespace:: Cluster

Defines an interface for managing pools of cluster nodes.  Pools are
a useful way to distribute work or data among nodes within a cluster.

:Namespace: Cluster
:Imports: :doc:`base/frameworks/cluster/main.bro </scripts/base/frameworks/cluster/main.bro>`, :doc:`base/utils/hash_hrw.bro </scripts/base/utils/hash_hrw.bro>`

Summary
~~~~~~~
State Variables
###############
===================================================================================== ======================================================
:bro:id:`Cluster::logger_pool`: :bro:type:`Cluster::Pool`                             A pool containing all the logger nodes of a cluster.
:bro:id:`Cluster::logger_pool_spec`: :bro:type:`Cluster::PoolSpec` :bro:attr:`&redef` The specification for :bro:see:`Cluster::logger_pool`.
:bro:id:`Cluster::proxy_pool`: :bro:type:`Cluster::Pool`                              A pool containing all the proxy nodes of a cluster.
:bro:id:`Cluster::proxy_pool_spec`: :bro:type:`Cluster::PoolSpec` :bro:attr:`&redef`  The specification for :bro:see:`Cluster::proxy_pool`.
:bro:id:`Cluster::worker_pool`: :bro:type:`Cluster::Pool`                             A pool containing all the worker nodes of a cluster.
:bro:id:`Cluster::worker_pool_spec`: :bro:type:`Cluster::PoolSpec` :bro:attr:`&redef` The specification for :bro:see:`Cluster::worker_pool`.
===================================================================================== ======================================================

Types
#####
======================================================= ===========================================================
:bro:type:`Cluster::PoolNode`: :bro:type:`record`       Store state of a cluster within the context of a work pool.
:bro:type:`Cluster::PoolNodeTable`: :bro:type:`table`   
:bro:type:`Cluster::PoolSpec`: :bro:type:`record`       A pool specification.
:bro:type:`Cluster::RoundRobinTable`: :bro:type:`table` 
======================================================= ===========================================================

Functions
#########
====================================================== ======================================================================
:bro:id:`Cluster::hrw_topic`: :bro:type:`function`     Retrieve the topic associated with the node mapped via Rendezvous hash
                                                       of an arbitrary key.
:bro:id:`Cluster::register_pool`: :bro:type:`function` Registers and initializes a pool.
:bro:id:`Cluster::rr_log_topic`: :bro:type:`function`  Distributes log message topics among logger nodes via round-robin.
:bro:id:`Cluster::rr_topic`: :bro:type:`function`      Retrieve the topic associated with the node in a round-robin fashion.
====================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. bro:id:: Cluster::logger_pool

   :Type: :bro:type:`Cluster::Pool`
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

.. bro:id:: Cluster::logger_pool_spec

   :Type: :bro:type:`Cluster::PoolSpec`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         topic="bro/cluster/pool/logger"
         node_type=Cluster::LOGGER
         max_nodes=<uninitialized>
         exclusive=F
      }

   The specification for :bro:see:`Cluster::logger_pool`.

.. bro:id:: Cluster::proxy_pool

   :Type: :bro:type:`Cluster::Pool`
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

.. bro:id:: Cluster::proxy_pool_spec

   :Type: :bro:type:`Cluster::PoolSpec`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         topic="bro/cluster/pool/proxy"
         node_type=Cluster::PROXY
         max_nodes=<uninitialized>
         exclusive=F
      }

   The specification for :bro:see:`Cluster::proxy_pool`.

.. bro:id:: Cluster::worker_pool

   :Type: :bro:type:`Cluster::Pool`
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

.. bro:id:: Cluster::worker_pool_spec

   :Type: :bro:type:`Cluster::PoolSpec`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         topic="bro/cluster/pool/worker"
         node_type=Cluster::WORKER
         max_nodes=<uninitialized>
         exclusive=F
      }

   The specification for :bro:see:`Cluster::worker_pool`.

Types
#####
.. bro:type:: Cluster::PoolNode

   :Type: :bro:type:`record`

      name: :bro:type:`string`
         The node name (e.g. "manager").

      alias: :bro:type:`string`
         An alias of *name* used to prevent hashing collisions when creating
         *site_id*.

      site_id: :bro:type:`count`
         A 32-bit unique identifier for the pool node, derived from name/alias.

      alive: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Whether the node is currently alive and can receive work.

   Store state of a cluster within the context of a work pool.

.. bro:type:: Cluster::PoolNodeTable

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`Cluster::PoolNode`


.. bro:type:: Cluster::PoolSpec

   :Type: :bro:type:`record`

      topic: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         A topic string that can be used to reach all nodes within a pool.

      node_type: :bro:type:`Cluster::NodeType` :bro:attr:`&default` = ``Cluster::PROXY`` :bro:attr:`&optional`
         The type of nodes that are contained within the pool.

      max_nodes: :bro:type:`count` :bro:attr:`&optional`
         The maximum number of nodes that may belong to the pool.
         If not set, then all available nodes will be added to the pool,
         else the cluster framework will automatically limit the pool
         membership according to the threshhold.

      exclusive: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Whether the pool requires exclusive access to nodes.  If true,
         then *max_nodes* nodes will not be assigned to any other pool.
         When using this flag, *max_nodes* must also be set.

   A pool specification.

.. bro:type:: Cluster::RoundRobinTable

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`int`


Functions
#########
.. bro:id:: Cluster::hrw_topic

   :Type: :bro:type:`function` (pool: :bro:type:`Cluster::Pool`, key: :bro:type:`any`) : :bro:type:`string`

   Retrieve the topic associated with the node mapped via Rendezvous hash
   of an arbitrary key.
   

   :pool: the pool of nodes to consider.
   

   :key: data used for input to the hashing function that will uniformly
        distribute keys among available nodes.
   

   :returns: a topic string associated with a cluster node that is alive
            or an empty string if nothing is alive.

.. bro:id:: Cluster::register_pool

   :Type: :bro:type:`function` (spec: :bro:type:`Cluster::PoolSpec`) : :bro:type:`Cluster::Pool`

   Registers and initializes a pool.

.. bro:id:: Cluster::rr_log_topic

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, path: :bro:type:`string`) : :bro:type:`string`

   Distributes log message topics among logger nodes via round-robin.
   This will be automatically assigned to :bro:see:`Broker::log_topic`
   if :bro:see:`Cluster::enable_round_robin_logging` is enabled.
   If no logger nodes are active, then this will return the value
   of :bro:see:`Broker::default_log_topic`.

.. bro:id:: Cluster::rr_topic

   :Type: :bro:type:`function` (pool: :bro:type:`Cluster::Pool`, key: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`string`

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


