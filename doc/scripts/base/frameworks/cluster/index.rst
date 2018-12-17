:orphan:

Package: base/frameworks/cluster
================================

The cluster framework provides for establishing and controlling a cluster
of Bro instances.

:doc:`/scripts/base/frameworks/cluster/__load__.bro`


:doc:`/scripts/base/frameworks/cluster/main.bro`

   A framework for establishing and controlling a cluster of Bro instances.
   In order to use the cluster framework, a script named
   ``cluster-layout.bro`` must exist somewhere in Bro's script search path
   which has a cluster definition of the :bro:id:`Cluster::nodes` variable.
   The ``CLUSTER_NODE`` environment variable or :bro:id:`Cluster::node`
   must also be sent and the cluster framework loaded as a package like
   ``@load base/frameworks/cluster``.

:doc:`/scripts/base/frameworks/cluster/pools.bro`

   Defines an interface for managing pools of cluster nodes.  Pools are
   a useful way to distribute work or data among nodes within a cluster.

