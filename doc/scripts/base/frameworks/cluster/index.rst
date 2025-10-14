:orphan:

Package: base/frameworks/cluster
================================

The cluster framework provides for establishing and controlling a cluster
of Zeek instances.

:doc:`/scripts/base/frameworks/cluster/__load__.zeek`


:doc:`/scripts/base/frameworks/cluster/main.zeek`

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

:doc:`/scripts/base/frameworks/cluster/pools.zeek`

   Defines an interface for managing pools of cluster nodes.  Pools are
   a useful way to distribute work or data among nodes within a cluster.

