:tocdepth: 3

base/frameworks/supervisor/api.zeek
===================================
.. zeek:namespace:: Supervisor

The Zeek process supervision API.

:Namespace: Supervisor

Summary
~~~~~~~
Types
#####
============================================================= ========================================================================
:zeek:type:`Supervisor::ClusterEndpoint`: :zeek:type:`record` Describes configuration of a supervised-node within Zeek's Cluster
                                                              Framework.
:zeek:type:`Supervisor::ClusterRole`: :zeek:type:`enum`       The role a supervised-node will play in Zeek's Cluster Framework.
:zeek:type:`Supervisor::NodeConfig`: :zeek:type:`record`      Configuration options that influence behavior of a supervised Zeek node.
:zeek:type:`Supervisor::NodeStatus`: :zeek:type:`record`      The current status of a supervised node.
:zeek:type:`Supervisor::Status`: :zeek:type:`record`          The current status of a set of supervised nodes.
============================================================= ========================================================================

Functions
#########
=========================================================== =============================================================
:zeek:id:`Supervisor::create`: :zeek:type:`function`        Create a new supervised node process.
:zeek:id:`Supervisor::destroy`: :zeek:type:`function`       Destroy and remove a supervised node process.
:zeek:id:`Supervisor::is_supervised`: :zeek:type:`function` Returns: true if this is a supervised node process.
:zeek:id:`Supervisor::is_supervisor`: :zeek:type:`function` Returns: true if this is the Supervisor process.
:zeek:id:`Supervisor::node`: :zeek:type:`function`          Returns: the node configuration if this is a supervised node.
:zeek:id:`Supervisor::restart`: :zeek:type:`function`       Restart a supervised node process by destroying (killing) and
                                                            re-recreating it.
:zeek:id:`Supervisor::status`: :zeek:type:`function`        Retrieve current status of a supervised node process.
=========================================================== =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Supervisor::ClusterEndpoint

   :Type: :zeek:type:`record`

      role: :zeek:type:`Supervisor::ClusterRole`
         The role a supervised-node will play in Zeek's Cluster Framework.

      host: :zeek:type:`addr`
         The host/IP at which the cluster node runs.

      p: :zeek:type:`port`
         The TCP port at which the cluster node listens for connections.

      interface: :zeek:type:`string` :zeek:attr:`&optional`
         The interface name from which the node will read/analyze packets.
         Typically used by worker nodes.

   Describes configuration of a supervised-node within Zeek's Cluster
   Framework.

.. zeek:type:: Supervisor::ClusterRole

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Supervisor::NONE Supervisor::ClusterRole

      .. zeek:enum:: Supervisor::LOGGER Supervisor::ClusterRole

      .. zeek:enum:: Supervisor::MANAGER Supervisor::ClusterRole

      .. zeek:enum:: Supervisor::PROXY Supervisor::ClusterRole

      .. zeek:enum:: Supervisor::WORKER Supervisor::ClusterRole

   The role a supervised-node will play in Zeek's Cluster Framework.

.. zeek:type:: Supervisor::NodeConfig

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         The name of the supervised node.  These are unique within a given
         supervised process tree and typically human-readable.

      interface: :zeek:type:`string` :zeek:attr:`&optional`
         The interface name from which the node will read/analyze packets.

      directory: :zeek:type:`string` :zeek:attr:`&optional`
         The working directory that the node should use.

      stdout_file: :zeek:type:`string` :zeek:attr:`&optional`
         The filename/path to which the node's stdout will be redirected.

      stderr_file: :zeek:type:`string` :zeek:attr:`&optional`
         The filename/path to which the node's stderr will be redirected.

      scripts: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         Additional script filenames/paths that the node should load.

      cpu_affinity: :zeek:type:`int` :zeek:attr:`&optional`
         A cpu/core number to which the node will try to pin itself.

      cluster: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Supervisor::ClusterEndpoint` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         The Cluster Layout definition.  Each node in the Cluster Framework
         knows about the full, static cluster topology to which it belongs.
         Entries use node names for keys.  The Supervisor framework will
         automatically translate this table into the right Cluster Framework
         configuration when spawning supervised-nodes.  E.g. it will
         populate the both the CLUSTER_NODE environment variable and
         :zeek:see:`Cluster::nodes` table.

   Configuration options that influence behavior of a supervised Zeek node.

.. zeek:type:: Supervisor::NodeStatus

   :Type: :zeek:type:`record`

      node: :zeek:type:`Supervisor::NodeConfig`
         The desired node configuration.

      pid: :zeek:type:`int` :zeek:attr:`&optional`
         The current or last known process ID of the node.  This may not
         be initialized if the process has not yet started.

   The current status of a supervised node.

.. zeek:type:: Supervisor::Status

   :Type: :zeek:type:`record`

      nodes: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Supervisor::NodeStatus`
         The status of supervised nodes, keyed by node names.

   The current status of a set of supervised nodes.

Functions
#########
.. zeek:id:: Supervisor::create

   :Type: :zeek:type:`function` (node: :zeek:type:`Supervisor::NodeConfig`) : :zeek:type:`string`

   Create a new supervised node process.
   It's an error to call this from a process other than a Supervisor.
   

   :node: the desired configuration for the new supervised node process.
   

   :returns: an empty string on success or description of the error/failure.

.. zeek:id:: Supervisor::destroy

   :Type: :zeek:type:`function` (node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Destroy and remove a supervised node process.
   It's an error to call this from a process other than a Supervisor.
   

   :node: the name of the node to destroy or an empty string to mean
         "all nodes".
   

   :returns: true on success.

.. zeek:id:: Supervisor::is_supervised

   :Type: :zeek:type:`function` () : :zeek:type:`bool`


   :returns: true if this is a supervised node process.

.. zeek:id:: Supervisor::is_supervisor

   :Type: :zeek:type:`function` () : :zeek:type:`bool`


   :returns: true if this is the Supervisor process.

.. zeek:id:: Supervisor::node

   :Type: :zeek:type:`function` () : :zeek:type:`Supervisor::NodeConfig`


   :returns: the node configuration if this is a supervised node.
            It's an error to call this function from a process other than
            a supervised one.

.. zeek:id:: Supervisor::restart

   :Type: :zeek:type:`function` (node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Restart a supervised node process by destroying (killing) and
   re-recreating it.
   It's an error to call this from a process other than a Supervisor.
   

   :node: the name of the node to restart or an empty string to mean
         "all nodes".
   

   :returns: true on success.

.. zeek:id:: Supervisor::status

   :Type: :zeek:type:`function` (node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`Supervisor::Status`

   Retrieve current status of a supervised node process.
   It's an error to call this from a process other than a Supervisor.
   

   :node: the name of the node to get the status of or an empty string
         to mean "all nodes".
   

   :returns: the current status of a set of nodes.


