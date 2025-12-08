:tocdepth: 3

base/frameworks/supervisor/api.zeek
===================================
.. zeek:namespace:: Supervisor

The Zeek process supervision API.
This API was introduced in Zeek 3.1.0 and considered unstable until 4.0.0.
That is, it may change in various incompatible ways without warning or
deprecation until the stable 4.0.0 release.

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

Events
######
====================================================== ================================================================
:zeek:id:`Supervisor::node_status`: :zeek:type:`event` A notification event the Supervisor generates when it receives a
                                                       status message update from the stem, indicating node has
                                                       (re-)started.
====================================================== ================================================================

Hooks
#####
===================================================== ==================================================================
:zeek:id:`Supervisor::stderr_hook`: :zeek:type:`hook` Hooks into the stderr stream for all supervisor's child processes.
:zeek:id:`Supervisor::stdout_hook`: :zeek:type:`hook` Hooks into the stdout stream for all supervisor's child processes.
===================================================== ==================================================================

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
   :source-code: base/frameworks/supervisor/api.zeek 20 35

   :Type: :zeek:type:`record`


   .. zeek:field:: role :zeek:type:`Supervisor::ClusterRole`

      The role a supervised-node will play in Zeek's Cluster Framework.


   .. zeek:field:: host :zeek:type:`addr`

      The host/IP at which the cluster node runs.


   .. zeek:field:: p :zeek:type:`port`

      The TCP port at which the cluster node listens for connections.


   .. zeek:field:: interface :zeek:type:`string` :zeek:attr:`&optional`

      The interface name from which the node will read/analyze packets.
      Typically used by worker nodes.


   .. zeek:field:: pcap_file :zeek:type:`string` :zeek:attr:`&optional`

      The PCAP file name from which the node will read/analyze packets.
      Typically used by worker nodes.


   .. zeek:field:: metrics_port :zeek:type:`port` :zeek:attr:`&optional`

      The TCP port at which the cluster node exposes metrics for Prometheus.


   Describes configuration of a supervised-node within Zeek's Cluster
   Framework.

.. zeek:type:: Supervisor::ClusterRole
   :source-code: base/frameworks/supervisor/api.zeek 10 10

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Supervisor::NONE Supervisor::ClusterRole

      .. zeek:enum:: Supervisor::LOGGER Supervisor::ClusterRole

      .. zeek:enum:: Supervisor::MANAGER Supervisor::ClusterRole

      .. zeek:enum:: Supervisor::PROXY Supervisor::ClusterRole

      .. zeek:enum:: Supervisor::WORKER Supervisor::ClusterRole

   The role a supervised-node will play in Zeek's Cluster Framework.

.. zeek:type:: Supervisor::NodeConfig
   :source-code: base/frameworks/supervisor/api.zeek 38 73

   :Type: :zeek:type:`record`


   .. zeek:field:: name :zeek:type:`string`

      The name of the supervised node.  These are unique within a given
      supervised process tree and typically human-readable.


   .. zeek:field:: interface :zeek:type:`string` :zeek:attr:`&optional`

      The interface name from which the node will read/analyze packets.


   .. zeek:field:: pcap_file :zeek:type:`string` :zeek:attr:`&optional`

      The PCAP file name from which the node will read/analyze packets.


   .. zeek:field:: directory :zeek:type:`string` :zeek:attr:`&optional`

      The working directory that the node should use.


   .. zeek:field:: stdout_file :zeek:type:`string` :zeek:attr:`&optional`

      The filename/path to which the node's stdout will be redirected.


   .. zeek:field:: stderr_file :zeek:type:`string` :zeek:attr:`&optional`

      The filename/path to which the node's stderr will be redirected.


   .. zeek:field:: bare_mode :zeek:type:`bool` :zeek:attr:`&optional`

      Whether to start the node in bare mode. When left out, the node
      inherits the bare-mode status the supervisor itself runs with.


   .. zeek:field:: addl_base_scripts :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`

      Additional script filenames/paths that the node should load
      after the base scripts, and prior to any user-specified ones.


   .. zeek:field:: addl_user_scripts :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`

      Additional script filenames/paths that the node should load
      after any user-specified scripts.


   .. zeek:field:: env :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`

      Environment variables to define in the supervised node.


   .. zeek:field:: cpu_affinity :zeek:type:`int` :zeek:attr:`&optional`

      A cpu/core number to which the node will try to pin itself.


   .. zeek:field:: cluster :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Supervisor::ClusterEndpoint` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`

      The Cluster Layout definition.  Each node in the Cluster Framework
      knows about the full, static cluster topology to which it belongs.
      Entries use node names for keys.  The Supervisor framework will
      automatically translate this table into the right Cluster Framework
      configuration when spawning supervised-nodes.  E.g. it will
      populate the both the CLUSTER_NODE environment variable and
      :zeek:see:`Cluster::nodes` table.


   Configuration options that influence behavior of a supervised Zeek node.

.. zeek:type:: Supervisor::NodeStatus
   :source-code: base/frameworks/supervisor/api.zeek 76 82

   :Type: :zeek:type:`record`


   .. zeek:field:: node :zeek:type:`Supervisor::NodeConfig`

      The desired node configuration.


   .. zeek:field:: pid :zeek:type:`int` :zeek:attr:`&optional`

      The current or last known process ID of the node.  This may not
      be initialized if the process has not yet started.


   The current status of a supervised node.

.. zeek:type:: Supervisor::Status
   :source-code: base/frameworks/supervisor/api.zeek 85 88

   :Type: :zeek:type:`record`


   .. zeek:field:: nodes :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Supervisor::NodeStatus`

      The status of supervised nodes, keyed by node names.


   The current status of a set of supervised nodes.

Events
######
.. zeek:id:: Supervisor::node_status
   :source-code: base/frameworks/supervisor/api.zeek 174 174

   :Type: :zeek:type:`event` (node: :zeek:type:`string`, pid: :zeek:type:`count`)

   A notification event the Supervisor generates when it receives a
   status message update from the stem, indicating node has
   (re-)started.
   

   :param node: the name of a previously created node via
         :zeek:see:`Supervisor::create` indicating to which
         child process the stdout line is associated.
   

   :param pid: the process ID the stem reported for this node.

Hooks
#####
.. zeek:id:: Supervisor::stderr_hook
   :source-code: policy/frameworks/management/supervisor/main.zeek 77 92

   :Type: :zeek:type:`hook` (node: :zeek:type:`string`, msg: :zeek:type:`string`) : :zeek:type:`bool`

   Hooks into the stderr stream for all supervisor's child processes.
   If a hook terminates with ``break``, that will suppress output to the
   associated stream.
   

   :param node: the name of a previously created node via
         :zeek:see:`Supervisor::create` indicating to which
         child process the stdout line is associated.
         A empty value is used to indicate the message
         came from the internal supervisor stem process.
         (this should typically never happen).
   

   :param msg: line-buffered contents from the stderr of a child process.

.. zeek:id:: Supervisor::stdout_hook
   :source-code: policy/frameworks/management/supervisor/main.zeek 55 75

   :Type: :zeek:type:`hook` (node: :zeek:type:`string`, msg: :zeek:type:`string`) : :zeek:type:`bool`

   Hooks into the stdout stream for all supervisor's child processes.
   If a hook terminates with ``break``, that will suppress output to the
   associated stream.
   

   :param node: the name of a previously created node via
         :zeek:see:`Supervisor::create` indicating to which
         child process the stdout line is associated.
         An empty value is used to indicate the message
         came from the internal supervisor stem process
         (this should typically never happen).
   

   :param msg: line-buffered contents from the stdout of a child process.

Functions
#########
.. zeek:id:: Supervisor::create
   :source-code: base/frameworks/supervisor/main.zeek 14 17

   :Type: :zeek:type:`function` (node: :zeek:type:`Supervisor::NodeConfig`) : :zeek:type:`string`

   Create a new supervised node process.
   It's an error to call this from a process other than a Supervisor.
   

   :param node: the desired configuration for the new supervised node process.
   

   :returns: an empty string on success or description of the error/failure.

.. zeek:id:: Supervisor::destroy
   :source-code: base/frameworks/supervisor/main.zeek 19 22

   :Type: :zeek:type:`function` (node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Destroy and remove a supervised node process.
   It's an error to call this from a process other than a Supervisor.
   

   :param node: the name of the node to destroy or an empty string to mean
         "all nodes".
   

   :returns: true on success.

.. zeek:id:: Supervisor::is_supervised
   :source-code: base/frameworks/supervisor/main.zeek 34 37

   :Type: :zeek:type:`function` () : :zeek:type:`bool`


   :returns: true if this is a supervised node process.

.. zeek:id:: Supervisor::is_supervisor
   :source-code: base/frameworks/supervisor/main.zeek 29 32

   :Type: :zeek:type:`function` () : :zeek:type:`bool`


   :returns: true if this is the Supervisor process.

.. zeek:id:: Supervisor::node
   :source-code: base/frameworks/supervisor/main.zeek 39 42

   :Type: :zeek:type:`function` () : :zeek:type:`Supervisor::NodeConfig`


   :returns: the node configuration if this is a supervised node.
            It's an error to call this function from a process other than
            a supervised one.

.. zeek:id:: Supervisor::restart
   :source-code: base/frameworks/supervisor/main.zeek 24 27

   :Type: :zeek:type:`function` (node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Restart a supervised node process by destroying (killing) and
   re-recreating it.
   It's an error to call this from a process other than a Supervisor.
   

   :param node: the name of the node to restart or an empty string to mean
         "all nodes".
   

   :returns: true on success.

.. zeek:id:: Supervisor::status
   :source-code: base/frameworks/supervisor/main.zeek 9 12

   :Type: :zeek:type:`function` (node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`Supervisor::Status`

   Retrieve current status of a supervised node process.
   It's an error to call this from a process other than a Supervisor.
   

   :param node: the name of the node to get the status of or an empty string
         to mean "all nodes".
   

   :returns: the current status of a set of nodes.


