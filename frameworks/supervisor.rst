====================
Supervisor Framework
====================

.. rst-class:: opening

    The Supervisor framework enables an entirely new mode for Zeek, one that
    supervises a set of Zeek processes that are meant to be persistent.  A
    Supervisor automatically revives any process that dies or exits prematurely
    and also arranges for an ordered shutdown of the entire process tree upon
    its own termination.  This Supervisor mode for Zeek provides the basic
    foundation for process configuration/management that could be used to
    deploy a Zeek cluster similar to what ZeekControl does, but is also simpler
    to integrate as a standard system service.

Simple Example
==============

A simple example of using the Supervisor to monitor one Zeek process
sniffing packets from an interface looks like the following:

.. sourcecode:: console

  $ zeek -j simple-supervisor.zeek

.. literalinclude:: supervisor/simple-supervisor.zeek
   :caption: simple-supervisor.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

The command-line argument of ``-j`` toggles Zeek to run in "Supervisor mode" to
allow for creation and management of child processes.  If you're going to test
this locally, be sure to change ``en0`` to a real interface name you can sniff.

Notice that the ``simple-supervisor.zeek`` script is loaded and executed by
both the main Supervisor process and also the child Zeek process that it spawns
via :zeek:see:`Supervisor::create` with :zeek:see:`Supervisor::is_supervisor`
or :zeek:see:`Supervisor::is_supervised` being able to distinguish the
Supervisor process from the supervised child process, respectively.
You can also distinguish between multiple supervised child processes by
inspecting the contents of :zeek:see:`Supervisor::node` (e.g. comparing node
names).

If you happened to be running this locally on an interface with checksum
offloading and want Zeek to ignore checksums, instead simply run with the
``-C`` command-line argument like:

.. sourcecode:: console

  $ zeek -j -C simple-supervisor.zeek

Most command-line arguments to Zeek are automatically inherited by any
supervised child processes that get created.  The notable ones that are *not*
inherited are the options to read pcap files and live interfaces, ``-r`` and
``-i``, respectively.

For node-specific configuration options, see :zeek:see:`Supervisor::NodeConfig`
which gets passed as argument to :zeek:see:`Supervisor::create`.

Supervised Cluster Example
==========================

To run a full Zeek cluster similar to what you may already know, try the
following script:

.. sourcecode:: console

  $ zeek -j cluster-supervisor.zeek

.. literalinclude:: supervisor/cluster-supervisor.zeek
   :caption: cluster-supervisor.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

This script now spawns four nodes: a cluster manager, logger, worker, and
proxy.  It also configures each node to use a separate working directory
corresponding to the node's name within the current working directory of the
Supervisor process and redirects stdout and stderr to files inside.

The Supervisor process also listens on a port of its own for further
instructions from other external/remote processes via
:zeek:see:`Broker::listen`.  For example, you could use this other script to
tell the Supervisor to restart all processes, perhaps to re-load Zeek scripts
you've changed in the meantime:

.. sourcecode:: console

  $ zeek supervisor-control.zeek

.. literalinclude:: supervisor/supervisor-control.zeek
   :caption: supervisor-control.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

Any Supervisor instruction you can perform via an API call in a local script
can also be triggered via an associated external event.

For further details, consult the API at
:doc:`/scripts/base/frameworks/supervisor/api.zeek`.
