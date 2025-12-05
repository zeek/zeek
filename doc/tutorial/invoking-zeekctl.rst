.. _invoking-zeekctl:

.. _zeekcontrol cron: https://github.com/zeek/zeekctl?tab=readme-ov-file#zeekcontrol-cron-command

.. _zeekcontrol documentation: https://github.com/zeek/zeekctl

#############
 ZeekControl
#############

ZeekControl (or ``zeekctl``) is Zeek's primary tool for cluster
orchestration. A Zeek cluster analyzes network traffic by using multiple
coordinated Zeek processes. Every Zeek process in a cluster
is called a "node"---nodes within a cluster have different roles. A
node's role defines its type. You use ``zeekctl`` in order to coordinate
how many of each node type, what their options are, and start them.

This section will go more in depth about how to manage a Zeek cluster
using ``zeekctl``, but it is not a reference. See the `ZeekControl
documentation`_ for more information. Since this section is entirely
about invoking ``zeekctl``, it will not go over certain parts of the
Zeek cluster. See :ref:`cluster-setup` for that.

======================
 Invoking ``zeekctl``
======================

When invoked by itself, ``zeekctl`` drops you into an interactive
prompt:

.. code:: console

   # zeekctl
   Hint: Run the zeekctl "deploy" command to get started.

   Welcome to ZeekControl 2.6.0-28

   Type "help" for help.

   [ZeekControl] >

Any command for ``zeekctl`` can be run within this interactive prompt or
via arguments to the ``zeekctl`` executable. We will simply execute
commands as arguments to ``zeekctl`` directly, but feel free to use the
interactive prompt if that suits you better.

First, the most common ``zeekctl`` command is ``deploy``:

.. code:: console

   # zeekctl deploy

   checking configurations ...
   installing ...
   creating policy directories ...
   installing site policies ...
   generating standalone-layout.zeek ...
   generating local-networks.zeek ...
   generating zeekctl-config.zeek ...
   generating zeekctl-config.sh ...
   stopping ...
   stopping zeek ...
   starting ...
   starting zeek ...

This does more than bring up your cluster. First, it checks for syntax
errors in policy scripts. Then, it distributes configuration files to
all individual systems so that they are visible to all nodes of the
cluster. Finally, it orderly restarts all processes in the cluster.

This is equivalent to running three separate commands: ``check``,
``install``, and ``restart``:

.. code:: console

   # zeekctl check
   zeek scripts are ok.
   # zeekctl install
   removing old policies in /usr/local/zeek/spool/installed-scripts-do-not-touch/site ...
   removing old policies in /usr/local/zeek/spool/installed-scripts-do-not-touch/auto ...
   creating policy directories ...
   installing site policies ...
   generating standalone-layout.zeek ...
   generating local-networks.zeek ...
   generating zeekctl-config.zeek ...
   generating zeekctl-config.sh ...
   # zeekctl restart
   stopping ...
   stopping zeek ...
   starting ...
   starting zeek ..

But, you may as well just use ``deploy`` whenever you make changes to
any policy scripts or configuration files. Let's swap the default
cluster out for a "real" cluster, then redeploy as you would in a
production environment.

Before you change the cluster layout, make sure you run ``zeekctl stop``
in order to stop all of the current running nodes (which will just be
the standalone node):

.. code:: console

   # zeekctl stop
   stopping zeek ...

.. note::

   This section will use ``$PREFIX`` extensively to refer to Zeek's
   installation directory. This is set as an environment variable by the
   tutorial setup script, so you can use it verbatim.

Now, you can change the cluster setup to include multiple Zeek
processes. First, modify ``$PREFIX/etc/node.cfg`` by uncommenting the
"example clustered configuration" and commenting out the "standalone"
configuration. Here is the clustered configuration:

.. code:: console

   [logger-1]
   type=logger
   host=localhost

   [manager]
   type=manager
   host=localhost

   [proxy-1]
   type=proxy
   host=localhost

   [worker-1]
   type=worker
   host=localhost
   interface=eth0

   [worker-2]
   type=worker
   host=localhost
   interface=eth0

Since we changed the cluster, you should run ``zeekctl deploy`` and see
that the new topology is running:

.. code:: console

   # zeekctl deploy
   <...>
   starting ...
   starting logger ...
   starting manager ...
   starting proxy ...
   starting workers ...

Now we started the logger, manager, proxy, and workers. With a running
cluster, you can view its status in a few ways. The most interactive is
with ``zeekctl top``:

.. code:: console

   # zeekctl top
   Name         Type    Host             Pid     VSize  Rss  Cpu   Cmd
   logger-1     logger  localhost        4341      2G   154M   0%  zeek
   manager      manager localhost        4394    1013M  154M   0%  zeek
   proxy-1      proxy   localhost        4446    1013M  153M   0%  zeek
   worker-1     worker  localhost        4511      1G   279M   0%  zeek
   worker-2     worker  localhost        4512      1G   279M   0%  zeek

This command is different in the "interactive" mode of ``zeekctl`` - try
running ``zeekctl`` alone, then ``top``. Here you can watch the various
process resources live!

You can also check the status of your Zeek cluster with ``zeekctl
status``:

.. code:: console

   # zeekctl status
   Name         Type    Host             Status    Pid    Started
   logger-1     logger  localhost        running   4341   08 Dec 21:47:32
   manager      manager localhost        running   4394   08 Dec 21:47:33
   proxy-1      proxy   localhost        running   4446   08 Dec 21:47:34
   worker-1     worker  localhost        running   4511   08 Dec 21:47:35
   worker-2     worker  localhost        running   4512   08 Dec 21:47:35

This is useful to ensure the nodes are healthy and running.

If anything is wrong, you can also use ``zeekctl diag`` on the node. For
example, here we force the ``proxy-1`` node to immediately crash, then
check its ``stderr.log`` with ``zeekctl diag``:

.. code:: console

   # echo "@if ( cluster::node == \"proxy-1\" ) event zeek_init() { Reporter::fatal(\"bad\!\"); } @endif" >> $PREFIX/share/zeek/site/local.zeek
   # zeekctl deploy
   <...>
   starting proxy ...
   Error: proxy-1 terminated immediately after starting; check output with "diag"
   # zeekctl diag proxy-1
   <...>

   ==== stderr.log
   fatal error in /usr/local/zeek/spool/installed-scripts-do-not-touch/site/local.zeek, line 1: bad!

   <...>

   # sed -i '$d' $PREFIX/share/zeek/site/local.zeek # Remove the line we just added

The ``diag`` command is essential to diagnose issues with the cluster.

If you see that a certain node is stopped via ``zeekctl status`` and
need to restart just that node, you can specify it as an argument. For
example, here we kill the ``proxy-1`` node, then start just that node
after killing it:

.. code:: console

   # kill 4446
   # zeekctl status
   Name         Type    Host             Status    Pid    Started
   logger-1     logger  localhost        running   4341   08 Dec 21:47:32
   manager      manager localhost        running   4394   08 Dec 21:47:33
   proxy-1      proxy   localhost        crashed
   worker-1     worker  localhost        running   4511   08 Dec 21:47:35
   worker-2     worker  localhost        running   4512   08 Dec 21:47:35
   # zeekctl start proxy-1
   starting proxy ...

   # zeekctl status
   Name         Type    Host             Status    Pid    Started
   logger-1     logger  localhost        running   4341   08 Dec 21:47:32
   manager      manager localhost        running   4394   08 Dec 21:47:33
   proxy-1      proxy   localhost        running   4947   08 Dec 21:53:49
   worker-1     worker  localhost        running   4511   08 Dec 21:47:35
   worker-2     worker  localhost        running   4512   08 Dec 21:47:35

This requires manually intervention. Instead, you can use ``zeekctl``
with ``cron`` in order to automatically check for crashed nodes and
restart them. See the `ZeekControl cron`_ command reference for more
information.

.. note::

   ZeekControl itself has no active process monitoring. Therefore, in
   order to perform automatic restarts, you need to put the ``zeekctl
   cron`` command into a ``crontab`` entry.

Many basic clusters can be maintained with just what was discussed here:
a mixture of ``zeekctl`` commands like ``deploy``, ``start``, ``stop``,
and ``status``. You can use ``top`` and ``cron`` for extra visibility or
monitoring on your cluster. Then, configure the cluster according to
your particular environment, and that should be what you need to get a
capable Zeek cluster.

In the next section, we will go over analyzing logs. If you just want to
see how logs function when using ZeekControl, see the
:ref:`zeekcontrol_logs` section.
