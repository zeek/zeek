.. _redis_rce: https://github.com/LoRexxar/redis-rogue-server
.. _zeek package browser: https://packages.zeek.org/
.. _zkg_docs: https://docs.zeek.org/projects/package-manager/en/stable/index.html

.. _using-packages:

################
 Using Packages
################

Zeek contains a decent amount of functionality “out of the box”---but
its strength comes from the package ecosystem. These packages are
managed by the `Zeek Package Manager <zkg_docs_>`_, or ``zkg``. You
can find packages on the `Zeek Package Browser`_ website. This section will
explain how to use ``zkg`` in order to get the packages you need.

*********************************
 Finding and Installing Packages
*********************************

Say you're particularly worried about `a Redis remote code execution
<redis_rce_>`_ (there is nothing special about this exploit, it's simply
for demonstration). Zeek does not offer any detection for this
out-of-the-box. But, if you look on the `Zeek Package Browser`_, you can
easily find a `Zeek package <https://github.com/zeek/redis-rce>`_. Let's
install it.

.. code:: console

   # zkg install redis-rce

The package manager knows where to find this package because it's listed in its
default `"package source" <https://github.com/zeek/packages>`_, an index that
anyone can contribute to.

You may also install packages via their git URL, or from a local directory,
regardless of whether they're listed in a package source. For example:

.. code:: console

   # zkg install https://github.com/zeek/redis-rce

Most packages include a set of tests to ensure the package executes correctly
in your environment. During installation, ``zkg`` will run available tests.
These tests may fail, but you can still accept the prompt to install anyways.

The script you ran during tutorial setup also cloned this package into
the tutorial installation. Try running Zeek on a pcap from the package:

.. code:: console

   # zeek -r redis-rce/tests/Traces/exploit.pcap

This particular package creates notices when it detects traffic for the exploit,
but we seem to be missing a ``notice.log`` after running that command.
That's because packages have to be loaded explicitly in order to run. You can
do so by including its name on the command line:

.. code:: console

   # zeek -r redis-rce/tests/Traces/exploit.pcap redis-rce/export/whitelist-commands

You can also load all installed packages by simply adding the ``packages``
directory to your invocation. This package does not load anything by default, but you
can load all packages alongside the RCE exploit detection:

.. code:: console

   # zeek -r redis-rce/tests/Traces/exploit.pcap redis-rce/export/whitelist-commands packages

Then check the ``notice.log``:

.. code:: console

   # cat notice.log | zeek-cut -m note msg
   note    msg
   Bad_Redis_Command       Disallowed Redis command: SLAVEOF
   Bad_Redis_Command       Disallowed Redis command: system.exec

Packages should be regularly maintained and updated. When doing so,
users will want to fetch those updates. You can use ``zkg upgrade`` in
order to upgrade any packages you have, or specify a package to upgrade
just one. If you definitely don't want to upgrade certain packages, you
can use ``zkg pin`` in order to “pin” its version. To revert to a clean
slate, say ``zkg purge``.

For more commands, check out the zkg command line reference.

.. code:: console

   # zkg --help
   usage: zkg [-h] [--version] [--configfile FILE | --user] [--verbose]
              [--extra-source NAME=URL]
              {test,install,bundle,unbundle,remove,uninstall,purge,refresh,upgrade,load,unload,pin,unpin,list,search,info,config,autoconfig,env,create,template} ...
   ...
