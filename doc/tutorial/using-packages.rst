.. _cve-2022-26809: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26809
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

Say you're particularly worried about CVE-2022-26809_ (there is nothing
special about this CVE, it's simply an exploit that we can use for
demonstration). Zeek does not offer any detection for this
out-of-the-box. But, if you look on the `Zeek Package Browser`_, you can
easily find a `package by Corelight
<https://github.com/corelight/cve-2022-26809>`_. Let's install it.

.. code:: console

   # zkg install cve-2022-26809

The package manager knows where to find this package because it's listed in its
default `"package source" <https://github.com/zeek/packages>`_, an index that
anyone can contribute to.

You may also install packages via their git URL, or from a local directory,
regardless of whether they're listed in a package source. For example:

.. code:: console

   # zkg install https://github.com/corelight/cve-2022-26809

Most packages include a set of tests to ensure the package executes correctly
in your environment. During installation, ``zkg`` will run available tests.
These tests may fail, but you can still accept the prompt to install anyways.

The script you ran during tutorial setup also cloned this package into
the tutorial installation. Try running Zeek on a pcap from the package:

.. code:: console

   # zeek -r cve-2022-26809/testing/Traces/cve-2022-26809-4.pcap

This particular package creates notices when it detects traffic for the CVE,
but we seem to be missing a ``notice.log`` after running that command.
That's because packages have to be loaded explicitly in order to run. You can
do so by including its name on the command line:

.. code:: console

   # zeek -r cve-2022-26809/testing/Traces/cve-2022-26809-4.pcap cve-2022-26809

Alternatively you can also load all installed packages by simply adding the
``packages`` directory to your invocation:

.. code:: console

   # zeek -r cve-2022-26809/testing/Traces/cve-2022-26809-4.pcap packages

Then check the ``notice.log``:

.. code:: console

   # cat notice.log | zeek-cut -m
   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type      file_desc       proto   note    msg     sub     src     dst     p       n  peer_descr       actions email_dest      suppress_for    remote_location.country_code    remote_location.region      remote_location.city    remote_location.latitude        remote_location.longitude
   1649954026.163197       -       -       -       -       -       -       -       -       -  CVE_2022_26809::ExploitAttempt   192.168.56.104 attempting exploit on 192.168.56.102     Using opnum 5       -       -       -       -       -       Notice::ACTION_LOG      (empty) 3600.000000 -       -       -       -       -
   1649954026.275892       -       -       -       -       -       -       -       -       -  CVE_2022_26809::ExploitSuccess   192.168.56.102 exploited 192.168.56.104 Found via big_endian_specific (in dce_rpc_message)  -       -       -       -       -       Notice::ACTION_LOG (empty)  3600.000000     -       -       -       -       -
   1649954026.275892       -       -       -       -       -       -       -       -       -  CVE_2022_26809::ExploitSuccess   192.168.56.102 exploited 192.168.56.104 Found via big_endian (in dce_rpc_message)   -       -       -       -       -       Notice::ACTION_LOG      (empty)     3600.000000     -       -       -       -       -

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
