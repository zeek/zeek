.. _cve-2022-26809: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26809

.. _using-packages:

.. _zeek package browser: https://packages.zeek.org/

################
 Using Packages
################

Zeek contains a decent amount of functionality “out of the box” - but
its strength comes from the package ecosystem. These packages are
managed by the Zeek Package Manager, or ``zkg``. Then, you can find
packages on the `Zeek Package Browser`_. This section will explain how
to use ``zkg`` in order to get the packages you need.

*********************************
 Finding and Installing Packages
*********************************

Say you’re particularly worried about CVE-2022-26809_ (there is nothing
special about this CVE, it’s simply an exploit that we can use for
demonstration). Zeek does not offer any detection for this
out-of-the-box. But, if you look on the `Zeek Package Browser`_, you can
easily find a `package by Corelight
<https://github.com/corelight/cve-2022-26809>`_. Let’s install it.

First, since this is on the official Zeek package browser, you can
install it with just the package name:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zkg install cve-2022-26809

You may also use the git URL of the package:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zkg install https://github.com/corelight/cve-2022-26809

This will ask you to run the tests. TODO: This case the tests fail :( :(
:(

Part of the setup script also cloned this repository. Try running Zeek
on the pcap from the package:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zeek -r cve-2022-26809/testing/Traces/cve-2022-26809-4.pcap

This particular package creates notices when it’s detected, but there
isn’t a ``notice.log`` ! That's because packages have to be enabled in
order to run. This is done differently when executing Zeek on the
command line versus in the cluster. We’ll get to the cluster version
later. For now, you can load the package by just including its name in
the command line, or by prefixing that name with ``packages``:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zeek -r cve-2022-26809/testing/Traces/cve-2022-26809-4.pcap packages/cve-2022-26809

Then check the ``notice.log``:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ cat notice.log | zeek-cut -m
   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type      file_desc       proto   note    msg     sub     src     dst     p       n  peer_descr       actions email_dest      suppress_for    remote_location.country_code    remote_location.region      remote_location.city    remote_location.latitude        remote_location.longitude
   1649954026.163197       -       -       -       -       -       -       -       -       -  CVE_2022_26809::ExploitAttempt   192.168.56.104 attempting exploit on 192.168.56.102     Using opnum 5       -       -       -       -       -       Notice::ACTION_LOG      (empty) 3600.000000 -       -       -       -       -
   1649954026.275892       -       -       -       -       -       -       -       -       -  CVE_2022_26809::ExploitSuccess   192.168.56.102 exploited 192.168.56.104 Found via big_endian_specific (in dce_rpc_message)  -       -       -       -       -       Notice::ACTION_LOG (empty)  3600.000000     -       -       -       -       -
   1649954026.275892       -       -       -       -       -       -       -       -       -  CVE_2022_26809::ExploitSuccess   192.168.56.102 exploited 192.168.56.104 Found via big_endian (in dce_rpc_message)   -       -       -       -       -       Notice::ACTION_LOG      (empty)     3600.000000     -       -       -       -       -

Later, we will see how Zeek's notice framework can be configured to
react to events differently. For now, these are simply reported to
``notice.log``.

Packages should be regularly maintained and updated. When doing so,
users will want to fetch those updates. You can use ``zkg upgrade`` in
order to upgrade any packages you have, or specify a package to upgrade
just one. If you definitely don’t want to upgrade certain packages, you
can use ``zkg pin`` in order to “pin” its version.

For more commands, check out the zkg command line reference.

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zkg --help
   usage: zkg [-h] [--version] [--configfile FILE | --user] [--verbose]
              [--extra-source NAME=URL]
              {test,install,bundle,unbundle,remove,uninstall,purge,refresh,upgrade,load,unload,pin,unpin,list,search,info,config,autoconfig,env,create,template} ...
   ...
