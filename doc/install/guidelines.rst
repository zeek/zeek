
.. _upgrade-guidelines:

==============
How to Upgrade
==============

If you're doing an upgrade install (rather than a fresh install),
there's two suggested approaches: either install Bro using the same
installation prefix directory as before, or pick a new prefix and copy
local customizations over.  Regardless of which approach you choose,
if you are using BroControl, then after upgrading Bro you will need to
run "broctl check" (to verify that your new configuration is OK)
and "broctl install" to complete the upgrade process.

In the following we summarize general guidelines for upgrading, see
the :ref:`release-notes` for version-specific information.


Reusing Previous Install Prefix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you choose to configure and install Bro with the same prefix
directory as before, local customization and configuration to files in
``$prefix/share/bro/site`` and ``$prefix/etc`` won't be overwritten
(``$prefix`` indicating the root of where Bro was installed). Also, logs
generated at run-time won't be touched by the upgrade. Backing up local
changes before upgrading is still recommended.

After upgrading, remember to check ``$prefix/share/bro/site`` and
``$prefix/etc`` for ``.example`` files, which indicate that the
distribution's version of the file differs from the local one, and therefore,
may include local changes.  Review the differences and make adjustments
as necessary. Use the new version for differences that aren't a result of
a local change.

Using a New Install Prefix
~~~~~~~~~~~~~~~~~~~~~~~~~~

To install the newer version in a different prefix directory than before,
copy local customization and configuration files from ``$prefix/share/bro/site``
and ``$prefix/etc`` to the new location (``$prefix`` indicating the root of
where Bro was originally installed).  Review the files for differences
before copying and make adjustments as necessary (use the new version for
differences that aren't a result of a local change).  Of particular note,
the copied version of ``$prefix/etc/broctl.cfg`` is likely to need changes
to the ``SpoolDir`` and ``LogDir`` settings.
