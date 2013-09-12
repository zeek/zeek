
.. _upgrade-guidelines:

==================
General Guidelines
==================

If you're doing an upgrade install (rather than a fresh install),
there's two suggested approaches: either install Bro using the same
installation prefix directory as before, or pick a new prefix and copy
local customizations over. In the following we summarize general
guidelines for upgrading, see the :ref:`release-notes` for
version-specific information.

Re-Using Previous Install Prefix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you choose to configure and install Bro with the same prefix
directory as before, local customization and configuration to files in
``$prefix/share/bro/site`` and ``$prefix/etc`` won't be overwritten
(``$prefix`` indicating the root of where Bro was installed). Also, logs
generated at run-time won't be touched by the upgrade. (But making
a backup of local changes before upgrading is still recommended.)

After upgrading, remember to check ``$prefix/share/bro/site`` and
``$prefix/etc`` for ``.example`` files, which indicate the
distribution's version of the file differs from the local one, which may
include local changes.  Review the differences, and make adjustments
as necessary (for differences that aren't the result of a local change,
use the new version's).

Using a New Install prefix
~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to install the newer version in a different prefix
directory than before, you can just copy local customization and
configuration files from ``$prefix/share/bro/site`` and ``$prefix/etc``
to the new location (``$prefix`` indicating the root of where Bro was
originally installed).  Make sure to review the files for difference
before copying and make adjustments as necessary (for differences that
aren't the result of a local change, use the new version's).  Of
particular note, the copied version of ``$prefix/etc/broctl.cfg`` is
likely to need changes to the ``SpoolDir`` and ``LogDir`` settings.
